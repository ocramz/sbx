//! sbx — run an untrusted program under Landlock + seccomp.
//!
//!   sbx run [OPTIONS] [--] PROGRAM [ARGS...]   run sandboxed (container ENTRYPOINT)
//!   sbx probe                                  report kernel support (run this on your platform first)
//!   sbx policy [OPTIONS]                       print the effective policy after all overrides

mod landlock_layer;
mod policy;
mod seccomp_layer;
mod supervisor;

use policy::{Overrides, Policy};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

const USAGE: &str = "\
usage: sbx run [OPTIONS] [--] PROGRAM [ARGS...]
       sbx probe
       sbx policy [OPTIONS]

options (each also settable via the env var shown; flags win over env, env over the policy file):
  --policy FILE        base policy file              SBX_POLICY_FILE (default /etc/sbx/policy.toml)
  --ro PATH[:PATH]     grant read                    SBX_FS_RO
  --rw PATH[:PATH]     grant read/write              SBX_FS_RW
  --rx PATH[:PATH]     grant read/execute            SBX_FS_RX
  --net SPEC           none | unrestricted | tcp:443,8443[+udp]   SBX_NET
  --timeout SECS       wall-clock limit (exit 124)   SBX_TIMEOUT
  --workdir DIR        working directory             SBX_WORKDIR
  --no-subprocesses    threads only, no fork         SBX_SUBPROCESSES=0
  --env-pass NAMES     pass these env vars through   SBX_ENV_PASS
  --best-effort        run even without Landlock     SBX_BEST_EFFORT=1
  --seccomp-action A   errno | kill | log            SBX_SECCOMP_ACTION
  --quiet              only log errors               SBX_QUIET=1
";

static mut QUIET: bool = false;

pub fn log_info(msg: &str) {
    // SAFETY: written once during startup, single-threaded.
    if !unsafe { QUIET } {
        eprintln!("sbx: {msg}");
    }
}

pub fn log_error(msg: &str) {
    eprintln!("sbx: error: {msg}");
}

fn main() {
    std::process::exit(match real_main() {
        Ok(code) => code,
        Err(e) => {
            log_error(&e);
            125
        }
    });
}

fn real_main() -> Result<i32, String> {
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        eprint!("{USAGE}");
        return Ok(2);
    }
    let cmd = args.remove(0);
    let (cli, rest, quiet) = parse_flags(args)?;
    unsafe { QUIET = quiet || std::env::var("SBX_QUIET").is_ok_and(|v| v == "1") };

    match cmd.to_str() {
        Some("probe") => Ok(probe()),
        Some("policy") => {
            let (p, warnings) = Policy::resolve(Overrides::from_env()?.merge(cli))?;
            warnings.iter().for_each(|w| eprintln!("sbx: warning: {w}"));
            print!("{}", toml::to_string_pretty(&p).map_err(|e| e.to_string())?);
            Ok(0)
        }
        Some("run") => {
            if rest.is_empty() {
                return Err(format!("run: missing PROGRAM\n{USAGE}"));
            }
            let (p, warnings) = Policy::resolve(Overrides::from_env()?.merge(cli))?;
            warnings.iter().for_each(|w| eprintln!("sbx: warning: {w}"));
            run(p, rest)
        }
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            Ok(0)
        }
        Some("version" | "--version") => {
            println!("sbx {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        _ => Err(format!("unknown command {cmd:?}\n{USAGE}")),
    }
}

fn parse_flags(args: Vec<OsString>) -> Result<(Overrides, Vec<OsString>, bool), String> {
    let mut o = Overrides::default();
    let mut quiet = false;
    let mut it = args.into_iter();
    let mut rest = Vec::new();
    while let Some(a) = it.next() {
        let s = a.to_string_lossy().into_owned();
        if s == "--" {
            rest.extend(it);
            break;
        }
        if !s.starts_with("--") {
            // First non-flag is the program; everything after belongs to it.
            rest.push(a);
            rest.extend(it);
            break;
        }
        let (key, inline) = match s.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (s.clone(), None),
        };
        let mut val = || inline.clone().or_else(|| it.next().map(|v| v.to_string_lossy().into_owned())).ok_or(format!("{key} needs a value"));
        match key.as_str() {
            "--policy" => o.policy_file = Some(PathBuf::from(val()?)),
            "--ro" => o.ro.extend(policy::split_paths(&val()?)),
            "--rw" => o.rw.extend(policy::split_paths(&val()?)),
            "--rx" => o.rx.extend(policy::split_paths(&val()?)),
            "--net" => o.net = Some(val()?),
            "--timeout" => o.timeout_secs = Some(policy::parse_u64("--timeout", &val()?)?),
            "--workdir" => o.workdir = Some(PathBuf::from(val()?)),
            "--no-subprocesses" => o.subprocesses = Some(false),
            "--env-pass" => o.env_pass.extend(policy::split_list(&val()?)),
            "--best-effort" => o.best_effort = Some(true),
            "--seccomp-action" => o.on_violation = Some(val()?),
            "--quiet" => quiet = true,
            _ => return Err(format!("unknown option {key}\n{USAGE}")),
        }
    }
    Ok((o, rest, quiet))
}

fn run(p: Policy, cmd: Vec<OsString>) -> Result<i32, String> {
    let envp = build_env(&p);
    let path_var = envp
        .iter()
        .find_map(|(k, v)| (k == "PATH").then_some(v.clone()))
        .unwrap_or_default();
    let exe = resolve_program(&cmd[0], &path_var)?;

    // Everything that can fail on bad config happens here, before fork.
    let ll = landlock_layer::prepare(&p)?;
    let sc = seccomp_layer::build(&p)?;
    log_info(&ll.summary);
    if let Some(s) = &sc {
        log_info(&s.summary);
    }
    if unsafe { libc::geteuid() } != 0 && ll.ruleset.as_ref().is_some() && !p.landlock.scope_signals {
        log_info("note: sandbox shares sbx's uid; enable scope_signals or start sbx as root");
    }

    let cstr = |b: Vec<u8>| CString::new(b).map_err(|_| "argument contains NUL byte".to_string());
    let launch = supervisor::Launch {
        exe: cstr(exe.into_os_string().into_vec())?,
        argv: cmd.into_iter().map(|a| cstr(a.into_vec())).collect::<Result<_, _>>()?,
        envp: envp.into_iter().map(|(k, v)| cstr(format!("{k}={v}").into_bytes())).collect::<Result<_, _>>()?,
        landlock: ll.ruleset,
        seccomp: sc,
    };
    Ok(supervisor::run(&p, launch))
}

/// Only explicitly passed or set variables reach the sandbox.
fn build_env(p: &Policy) -> Vec<(String, String)> {
    let mut env: std::collections::BTreeMap<String, String> = Default::default();
    for k in &p.env.pass {
        if let Ok(v) = std::env::var(k) {
            env.insert(k.clone(), v);
        }
    }
    for (k, v) in &p.env.set {
        env.insert(k.clone(), v.clone());
    }
    env.into_iter().collect()
}

fn resolve_program(prog: &OsString, path_var: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let p = PathBuf::from(prog);
    if p.components().count() > 1 || p.is_absolute() {
        return Ok(p);
    }
    for dir in path_var.split(':').filter(|d| !d.is_empty()) {
        let cand = PathBuf::from(dir).join(&p);
        if let Ok(m) = std::fs::metadata(&cand) {
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return Ok(cand);
            }
        }
    }
    Err(format!("{}: not found in sandbox PATH ({path_var})", p.display()))
}

fn probe() -> i32 {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut uts) };
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy().into_owned();
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |k: &str| status.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string())).unwrap_or("?".into());

    println!("kernel           {release} ({})", std::env::consts::ARCH);
    println!("pid / uid        {} / {}", unsafe { libc::getpid() }, unsafe { libc::geteuid() });
    println!("seccomp (self)   mode {} (0=none 2=filter), no_new_privs={}", field("Seccomp:"), field("NoNewPrivs:"));
    let ll = landlock_layer::probe();
    println!("landlock         {ll}");
    if let landlock_layer::Probe::Available(v) = ll {
        let f = |min: i32, what: &str| println!("  {} v{min}+ {what}", if v >= min { "yes" } else { "no " });
        f(1, "filesystem rules");
        f(3, "truncate control");
        f(4, "TCP bind/connect port rules (network.mode=restricted)");
        f(5, "device ioctl control");
        f(6, "signal + abstract UNIX socket scoping");
        f(7, "audit logging of denials");
        f(9, "pathname UNIX socket connect control");
    }

    // Can we actually install a seccomp filter here (nested under the platform's)?
    let seccomp_ok = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let p = seccompiler::BpfProgram::from(vec![seccompiler::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x7fff_0000 }]);
            libc::_exit(if seccompiler::apply_filter(&p).is_ok() { 0 } else { 1 });
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
    };
    println!("seccomp filter   {}", if seccomp_ok { "can install" } else { "CANNOT install" });

    let ok = seccomp_ok && matches!(ll, landlock_layer::Probe::Available(_));
    println!("verdict          {}", if ok { "OK: both layers enforceable" } else { "NOT OK: see above" });
    if ok { 0 } else { 1 }
}
