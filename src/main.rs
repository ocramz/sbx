//! sbx: run an untrusted program under Landlock + seccomp.
//!
//!   sbx run [OPTIONS] -- PROGRAM [ARGS...]   run sandboxed (container ENTRYPOINT)
//!   sbx probe [OPTIONS]                      check that this kernel/container can enforce the policy
//!   sbx policy [OPTIONS]                     validate and print the effective policy

mod capabilities;
mod dns;
mod egress;
mod landlock_layer;
mod log;
mod net;
mod notify;
mod policy;
mod seccomp_layer;
mod supervisor;

use policy::{LandlockAbi, NetMode, Overrides, Policy};
use std::collections::BTreeSet;
use std::ffi::{CString, OsString};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::Arc;

const USAGE: &str = "\
usage: sbx run [OPTIONS] -- PROGRAM [ARGS...]
       sbx probe [OPTIONS]
       sbx policy [OPTIONS]
       sbx version

A policy file is required. Options override or extend it (flags win over the
environment variable shown):
  --policy FILE          policy file                          SBX_POLICY_FILE
  --ro PATH[:PATH]       grant read (repeatable)              SBX_FS_RO
  --rw PATH[:PATH]       grant read/write (repeatable)        SBX_FS_RW
  --rx PATH[:PATH]       grant read/execute (repeatable)      SBX_FS_RX
  --net MODE             none | egress | unrestricted         SBX_NET
  --egress RULE          allow egress, e.g. api.github.com:443,
                         10.0.0.0/8:5432, [2001:db8::/32]:443 (repeatable)
                                                              SBX_EGRESS (comma-separated)
  --timeout SECS|none    wall-clock limit (exit 124)          SBX_TIMEOUT
  --workdir DIR          working directory                    SBX_WORKDIR
  --no-subprocesses      threads only, no fork                SBX_SUBPROCESSES=false
  --env-pass NAME[:NAME] pass these variables (repeatable)    SBX_ENV_PASS
  --seccomp-action A     errno | kill                         SBX_SECCOMP_ACTION
  --quiet                only log warnings and errors         SBX_QUIET=true

Exit codes: the program's own, 124 on timeout, 125 for sbx errors,
127 if the program cannot be executed, 128+N if killed by signal N.
";

fn main() {
    std::process::exit(match real_main() {
        Ok(code) => code,
        Err(errs) => {
            for e in errs {
                log::error(e);
            }
            125
        }
    });
}

fn real_main() -> Result<i32, Vec<String>> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return Ok(2);
    };
    let cmd = cmd
        .to_str()
        .ok_or_else(|| vec![format!("command {cmd:?} is not valid UTF-8")])?;
    match cmd {
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(0)
        }
        "version" | "--version" => {
            println!("sbx {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "run" | "probe" | "policy" => {
            let (flags, program) = parse_flags(rest, cmd == "run")?;
            let ov = Overrides::from_env()?.merge(flags);
            log::set_quiet(ov.quiet == Some(true));
            let (p, warnings) = Policy::resolve(ov)?;
            for w in &warnings {
                log::warn(w);
            }
            match cmd {
                "policy" => {
                    let out = toml::to_string_pretty(&p).map_err(|e| vec![format!("serializing the policy: {e}")])?;
                    print!("{out}");
                    Ok(0)
                }
                "probe" => Ok(probe(&p)),
                _ => run(p, program),
            }
        }
        other => Err(vec![format!("unknown command {other:?}\n{USAGE}")]),
    }
}

/// Parse options (and, for `run`, the mandatory `-- PROGRAM ARGS...`).
fn parse_flags(args: &[OsString], run: bool) -> Result<(Overrides, Vec<OsString>), Vec<String>> {
    let mut o = Overrides::default();
    let mut seen = BTreeSet::new();
    let mut it = args.iter();
    let mut program = None;
    let usage = |e: String| vec![format!("{e}\n{USAGE}")];
    while let Some(a) = it.next() {
        let s = a
            .to_str()
            .ok_or_else(|| usage(format!("argument {a:?} is not valid UTF-8")))?;
        if s == "--" {
            if !run {
                return Err(usage("unexpected '--': only `sbx run` takes a program".into()));
            }
            program = Some(it.cloned().collect::<Vec<_>>());
            break;
        }
        if !s.starts_with("--") {
            return Err(usage(if run {
                format!("unexpected argument {s:?}: put -- before the program (sbx run [OPTIONS] -- PROGRAM [ARGS...])")
            } else {
                format!("unexpected argument {s:?}")
            }));
        }
        let (key, inline) = match s.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (s, None),
        };
        let repeatable = matches!(key, "--ro" | "--rw" | "--rx" | "--egress" | "--env-pass");
        if !repeatable && !seen.insert(key.to_string()) {
            return Err(usage(format!("{key} given more than once")));
        }
        let takes_value = !matches!(key, "--no-subprocesses" | "--quiet");
        let val = if takes_value {
            match inline {
                Some(v) => v,
                None => {
                    let v = it.next().ok_or_else(|| usage(format!("{key} needs a value")))?;
                    v.to_str()
                        .ok_or_else(|| usage(format!("value of {key} is not valid UTF-8")))?
                        .to_string()
                }
            }
        } else {
            if inline.is_some() {
                return Err(usage(format!("{key} takes no value")));
            }
            String::new()
        };
        let one = |r: Result<(), String>| r.map_err(|e| vec![e]);
        match key {
            "--policy" => o.policy_file = Some(PathBuf::from(val)),
            "--ro" => one(policy::split_paths(key, &val).map(|p| o.ro.extend(p)))?,
            "--rw" => one(policy::split_paths(key, &val).map(|p| o.rw.extend(p)))?,
            "--rx" => one(policy::split_paths(key, &val).map(|p| o.rx.extend(p)))?,
            "--net" => one(policy::parse_net(key, &val).map(|n| o.net = Some(n)))?,
            "--egress" => one(policy::parse_egress_rule(&val).map(|r| o.egress.push(r)))?,
            "--timeout" => one(policy::parse_timeout(key, &val).map(|t| o.timeout = Some(t)))?,
            "--workdir" => o.workdir = Some(PathBuf::from(val)),
            "--no-subprocesses" => o.subprocesses = Some(false),
            "--env-pass" => one(policy::split_names(key, &val).map(|n| o.env_pass.extend(n)))?,
            "--seccomp-action" => one(policy::parse_violation(key, &val).map(|v| o.on_violation = Some(v)))?,
            "--quiet" => o.quiet = Some(true),
            _ => return Err(usage(format!("unknown option {key}"))),
        }
    }
    match (run, program) {
        (true, None) => Err(usage("run: missing `-- PROGRAM [ARGS...]`".into())),
        (true, Some(p)) if p.is_empty() => Err(usage("run: missing PROGRAM after --".into())),
        (_, p) => Ok((o, p.unwrap_or_default())),
    }
}

fn run(p: Policy, cmd: Vec<OsString>) -> Result<i32, Vec<String>> {
    let one = |e: String| vec![e];
    let envp = build_env(&p).map_err(one)?;
    let exe = resolve_program(&cmd[0], &envp).map_err(one)?;
    capabilities::require(&p)?;
    // Held until sbx exits.
    let _slot = supervisor::claim_sandbox_slot().map_err(one)?;

    // Without Landlock nothing stops an IP socket inherited on stdio from
    // connecting in mode none either.
    if p.network.mode == NetMode::Egress || (p.network.mode == NetMode::None && p.landlock.abi == LandlockAbi::Off) {
        check_stdio().map_err(one)?;
    }
    let mut svc = supervisor::Services {
        egress: None,
        dns: None,
    };
    if p.network.mode == NetMode::Egress {
        let egress = Arc::new(egress::Egress::new(&p));
        log::info(egress.summary());
        if let Some(d) = &p.network.dns {
            dns::setup_resolv_conf(d).map_err(one)?;
            let listener = dns::bind(d).map_err(one)?;
            svc.dns = Some((listener, d.clone()));
        }
        svc.egress = Some(egress);
    }
    // Everything that can fail on bad config happens here, before fork.
    let ll = landlock_layer::prepare(&p).map_err(one)?;
    let sc = seccomp_layer::build(&p).map_err(one)?;
    log::info(&ll.summary);
    log::info(&sc.summary);

    let cstr = |b: Vec<u8>, what: &str| CString::new(b).map_err(|_| vec![format!("{what} contains a NUL byte")]);
    let launch = supervisor::Launch {
        exe: cstr(exe.into_os_string().into_vec(), "program path")?,
        argv: cmd
            .into_iter()
            .map(|a| cstr(a.into_vec(), "an argument"))
            .collect::<Result<_, _>>()?,
        envp: envp
            .into_iter()
            .map(|(k, v)| cstr(format!("{k}={v}").into_bytes(), "an environment variable"))
            .collect::<Result<_, _>>()?,
        landlock: ll.ruleset,
        seccomp: sc,
    };
    Ok(supervisor::run(&p, launch, svc))
}

/// The sandbox environment: exactly env.set plus the env.pass variables,
/// each of which must be set.
fn build_env(p: &Policy) -> Result<Vec<(String, String)>, String> {
    let mut env: std::collections::BTreeMap<String, String> = Default::default();
    for k in &p.env.pass {
        match std::env::var_os(k) {
            None => return Err(format!("env.pass lists {k}, but it is not set in sbx's environment")),
            Some(v) => {
                let v = v
                    .into_string()
                    .map_err(|_| format!("environment variable {k} is not valid UTF-8"))?;
                env.insert(k.clone(), v);
            }
        }
    }
    for (k, v) in &p.env.set {
        env.insert(k.clone(), v.clone());
    }
    Ok(env.into_iter().collect())
}

/// PROGRAM is used as given if it contains a '/'; otherwise it is looked up
/// in the sandbox's PATH, which must then be set and contain absolute
/// directories only.
fn resolve_program(prog: &OsString, envp: &[(String, String)]) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let p = PathBuf::from(prog);
    if prog.as_encoded_bytes().contains(&b'/') {
        return Ok(p);
    }
    let path = envp
        .iter()
        .find_map(|(k, v)| (k == "PATH").then_some(v.as_str()))
        .ok_or_else(|| {
            format!(
                "{}: the program has no '/' and the sandbox environment sets no PATH",
                p.display()
            )
        })?;
    for dir in path.split(':') {
        if dir.is_empty() || !dir.starts_with('/') {
            return Err(format!(
                "sandbox PATH {path:?} contains {dir:?}; only absolute directories are allowed"
            ));
        }
        let cand = PathBuf::from(dir).join(&p);
        match std::fs::metadata(&cand) {
            Ok(m) if m.is_file() && m.permissions().mode() & 0o111 != 0 => {
                log::info(format!(
                    "{} resolved to {} via the sandbox PATH",
                    p.display(),
                    cand.display()
                ));
                return Ok(cand);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("looking up {}: {}: {e}", p.display(), cand.display())),
        }
    }
    Err(format!("{}: not found in the sandbox PATH ({path})", p.display()))
}

/// An inherited IP socket on stdio would bypass the egress filter (and,
/// without Landlock, mode none).
fn check_stdio() -> Result<(), String> {
    for fd in 0..3 {
        // SAFETY: fds 0-2 are only inspected, never closed, and outlive this call.
        let b = unsafe { BorrowedFd::borrow_raw(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: st is valid output storage.
        if unsafe { libc::fstat(b.as_raw_fd(), &mut st) } != 0 {
            if log::errno() == libc::EBADF {
                continue;
            }
            return Err(log::os_err(format!("fstat(fd {fd})")));
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            continue;
        }
        let mut dom: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: dom/len are valid for the call.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                &mut dom as *mut _ as *mut libc::c_void,
                &mut len,
            )
        } != 0
        {
            return Err(log::os_err(format!("getsockopt(fd {fd}, SO_DOMAIN)")));
        }
        if dom == libc::AF_INET || dom == libc::AF_INET6 {
            return Err(format!(
                "fd {fd} is an IP socket; the program would inherit it and bypass network filtering \
                 (give sbx pipes, files or UNIX sockets as stdio)"
            ));
        }
    }
    Ok(())
}

fn probe(p: &Policy) -> i32 {
    let checks = capabilities::check(p);
    let mut ok = true;
    for c in &checks {
        match &c.outcome {
            Ok(m) => println!("ok       {:<32} {m}", c.name),
            Err(e) => {
                ok = false;
                println!("MISSING  {:<32} {e}", c.name);
            }
        }
    }
    let landlock_on = p.landlock.abi != LandlockAbi::Off;
    if let (true, landlock_layer::Probe::Available(v)) = (landlock_on, landlock_layer::probe()) {
        let f = |min: u8, what: &str| {
            println!(
                "         landlock v{min}+ {:<4} {what}",
                if v >= min { "yes" } else { "no" }
            )
        };
        f(1, "filesystem rules");
        f(3, "truncate control");
        f(4, "TCP bind/connect rules (network.mode none/egress)");
        f(5, "device ioctl control");
        f(6, "signal + abstract UNIX socket scoping");
        f(9, "pathname UNIX socket connect control");
    }
    println!(
        "verdict  {}",
        if ok {
            "OK: this policy can be enforced here"
        } else {
            "NOT OK: see MISSING above"
        }
    );
    if ok {
        0
    } else {
        1
    }
}
