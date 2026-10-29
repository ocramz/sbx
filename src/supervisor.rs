//! Process model:
//!
//!   sbx (supervisor: PID 1 in a container, unsandboxed, never runs payload code)
//!    ├─ threads, started after fork: seccomp notification dispatcher,
//!    │  blocking egress connects, DNS proxy
//!    └─ child: [join the sandbox cgroup] → setsid → chdir → rlimits → drop identity and capabilities
//!              → PDEATHSIG → NO_NEW_PRIVS → Landlock (unless "off") → seccomp prelude
//!              → policy filter (listener handed to the supervisor) → execve
//!         └─ untrusted program and all its descendants (inherit every layer)
//!
//! One sandbox per container: `sbx run` claims a slot (an abstract UNIX
//! socket) before it changes anything (resolv.conf, the DNS proxy, the
//! cgroup) and holds it until it exits. The signals the supervisor handles
//! are blocked before any of that, so none of them can stop sbx half-way.
//!
//! The supervisor is single-threaded until after fork, so the child may
//! allocate before exec. Setup failures in the child come back over a
//! close-on-exec pipe; the listener comes over a SOCK_SEQPACKET socketpair.

use crate::cgroup::{self, Delegation};
use crate::dns;
use crate::egress::Egress;
use crate::landlock_layer;
use crate::log::{self, errno, fatal_signal, os_err};
use crate::notify::{self, Dispatcher, Listener, Received, Stats};
use crate::policy::{DnsCfg, LandlockAbi, Limit, Policy, Timeout};
use crate::report::{self, At, Program, Ran, SetupError, Stage, Usage};
use crate::seccomp_layer::{self, Programs};
use landlock::RulesetCreated;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::Read;
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct Launch {
    pub exe: CString,
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub landlock: Option<RulesetCreated>,
    pub seccomp: Programs,
    /// sbx-sandbox/cgroup.procs (cgroup.mode = "delegated").
    pub cgroup_procs: Option<RawFd>,
}

/// Supervisor-side services for the sandbox.
pub struct Services {
    pub egress: Option<Arc<Egress>>,
    pub dns: Option<(TcpListener, DnsCfg)>,
}

/// Abstract UNIX socket name that a running `sbx run` holds.
const SLOT_NAME: &[u8] = b"sbx/sandbox";

/// Claim the container's single sandbox slot, held until the socket is
/// dropped or sbx exits. Abstract names are per network namespace, so the
/// slot is shared by everything in that namespace (a container, a pod, or
/// the host with `--network host`). The socket is close-on-exec and never
/// read; nothing can be gained by sending to it.
pub fn claim_sandbox_slot() -> Result<UnixDatagram, String> {
    let addr = SocketAddr::from_abstract_name(SLOT_NAME).map_err(|e| format!("abstract socket name: {e}"))?;
    UnixDatagram::bind_addr(&addr).map_err(|e| match e.raw_os_error() {
        Some(libc::EADDRINUSE) => {
            "another sbx sandbox is running in this container; sbx runs one sandbox per container".to_string()
        }
        _ => format!("binding the abstract UNIX socket @sbx/sandbox: {e}"),
    })
}

const FORWARDED: [libc::c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

/// Run the program and supervise it until every sandboxed process is gone.
pub fn run(p: &Policy, l: Launch, svc: Services, sig: &Signals, cg: Option<&Delegation>) -> Result<Ran, SetupError> {
    launch(p, l, svc, sig, cg)
}

fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds has room for two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(os_err("pipe2"));
    }
    // SAFETY: both fds are new and owned by us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn socketpair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds has room for two descriptors.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(os_err("socketpair"));
    }
    // SAFETY: both fds are new and owned by us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// The signals the supervisor handles with sigtimedwait, blocked.
pub struct Signals {
    set: libc::sigset_t,
}

/// Block the signals the supervisor handles. Threads started later inherit
/// the mask, so these always reach the main loop; until then they wait.
pub fn block_signals() -> Result<Signals, String> {
    // SAFETY: sigset manipulation on a local set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in FORWARDED.iter().copied().chain([libc::SIGCHLD, fatal_signal()]) {
            if libc::sigaddset(&mut set, s) != 0 {
                return Err(os_err(format!("sigaddset({s})")));
            }
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(os_err("sigprocmask(SIG_BLOCK)"));
        }
        Ok(Signals { set })
    }
}

impl Signals {
    /// A signal that arrived during setup and means "stop": nothing is
    /// started then.
    fn check_pending(&self) -> Result<(), String> {
        // SAFETY: zeroed sigset is valid output storage.
        let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: pending is valid.
        if unsafe { libc::sigpending(&mut pending) } != 0 {
            return Err(os_err("sigpending"));
        }
        // SAFETY: membership test on a set the kernel filled.
        let has = |s| unsafe { libc::sigismember(&pending, s) } == 1;
        if has(fatal_signal()) {
            return Err(log::fatal_message().unwrap_or_else(|| "sbx failed during setup".into()));
        }
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            if has(s) {
                return Err(format!("received signal {s} during setup; not starting the program"));
            }
        }
        Ok(())
    }
}

fn launch(p: &Policy, mut l: Launch, svc: Services, sig: &Signals, cg: Option<&Delegation>) -> Result<Ran, SetupError> {
    // SAFETY: getpid has no preconditions.
    let am_pid1 = unsafe { libc::getpid() } == 1;
    if !am_pid1 {
        // Orphaned descendants get reparented to us so we can reap and kill them.
        // SAFETY: plain prctl.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(os_err("prctl(PR_SET_CHILD_SUBREAPER)")).at(Stage::Launch);
        }
    }
    sig.check_pending().at(Stage::Launch)?;
    let (err_r, err_w) = pipe().at(Stage::Launch)?;
    let (sock_parent, sock_child) = socketpair().at(Stage::Launch)?;
    // SAFETY: getpid has no preconditions.
    let parent_pid = unsafe { libc::getpid() };

    // SAFETY: the supervisor is single-threaded at this point.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(os_err("fork")).at(Stage::Launch);
    }
    if pid == 0 {
        drop(err_r);
        drop(sock_parent);
        let (stage, e) = child(p, &mut l, err_w.as_raw_fd(), sock_child.as_raw_fd(), parent_pid);
        let msg = format!("{}: {e}", stage.as_str());
        // SAFETY: report and exit without running destructors.
        unsafe {
            libc::write(err_w.as_raw_fd(), msg.as_ptr().cast(), msg.len());
            libc::_exit(stage.exit_code());
        }
    }

    // Parent: drop our copy of the ruleset fd and the child's ends.
    drop(l.landlock.take());
    drop(err_w);
    drop(sock_child);
    let listener = match notify::recv_fd(sock_parent.as_raw_fd()) {
        Ok(Received::Fd(fd)) => fd,
        Ok(Received::Eof) | Ok(Received::Text(_)) => return Err(child_setup_failed(pid, err_r, cg)),
        Err(e) => {
            kill_and_wait(pid);
            return Err(format!("receiving the seccomp listener from the child: {e}")).at(Stage::Listener);
        }
    };
    drop(sock_parent);

    let stats = Arc::new(Stats::default());
    let dispatcher = match start_services(p, &l, listener, svc, &stats) {
        Ok(d) => d,
        Err(e) => {
            kill_and_wait(pid);
            return Err(e).at(Stage::Services);
        }
    };

    // EOF on the close-on-exec pipe means execve succeeded.
    let mut msg = String::new();
    if let Err(e) = std::fs::File::from(err_r).read_to_string(&mut msg) {
        kill_and_wait(pid);
        return Err(format!("reading the child's setup status: {e}")).at(Stage::Launch);
    }
    if !msg.is_empty() {
        return Err(child_failure(pid, &msg, cg));
    }
    log::info(format!("started pid {pid}"));
    Ok(supervise(p, pid, am_pid1, sig, &stats, dispatcher, cg))
}

fn start_services(
    p: &Policy,
    l: &Launch,
    listener: OwnedFd,
    svc: Services,
    stats: &Arc<Stats>,
) -> Result<JoinHandle<()>, String> {
    let listener = Arc::new(Listener::new(listener)?);
    let dispatcher = Dispatcher {
        listener,
        table: l.seccomp.table.clone(),
        on_violation: p.seccomp.on_violation,
        egress: svc.egress.clone(),
        stats: Arc::clone(stats),
    }
    .spawn()?;
    if let Some((tcp, cfg)) = svc.dns {
        let egress = svc.egress.ok_or("BUG: DNS proxy without an egress filter")?;
        dns::Proxy::spawn(tcp, cfg, egress)?;
    }
    Ok(dispatcher)
}

fn child_setup_failed(pid: libc::pid_t, err_r: OwnedFd, cg: Option<&Delegation>) -> SetupError {
    let mut msg = String::new();
    if let Err(e) = std::fs::File::from(err_r).read_to_string(&mut msg) {
        kill_and_wait(pid);
        return SetupError {
            stage: Stage::Launch,
            errors: vec![format!("reading the child's setup status: {e}")],
        };
    }
    if msg.is_empty() {
        msg = "launch: the child exited without reporting an error".into();
    }
    child_failure(pid, &msg, cg)
}

/// The child's `"stage: message"` report, once the child is reaped.
fn child_failure(pid: libc::pid_t, msg: &str, cg: Option<&Delegation>) -> SetupError {
    let (stage, detail) = Stage::from_prefix(msg).unwrap_or((Stage::Launch, msg));
    let mut errors = vec![format!(
        "sandbox setup failed in the child: {}: {detail}",
        stage.as_str()
    )];
    if stage == Stage::Execve && detail.contains("Permission denied") {
        errors.push("hint: the program (and its interpreter) need 'x' in an fs rule, e.g. --rx /opt/app".into());
    }
    if let Err(e) = wait_for(pid, &mut Usage::default()) {
        errors.push(e);
    }
    if cg.is_some_and(|c| c.oom_kills() > 0) {
        errors.push("hint: the OOM killer killed the child during setup; raise cgroup.memory_mb".into());
    }
    SetupError { stage, errors }
}

/// waitpid that adds the reaped process's resource usage (which includes
/// the descendants it waited for itself) to `usage`. Ok(None): WNOHANG and
/// nothing has exited.
fn wait(pid: libc::pid_t, flags: libc::c_int, usage: &mut Usage) -> Result<Option<(libc::pid_t, libc::c_int)>, i32> {
    let mut st = 0;
    // SAFETY: zeroed rusage is valid output storage.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: waiting for our own children; st and ru are valid.
    let r = unsafe { libc::wait4(pid, &mut st, flags, &mut ru) };
    if r < 0 {
        return Err(errno());
    }
    if r == 0 {
        return Ok(None);
    }
    *usage = usage.combine(Usage::from_rusage(&ru));
    Ok(Some((r, st)))
}

fn wait_for(pid: libc::pid_t, usage: &mut Usage) -> Result<libc::c_int, String> {
    loop {
        match wait(pid, 0, usage) {
            Ok(Some((_, st))) => return Ok(st),
            Err(libc::EINTR) | Ok(None) => continue,
            Err(e) => return Err(format!("waitpid({pid}): {}", std::io::Error::from_raw_os_error(e))),
        }
    }
}

fn kill_and_wait(pid: libc::pid_t) {
    // SAFETY: killing our own child.
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 && errno() != libc::ESRCH {
        log::error(os_err(format!("kill({pid}, SIGKILL)")));
    }
    if let Err(e) = wait_for(pid, &mut Usage::default()) {
        log::error(e);
    }
}

/// Runs in the forked child. Returns only on failure.
fn child(p: &Policy, l: &mut Launch, err_fd: RawFd, sock_fd: RawFd, parent: libc::pid_t) -> (Stage, String) {
    // First, so everything the child does from here on is charged to the sandbox.
    if let Some(fd) = l.cgroup_procs {
        if let Err(e) = cgroup::join(fd) {
            return (Stage::Cgroup, e);
        }
    }
    // SAFETY (whole function): we are the only thread of a freshly forked child.
    unsafe {
        // Own session and process group: no controlling terminal, killable as a group.
        if libc::setsid() < 0 {
            return (Stage::Setsid, os_err("setsid"));
        }
        let wd = match CString::new(p.process.workdir.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => return (Stage::Chdir, "process.workdir contains a NUL byte".into()),
        };
        if libc::chdir(wd.as_ptr()) != 0 {
            return (Stage::Chdir, os_err(p.process.workdir.display()));
        }
    }
    if let Err(e) = set_limits(p) {
        return (Stage::Setrlimit, e);
    }
    if let Err(e) = drop_identity(p) {
        return (Stage::Identity, e);
    }
    unsafe {
        // Must come after the uid change, which clears it. Kills the child if sbx dies.
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            return (Stage::Pdeathsig, os_err("prctl(PR_SET_PDEATHSIG)"));
        }
        if libc::getppid() != parent {
            return (Stage::Pdeathsig, "the supervisor exited during setup".into());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return (Stage::NoNewPrivs, os_err("prctl(PR_SET_NO_NEW_PRIVS)"));
        }
    }
    // Everything the child needs after its policy filter is installed is
    // prepared now: from that point on it only makes the syscalls sbx
    // reserves (a denied syscall would block on a listener nobody reads yet).
    let mut argv: Vec<*const libc::c_char> = l.argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = l.envp.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    match (l.landlock.take(), p.landlock.abi) {
        (Some(rs), _) => {
            if let Err(e) = landlock_layer::enforce(rs) {
                return (Stage::Landlock, e);
            }
        }
        (None, LandlockAbi::Off) => {}
        (None, LandlockAbi::V(_)) => return (Stage::Landlock, "BUG: no Landlock ruleset".into()),
    }
    if let Err(e) = seccomp_layer::install_prelude(&l.seccomp.prelude) {
        return (Stage::Seccomp, e);
    }
    let listener = match seccomp_layer::install_with_listener(&l.seccomp.main) {
        Ok(fd) => fd,
        Err(e) => return (Stage::Seccomp, e),
    };
    if let Err(e) = notify::send_fd(sock_fd, listener) {
        return (Stage::Seccomp, format!("handing the listener to the supervisor: {e}"));
    }
    unsafe {
        libc::close(listener);
        libc::close(sock_fd);
    }
    if let Err(e) = close_fds_except(err_fd) {
        return (Stage::CloseRange, e);
    }
    if let Err(e) = reset_signals() {
        return (Stage::Signals, e);
    }

    // SAFETY: argv/envp are NULL-terminated arrays of live C strings.
    unsafe { libc::execve(l.exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    (Stage::Execve, os_err(l.exe.to_string_lossy()))
}

fn set_limits(p: &Policy) -> Result<(), String> {
    let set = |res, v: libc::rlim_t, name: &str| -> Result<(), String> {
        let lim = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: plain setrlimit with a valid struct.
        if unsafe { libc::setrlimit(res, &lim) } != 0 {
            return Err(os_err(format!(
                "{name} = {}",
                if v == libc::RLIM_INFINITY {
                    "unlimited".into()
                } else {
                    v.to_string()
                }
            )));
        }
        Ok(())
    };
    let val = |l: Limit, shift: u32| match l {
        Limit::Value(n) => (n << shift) as libc::rlim_t,
        Limit::Unlimited => libc::RLIM_INFINITY,
    };
    let l = &p.limits;
    set(libc::RLIMIT_CORE, 0, "RLIMIT_CORE")?;
    set(libc::RLIMIT_NOFILE, l.nofile as libc::rlim_t, "RLIMIT_NOFILE")?;
    set(libc::RLIMIT_NPROC, val(l.nproc, 0), "RLIMIT_NPROC")?;
    set(libc::RLIMIT_FSIZE, val(l.fsize_mb, 20), "RLIMIT_FSIZE")?;
    set(libc::RLIMIT_AS, val(l.as_mb, 20), "RLIMIT_AS")?;
    set(libc::RLIMIT_CPU, val(l.cpu_secs, 0), "RLIMIT_CPU")?;
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn capget() -> Result<[CapData; 2], String> {
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: header and two data structs as required by v3.
    if unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) } != 0 {
        return Err(os_err("capget"));
    }
    Ok(data)
}

fn last_cap() -> Result<u32, String> {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|e| format!("read /proc/sys/kernel/cap_last_cap: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("parse /proc/sys/kernel/cap_last_cap: {e}"))
}

/// Switch to the policy identity and leave the child with no capabilities.
fn drop_identity(p: &Policy) -> Result<(), String> {
    let (uid, gid) = (p.process.uid, p.process.gid);
    let last = last_cap()?;
    // SAFETY: identity syscalls in the single-threaded child.
    unsafe {
        if libc::geteuid() == 0 {
            // While still privileged: empty the bounding set, so nothing in the
            // sandbox can ever regain a capability.
            for cap in 0..=last {
                if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) != 0 {
                    return Err(os_err(format!("prctl(PR_CAPBSET_DROP, {cap}) (needs CAP_SETPCAP)")));
                }
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(os_err("setgroups([])"));
            }
            if libc::setresgid(gid, gid, gid) != 0 {
                return Err(os_err(format!("setresgid({gid})")));
            }
            if libc::setresuid(uid, uid, uid) != 0 {
                return Err(os_err(format!("setresuid({uid})")));
            }
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        if libc::getresuid(&mut r, &mut e, &mut s) != 0 || [r, e, s] != [uid; 3] {
            return Err(format!("uid is {r}/{e}/{s}, expected {uid}"));
        }
        if libc::getresgid(&mut r, &mut e, &mut s) != 0 || [r, e, s] != [gid; 3] {
            return Err(format!("gid is {r}/{e}/{s}, expected {gid}"));
        }
        if libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 {
            return Err(os_err("prctl(PR_CAP_AMBIENT_CLEAR_ALL)"));
        }
        let hdr = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let zero = [CapData::default(); 2];
        if libc::syscall(libc::SYS_capset, &hdr, zero.as_ptr()) != 0 {
            return Err(os_err("capset(no capabilities)"));
        }
    }
    let caps = capget()?;
    if caps != [CapData::default(); 2] {
        return Err(format!("capabilities remain after dropping them: {caps:?}"));
    }
    Ok(())
}

/// Close inherited descriptors (e.g. a parent server's sockets) except stdio and `keep`.
fn close_fds_except(keep: RawFd) -> Result<(), String> {
    let keep = keep as libc::c_uint;
    let close_range = |lo: libc::c_uint, hi: libc::c_uint| -> Result<(), String> {
        // SAFETY: closing fd ranges in the child.
        if unsafe { libc::syscall(libc::SYS_close_range, lo, hi, 0u32) } != 0 {
            return Err(os_err(format!("close_range({lo}, {hi})")));
        }
        Ok(())
    };
    if keep > 3 {
        close_range(3, keep - 1)?;
    }
    close_range(keep + 1, libc::c_uint::MAX)
}

/// Number of signals the kernel knows (_NSIG) and the size of its sigset.
const KERNEL_NSIG: libc::c_int = 64;
const KERNEL_SIGSET_SIZE: usize = 8;

/// The program starts with default dispositions for every signal and an
/// empty mask, whatever sbx inherited (Rust ignores SIGPIPE, runtimes may
/// ignore SIGHUP or real-time signals). Handled signals are reset by execve;
/// ignored ones are not. Raw syscalls are used because libc wrappers refuse
/// the real-time signals they reserve for themselves.
fn reset_signals() -> Result<(), String> {
    // Kernel struct sigaction: handler, flags, [restorer,] mask. All zero is
    // SIG_DFL with no flags and an empty mask, whichever layout applies.
    let dfl = [0u64; 4];
    for sig in 1..=KERNEL_NSIG {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            continue;
        }
        // SAFETY: dfl is a zeroed kernel sigaction; no old action is requested.
        let r = unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                sig,
                dfl.as_ptr(),
                std::ptr::null_mut::<u64>(),
                KERNEL_SIGSET_SIZE,
            )
        };
        if r != 0 {
            return Err(os_err(format!("rt_sigaction({sig}, SIG_DFL)")));
        }
    }
    let empty = 0u64;
    // SAFETY: an empty kernel sigset; the old mask is not requested.
    let r = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &empty as *const u64,
            std::ptr::null_mut::<u64>(),
            KERNEL_SIGSET_SIZE,
        )
    };
    if r != 0 {
        return Err(os_err("rt_sigprocmask(SIG_SETMASK, {})"));
    }
    Ok(())
}

fn supervise(
    p: &Policy,
    child: libc::pid_t,
    am_pid1: bool,
    sig: &Signals,
    stats: &Stats,
    dispatcher: JoinHandle<()>,
    cg: Option<&Delegation>,
) -> Ran {
    let started = Instant::now();
    let deadline = match p.process.timeout_secs {
        Timeout::Secs(n) => Some(started + Duration::from_secs(n)),
        Timeout::None => None,
    };
    let grace = Duration::from_secs(p.process.kill_grace_secs);
    let mut kill_at: Option<Instant> = None;
    let mut timed_out = false;
    let mut fatal = false;
    // Whether sbx killed the tree before the program exited.
    let mut killed = false;
    let mut usage = Usage::default();
    let kill = |killed: &mut bool| {
        *killed = true;
        kill_tree(child, am_pid1, cg);
    };

    let status = loop {
        let now = Instant::now();
        if let Some(d) = deadline {
            if now >= d && !timed_out {
                timed_out = true;
                log::error(format!(
                    "timeout after {}s, killing the sandbox",
                    d.duration_since(started).as_secs()
                ));
                kill(&mut killed);
            }
        }
        if let Some(k) = kill_at {
            if now >= k {
                log::info("grace period over, sending SIGKILL");
                kill(&mut killed);
                kill_at = None;
            }
        }
        let next = [deadline.filter(|_| !timed_out), kill_at].into_iter().flatten().min();
        let ts = next.map(|n| {
            let d = n.saturating_duration_since(Instant::now());
            libc::timespec {
                tv_sec: d.as_secs() as _,
                tv_nsec: d.subsec_nanos() as _,
            }
        });
        // SAFETY: zeroed siginfo is valid output storage.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: set and info are valid; ts is either null or a valid timespec.
        let s = unsafe {
            libc::sigtimedwait(
                &sig.set,
                &mut info,
                ts.as_ref().map_or(std::ptr::null(), |t| t as *const _),
            )
        };
        if s < 0 {
            match errno() {
                libc::EAGAIN | libc::EINTR => continue,
                _ => {
                    log::raise_fatal(&os_err("sigtimedwait"));
                    fatal = true;
                    kill(&mut killed);
                    match wait_for(child, &mut usage) {
                        Ok(st) => break Some(st),
                        Err(e) => {
                            log::error(e);
                            break None;
                        }
                    }
                }
            }
        }
        if s == libc::SIGCHLD {
            if let Some(st) = reap(child, &mut usage) {
                break Some(st);
            }
            continue;
        }
        if s == fatal_signal() {
            fatal = true;
            kill(&mut killed);
            continue;
        }
        // Forward termination and user signals to the sandbox's process group.
        // SAFETY: signalling our child's process group.
        if unsafe { libc::kill(-child, s) } != 0 && errno() != libc::ESRCH {
            log::error(os_err(format!("forwarding signal {s} to the sandbox")));
        }
        if matches!(s, libc::SIGTERM | libc::SIGINT | libc::SIGHUP | libc::SIGQUIT) {
            if kill_at.is_some() {
                kill(&mut killed); // second signal: don't wait
            } else {
                kill_at = Some(Instant::now() + grace);
            }
        }
    };
    let wall = started.elapsed();

    // The main program is gone; nothing it left behind may outlive it.
    let killed_after_exit = (!killed).then(|| leftovers(am_pid1, cg));
    if let Some(n @ 1..) = killed_after_exit {
        log::info(format!(
            "killing {n} process(es) still running after the program exited"
        ));
    }
    kill_tree(child, am_pid1, cg);
    reap_all(am_pid1, &mut usage);
    // The listener reports POLLHUP once no sandboxed task is left, so the
    // dispatcher returns and the denial counts are final.
    let until = Instant::now() + Duration::from_secs(2);
    while !dispatcher.is_finished() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    if dispatcher.is_finished() {
        let _ = dispatcher.join();
    } else {
        log::warn("the seccomp notification thread is still running; the denial counts may be incomplete");
    }
    for line in stats.summary() {
        log::info(format!("repeated: {line}"));
    }

    let program = status.and_then(Program::from_wait_status);
    match (status, program) {
        (_, Some(Program::Signaled(s))) => log::info(format!("program killed by signal {s}")),
        (Some(st), None) => log::error(format!("unexpected wait status {st:#x}")),
        _ => {}
    }
    let code = report::exit_code(fatal, timed_out, program);
    log::info(format!("exit {code} after {:.1}s", wall.as_secs_f64()));
    Ran {
        exit_code: code,
        program,
        timed_out,
        supervisor_error: if fatal { log::fatal_message() } else { None },
        denials: stats.denials(),
        killed_after_exit,
        wall_ms: wall.as_millis() as u64,
        usage,
        cgroup: None,
    }
}

/// Reap whatever has exited; return the main child's status once it has.
fn reap(child: libc::pid_t, usage: &mut Usage) -> Option<libc::c_int> {
    let mut main = None;
    loop {
        match wait(-1, libc::WNOHANG, usage) {
            Ok(Some((pid, st))) if pid == child => main = Some(st),
            Ok(Some(_)) => {}
            Ok(None) | Err(libc::ECHILD) => return main,
            Err(libc::EINTR) => {}
            Err(e) => {
                log::error(format!("waitpid(-1): {}", std::io::Error::from_raw_os_error(e)));
                return main;
            }
        }
    }
}

/// How many sandboxed processes (not zombies) are still running.
fn leftovers(am_pid1: bool, cg: Option<&Delegation>) -> u32 {
    if let Some(c) = cg {
        match c.live_processes() {
            Ok(n) => return n,
            Err(e) => log::error(format!("counting the processes left in the sandbox cgroup: {e}")),
        }
    }
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() };
    live_descendants(&proc_table(), me, am_pid1)
}

/// One /proc entry: (pid, parent pid, is a zombie).
type ProcEntry = (libc::pid_t, libc::pid_t, bool);

/// Live processes below `root`: with `everything` (sbx is PID 1 of the
/// container), every process but `root` itself.
fn live_descendants(procs: &[ProcEntry], root: libc::pid_t, everything: bool) -> u32 {
    let below: BTreeSet<libc::pid_t> = if everything {
        procs
            .iter()
            .map(|&(pid, _, _)| pid)
            .filter(|&pid| pid != root)
            .collect()
    } else {
        let mut below = BTreeSet::new();
        let mut parents = vec![root];
        while let Some(parent) = parents.pop() {
            for &(pid, ppid, _) in procs {
                if ppid == parent && pid != root && below.insert(pid) {
                    parents.push(pid);
                }
            }
        }
        below
    };
    procs
        .iter()
        .filter(|&&(pid, _, zombie)| !zombie && below.contains(&pid))
        .count() as u32
}

fn proc_table() -> Vec<ProcEntry> {
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            log::error(format!("cannot list /proc to find leftover sandbox processes: {e}"));
            return vec![];
        }
    };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter_map(|pid| {
            // "pid (comm) state ppid ...": comm may contain anything, so split at its last ')'.
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let (_, rest) = stat.rsplit_once(')')?;
            let mut f = rest.split_whitespace();
            let state = f.next()?;
            let ppid = f.next()?.parse().ok()?;
            Some((pid, ppid, state == "Z"))
        })
        .collect()
}

fn kill_tree(child: libc::pid_t, am_pid1: bool, cg: Option<&Delegation>) {
    // The sandbox cgroup holds every sandboxed process, whatever its session.
    if let Some(c) = cg {
        if let Err(e) = c.kill() {
            log::error(e);
        }
    }
    // SAFETY: signalling our own descendants.
    unsafe {
        if libc::kill(-child, libc::SIGKILL) != 0 && errno() != libc::ESRCH {
            log::error(os_err("kill(sandbox process group, SIGKILL)"));
        }
        if am_pid1 {
            // As PID 1 of the container's PID namespace this reaches every other
            // process, including ones that left the process group with setsid().
            if libc::kill(-1, libc::SIGKILL) != 0 && errno() != libc::ESRCH {
                log::error(os_err("kill(-1, SIGKILL)"));
            }
        }
    }
    if !am_pid1 {
        // Subreaper: escapees are reparented to us once their parent dies.
        for pid in own_children() {
            // SAFETY: signalling our own child.
            if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 && errno() != libc::ESRCH {
                log::error(os_err(format!("kill({pid}, SIGKILL)")));
            }
        }
    }
}

fn reap_all(am_pid1: bool, usage: &mut Usage) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match wait(-1, libc::WNOHANG, usage) {
            Ok(Some(_)) | Err(libc::EINTR) => {}
            Err(libc::ECHILD) => return,
            Err(e) => {
                log::error(format!("waitpid(-1): {}", std::io::Error::from_raw_os_error(e)));
                return;
            }
            Ok(None) => {
                if Instant::now() > until {
                    log::error("some sandboxed processes did not exit within 5s of SIGKILL");
                    return;
                }
                if !am_pid1 {
                    for pid in own_children() {
                        // SAFETY: signalling our own child.
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn own_children() -> Vec<libc::pid_t> {
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() };
    proc_table()
        .into_iter()
        .filter(|&(_, ppid, _)| ppid == me)
        .map(|(pid, _, _)| pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A random forest of processes: entry i's parent is an earlier entry,
    /// or a process outside the tree.
    fn table() -> impl Strategy<Value = Vec<ProcEntry>> {
        prop::collection::vec((any::<prop::sample::Index>(), any::<bool>(), any::<bool>()), 0..40).prop_map(|v| {
            let mut t: Vec<ProcEntry> = vec![(1, 0, false)];
            for (i, (parent, outside, zombie)) in v.into_iter().enumerate() {
                let pid = 2 + i as libc::pid_t;
                let ppid = if outside { 1000 } else { t[parent.index(t.len())].0 };
                t.push((pid, ppid, zombie));
            }
            t
        })
    }

    proptest! {
        #[test]
        fn leftovers_are_the_live_descendants(t in table(), root_ix in any::<prop::sample::Index>()) {
            let root = t[root_ix.index(t.len())].0;
            let n = live_descendants(&t, root, false);
            // Brute force: follow each process's parents up to the root.
            let parent = |pid| t.iter().find(|e| e.0 == pid).map(|e| e.1);
            let below = |mut pid| loop {
                match parent(pid) {
                    Some(pp) if pp == root => return true,
                    Some(pp) => pid = pp,
                    None => return false,
                }
            };
            let want = t.iter().filter(|e| e.0 != root && !e.2 && below(e.0)).count() as u32;
            prop_assert_eq!(n, want);
            let all = t.iter().filter(|e| e.0 != root && !e.2).count() as u32;
            prop_assert_eq!(live_descendants(&t, root, true), all);
        }
    }
}
