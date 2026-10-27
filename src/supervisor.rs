//! Process model:
//!
//!   sbx (supervisor: PID 1 in a container, unsandboxed, never runs payload code)
//!    ├─ threads, started after fork: seccomp notification dispatcher,
//!    │  blocking egress connects, DNS proxy
//!    └─ child: setsid → chdir → rlimits → drop identity and capabilities
//!              → PDEATHSIG → NO_NEW_PRIVS → Landlock → seccomp prelude
//!              → policy filter (listener handed to the supervisor) → execve
//!         └─ untrusted program and all its descendants (inherit every layer)
//!
//! The supervisor is single-threaded until after fork, so the child may
//! allocate before exec. Setup failures in the child come back over a
//! close-on-exec pipe; the listener comes over a SOCK_SEQPACKET socketpair.

use crate::dns;
use crate::egress::Egress;
use crate::landlock_layer;
use crate::log::{self, errno, os_err};
use crate::notify::{self, Dispatcher, Listener, Received, Stats};
use crate::policy::{DnsCfg, Limit, Policy, Timeout};
use crate::seccomp_layer::{self, Programs};
use landlock::RulesetCreated;
use std::ffi::CString;
use std::io::Read;
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Launch {
    pub exe: CString,
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub landlock: Option<RulesetCreated>,
    pub seccomp: Programs,
}

/// Supervisor-side services for the sandbox.
pub struct Services {
    pub egress: Option<Arc<Egress>>,
    pub dns: Option<(TcpListener, DnsCfg)>,
}

const FORWARDED: [libc::c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

pub fn run(p: &Policy, l: Launch, svc: Services) -> i32 {
    match launch(p, l, svc) {
        Ok(code) => code,
        Err(e) => {
            log::error(e);
            125
        }
    }
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

/// Block the signals the supervisor handles with sigtimedwait. Threads
/// started later inherit the mask, so these always reach the main loop.
fn block_signals() -> Result<libc::sigset_t, String> {
    // SAFETY: sigset manipulation on a local set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in FORWARDED.iter().copied().chain([libc::SIGCHLD, notify::fatal_signal()]) {
            if libc::sigaddset(&mut set, s) != 0 {
                return Err(os_err(format!("sigaddset({s})")));
            }
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(os_err("sigprocmask(SIG_BLOCK)"));
        }
        Ok(set)
    }
}

fn launch(p: &Policy, mut l: Launch, svc: Services) -> Result<i32, String> {
    // SAFETY: getpid has no preconditions.
    let am_pid1 = unsafe { libc::getpid() } == 1;
    if !am_pid1 {
        // Orphaned descendants get reparented to us so we can reap and kill them.
        // SAFETY: plain prctl.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(os_err("prctl(PR_SET_CHILD_SUBREAPER)"));
        }
    }
    let set = block_signals()?;
    let (err_r, err_w) = pipe()?;
    let (sock_parent, sock_child) = socketpair()?;
    // SAFETY: getpid has no preconditions.
    let parent_pid = unsafe { libc::getpid() };

    // SAFETY: the supervisor is single-threaded at this point.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(os_err("fork"));
    }
    if pid == 0 {
        drop(err_r);
        drop(sock_parent);
        let (stage, e) = child(p, &mut l, err_w.as_raw_fd(), sock_child.as_raw_fd(), parent_pid);
        let msg = format!("{stage}: {e}");
        // SAFETY: report and exit without running destructors.
        unsafe {
            libc::write(err_w.as_raw_fd(), msg.as_ptr().cast(), msg.len());
            libc::_exit(if stage == "execve" { 127 } else { 125 });
        }
    }

    // Parent: drop our copy of the ruleset fd and the child's ends.
    drop(l.landlock.take());
    drop(err_w);
    drop(sock_child);
    let listener = match notify::recv_fd(sock_parent.as_raw_fd()) {
        Ok(Received::Fd(fd)) => fd,
        Ok(Received::Eof) | Ok(Received::Text(_)) => return child_setup_failed(pid, err_r),
        Err(e) => {
            kill_and_wait(pid);
            return Err(format!("receiving the seccomp listener from the child: {e}"));
        }
    };
    drop(sock_parent);

    let stats = Arc::new(Stats::default());
    if let Err(e) = start_services(p, &l, listener, svc, &stats) {
        kill_and_wait(pid);
        return Err(e);
    }

    // EOF on the close-on-exec pipe means execve succeeded.
    let mut msg = String::new();
    if let Err(e) = std::fs::File::from(err_r).read_to_string(&mut msg) {
        kill_and_wait(pid);
        return Err(format!("reading the child's setup status: {e}"));
    }
    if !msg.is_empty() {
        return Ok(report_child_failure(pid, &msg));
    }
    log::info(format!("started pid {pid}"));
    Ok(supervise(p, pid, am_pid1, &set, &stats))
}

fn start_services(p: &Policy, l: &Launch, listener: OwnedFd, svc: Services, stats: &Arc<Stats>) -> Result<(), String> {
    let listener = Arc::new(Listener::new(listener)?);
    Dispatcher {
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
    Ok(())
}

fn child_setup_failed(pid: libc::pid_t, err_r: OwnedFd) -> Result<i32, String> {
    let mut msg = String::new();
    if let Err(e) = std::fs::File::from(err_r).read_to_string(&mut msg) {
        kill_and_wait(pid);
        return Err(format!("reading the child's setup status: {e}"));
    }
    if msg.is_empty() {
        msg = "the child exited without reporting an error".into();
    }
    Ok(report_child_failure(pid, &msg))
}

fn report_child_failure(pid: libc::pid_t, msg: &str) -> i32 {
    log::error(format!("sandbox setup failed in the child: {msg}"));
    if msg.starts_with("execve") && msg.contains("Permission denied") {
        log::error("hint: the program (and its interpreter) need 'x' in an fs rule, e.g. --rx /opt/app");
    }
    match wait_for(pid) {
        Ok(st) if libc::WIFEXITED(st) => libc::WEXITSTATUS(st),
        Ok(_) => 125,
        Err(e) => {
            log::error(e);
            125
        }
    }
}

fn wait_for(pid: libc::pid_t) -> Result<libc::c_int, String> {
    let mut st = 0;
    loop {
        // SAFETY: waiting for our own child.
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r == pid {
            return Ok(st);
        }
        if errno() != libc::EINTR {
            return Err(os_err(format!("waitpid({pid})")));
        }
    }
}

fn kill_and_wait(pid: libc::pid_t) {
    // SAFETY: killing our own child.
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 && errno() != libc::ESRCH {
        log::error(os_err(format!("kill({pid}, SIGKILL)")));
    }
    if let Err(e) = wait_for(pid) {
        log::error(e);
    }
}

/// Runs in the forked child. Returns only on failure.
fn child(p: &Policy, l: &mut Launch, err_fd: RawFd, sock_fd: RawFd, parent: libc::pid_t) -> (&'static str, String) {
    // SAFETY (whole function): we are the only thread of a freshly forked child.
    unsafe {
        // Own session and process group: no controlling terminal, killable as a group.
        if libc::setsid() < 0 {
            return ("setsid", os_err("setsid"));
        }
        let wd = match CString::new(p.process.workdir.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => return ("chdir", "process.workdir contains a NUL byte".into()),
        };
        if libc::chdir(wd.as_ptr()) != 0 {
            return ("chdir", os_err(p.process.workdir.display()));
        }
    }
    if let Err(e) = set_limits(p) {
        return ("setrlimit", e);
    }
    if let Err(e) = drop_identity(p) {
        return ("identity", e);
    }
    unsafe {
        // Must come after the uid change, which clears it. Kills the child if sbx dies.
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            return ("pdeathsig", os_err("prctl(PR_SET_PDEATHSIG)"));
        }
        if libc::getppid() != parent {
            return ("pdeathsig", "the supervisor exited during setup".into());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return ("no_new_privs", os_err("prctl(PR_SET_NO_NEW_PRIVS)"));
        }
    }
    // Everything the child needs after its policy filter is installed is
    // prepared now: from that point on it only makes the syscalls sbx
    // reserves (a denied syscall would block on a listener nobody reads yet).
    let mut argv: Vec<*const libc::c_char> = l.argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = l.envp.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    match l.landlock.take() {
        Some(rs) => {
            if let Err(e) = landlock_layer::enforce(rs) {
                return ("landlock", e);
            }
        }
        None => return ("landlock", "BUG: no Landlock ruleset".into()),
    }
    if let Err(e) = seccomp_layer::install_prelude(&l.seccomp.prelude) {
        return ("seccomp", e);
    }
    let listener = match seccomp_layer::install_with_listener(&l.seccomp.main) {
        Ok(fd) => fd,
        Err(e) => return ("seccomp", e),
    };
    if let Err(e) = notify::send_fd(sock_fd, listener) {
        return ("seccomp", format!("handing the listener to the supervisor: {e}"));
    }
    unsafe {
        libc::close(listener);
        libc::close(sock_fd);
    }
    if let Err(e) = close_fds_except(err_fd) {
        return ("close_range", e);
    }
    if let Err(e) = reset_signals() {
        return ("signals", e);
    }

    // SAFETY: argv/envp are NULL-terminated arrays of live C strings.
    unsafe { libc::execve(l.exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    ("execve", os_err(l.exe.to_string_lossy()))
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

fn supervise(p: &Policy, child: libc::pid_t, am_pid1: bool, set: &libc::sigset_t, stats: &Stats) -> i32 {
    let started = Instant::now();
    let deadline = match p.process.timeout_secs {
        Timeout::Secs(n) => Some(started + Duration::from_secs(n)),
        Timeout::None => None,
    };
    let grace = Duration::from_secs(p.process.kill_grace_secs);
    let mut kill_at: Option<Instant> = None;
    let mut timed_out = false;
    let mut fatal = false;

    let status = loop {
        let now = Instant::now();
        if let Some(d) = deadline {
            if now >= d && !timed_out {
                timed_out = true;
                log::error(format!(
                    "timeout after {}s, killing the sandbox",
                    d.duration_since(started).as_secs()
                ));
                kill_tree(child, am_pid1);
            }
        }
        if let Some(k) = kill_at {
            if now >= k {
                log::info("grace period over, sending SIGKILL");
                kill_tree(child, am_pid1);
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
        let sig =
            unsafe { libc::sigtimedwait(set, &mut info, ts.as_ref().map_or(std::ptr::null(), |t| t as *const _)) };
        if sig < 0 {
            match errno() {
                libc::EAGAIN | libc::EINTR => continue,
                _ => {
                    log::error(os_err("sigtimedwait"));
                    fatal = true;
                    kill_tree(child, am_pid1);
                    match wait_for(child) {
                        Ok(st) => break st,
                        Err(e) => {
                            log::error(e);
                            return 125;
                        }
                    }
                }
            }
        }
        if sig == libc::SIGCHLD {
            if let Some(st) = reap(child) {
                break st;
            }
            continue;
        }
        if sig == notify::fatal_signal() {
            fatal = true;
            kill_tree(child, am_pid1);
            continue;
        }
        // Forward termination and user signals to the sandbox's process group.
        // SAFETY: signalling our child's process group.
        if unsafe { libc::kill(-child, sig) } != 0 && errno() != libc::ESRCH {
            log::error(os_err(format!("forwarding signal {sig} to the sandbox")));
        }
        if matches!(sig, libc::SIGTERM | libc::SIGINT | libc::SIGHUP | libc::SIGQUIT) {
            if kill_at.is_some() {
                kill_tree(child, am_pid1); // second signal: don't wait
            } else {
                kill_at = Some(Instant::now() + grace);
            }
        }
    };

    // The main program is gone; nothing it left behind may outlive it.
    kill_tree(child, am_pid1);
    reap_all(am_pid1);
    for line in stats.summary() {
        log::info(format!("repeated: {line}"));
    }

    let code = if fatal {
        125
    } else if timed_out {
        124
    } else if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        let s = libc::WTERMSIG(status);
        log::info(format!("program killed by signal {s}"));
        128 + s
    } else {
        log::error(format!("unexpected wait status {status:#x}"));
        125
    };
    log::info(format!("exit {code} after {:.1}s", started.elapsed().as_secs_f64()));
    code
}

/// Reap whatever has exited; return the main child's status once it has.
fn reap(child: libc::pid_t) -> Option<libc::c_int> {
    let mut main = None;
    loop {
        let mut st = 0;
        // SAFETY: non-blocking wait for any child.
        let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if r < 0 && errno() != libc::ECHILD {
            log::error(os_err("waitpid(-1)"));
        }
        if r <= 0 {
            return main;
        }
        if r == child {
            main = Some(st);
        }
    }
}

fn kill_tree(child: libc::pid_t, am_pid1: bool) {
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

fn reap_all(am_pid1: bool) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let mut st = 0;
        // SAFETY: non-blocking wait for any child.
        let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if r < 0 {
            if errno() != libc::ECHILD {
                log::error(os_err("waitpid(-1)"));
            }
            return;
        }
        if r == 0 {
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

fn own_children() -> Vec<libc::pid_t> {
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() };
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            log::error(format!("cannot list /proc to find leftover sandbox processes: {e}"));
            return vec![];
        }
    };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter(|&pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| {
                s.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().nth(1)?.parse().ok())
            }) == Some(me)
        })
        .collect()
}
