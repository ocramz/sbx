//! Process model:
//!
//!   sbx (supervisor, unsandboxed, PID 1 in job mode)
//!    └─ child: setsid → rlimits → drop uid/gid → NO_NEW_PRIVS → Landlock → seccomp → execve
//!         └─ untrusted program and all its descendants (inherit every layer)
//!
//! The supervisor is single-threaded, so the child may allocate between fork
//! and exec. Setup failures in the child are sent back over a CLOEXEC pipe.

use crate::landlock_layer;
use crate::policy::Policy;
use crate::seccomp_layer::{self, Programs};
use landlock::RulesetCreated;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

pub struct Launch {
    pub exe: CString,
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub landlock: Option<RulesetCreated>,
    pub seccomp: Option<Programs>,
}

const FORWARDED: [libc::c_int; 6] =
    [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT, libc::SIGUSR1, libc::SIGUSR2];

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

pub fn run(p: &Policy, mut l: Launch) -> i32 {
    let am_pid1 = unsafe { libc::getpid() } == 1;
    if !am_pid1 {
        // Orphaned descendants get reparented to us so we can reap/kill them.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    }

    // Block the signals we handle synchronously via sigtimedwait().
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        for s in FORWARDED {
            libc::sigaddset(&mut set, s);
        }
        libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old);
    }

    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        crate::log_error(&os_err("pipe2"));
        return 125;
    }
    let (rd, wr) = (fds[0], fds[1]);
    let parent_pid = unsafe { libc::getpid() };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        crate::log_error(&os_err("fork"));
        return 125;
    }
    if pid == 0 {
        unsafe { libc::close(rd) };
        let (stage, err) = child(p, &mut l, wr, parent_pid, &old);
        let msg = format!("{stage}: {err}");
        unsafe {
            libc::write(wr, msg.as_ptr().cast(), msg.len());
            libc::_exit(if stage == "execve" { 127 } else { 125 });
        }
    }

    // Parent. Drop our copy of the ruleset fd and wait for exec (pipe EOF) or an error.
    drop(l.landlock.take());
    unsafe { libc::close(wr) };
    let mut msg = String::new();
    let _ = unsafe { std::fs::File::from_raw_fd(rd) }.read_to_string(&mut msg);
    if !msg.is_empty() {
        crate::log_error(&format!("sandbox setup failed in child: {msg}"));
        if msg.starts_with("execve") && msg.contains("Permission denied") {
            crate::log_error("hint: the program (and its interpreter) need 'x' in an fs rule, e.g. --rx /opt/app");
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        return if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 125 };
    }
    crate::log_info(&format!("started pid {pid}"));

    supervise(p, pid, am_pid1, &set)
}

/// Runs in the forked child. Returns only on failure.
fn child(p: &Policy, l: &mut Launch, err_fd: RawFd, parent: libc::pid_t, mask: &libc::sigset_t) -> (&'static str, String) {
    unsafe {
        // Own session + process group: no controlling terminal, killable as a group.
        if libc::setsid() < 0 {
            return ("setsid", os_err("setsid"));
        }
        if let Some(dir) = &p.process.workdir {
            let c = CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
            if libc::chdir(c.as_ptr()) != 0 {
                return ("chdir", os_err(&dir.display().to_string()));
            }
        }
        if let Err(e) = set_limits(p) {
            return ("setrlimit", e);
        }
        if libc::geteuid() == 0 {
            let (uid, gid) = (p.process.uid, p.process.gid);
            if uid == 0 {
                return ("setuid", "refusing to run the sandbox as uid 0".into());
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return ("drop-privileges", os_err("setres[ug]id"));
            }
            if libc::getuid() != uid || libc::geteuid() != uid {
                return ("drop-privileges", "uid did not change".into());
            }
        }
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        // Must be set after the uid change (which clears it). Kills the child if sbx dies.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        if libc::getppid() != parent {
            return ("pdeathsig", "supervisor exited during setup".into());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return ("no_new_privs", os_err("prctl"));
        }
    }
    if let Some(rs) = l.landlock.take() {
        if let Err(e) = landlock_layer::enforce(rs) {
            return ("landlock", e);
        }
    }
    if let Some(sc) = &l.seccomp {
        if let Err(e) = seccomp_layer::enforce(sc) {
            return ("seccomp", e);
        }
    }
    close_fds_except(err_fd);
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, mask, std::ptr::null_mut()) };

    let mut argv: Vec<*const libc::c_char> = l.argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = l.envp.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    unsafe { libc::execve(l.exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    ("execve", os_err(&l.exe.to_string_lossy()))
}

fn set_limits(p: &Policy) -> Result<(), String> {
    let set = |res, v: u64, name: &str| -> Result<(), String> {
        let lim = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
        if unsafe { libc::setrlimit(res, &lim) } != 0 {
            return Err(os_err(name));
        }
        Ok(())
    };
    let l = &p.limits;
    set(libc::RLIMIT_CORE, 0, "RLIMIT_CORE")?;
    if let Some(v) = l.nofile {
        set(libc::RLIMIT_NOFILE, v, "RLIMIT_NOFILE")?;
    }
    if let Some(v) = l.nproc {
        set(libc::RLIMIT_NPROC, v, "RLIMIT_NPROC")?;
    }
    if let Some(v) = l.fsize_mb {
        set(libc::RLIMIT_FSIZE, v << 20, "RLIMIT_FSIZE")?;
    }
    if let Some(v) = l.as_mb {
        set(libc::RLIMIT_AS, v << 20, "RLIMIT_AS")?;
    }
    if let Some(v) = l.cpu_secs {
        set(libc::RLIMIT_CPU, v, "RLIMIT_CPU")?;
    }
    Ok(())
}

/// Close inherited descriptors (e.g. a parent server's sockets) except stdio and `keep`.
fn close_fds_except(keep: RawFd) {
    let keep = keep as libc::c_uint;
    let close_range = |lo: libc::c_uint, hi: libc::c_uint| unsafe { libc::syscall(libc::SYS_close_range, lo, hi, 0u32) };
    let lower_ok = keep <= 3 || close_range(3, keep - 1) == 0;
    if !(lower_ok && close_range(keep + 1, libc::c_uint::MAX) == 0) {
        for fd in 3..65536 {
            if fd != keep as i32 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

fn supervise(p: &Policy, child: libc::pid_t, am_pid1: bool, set: &libc::sigset_t) -> i32 {
    let started = Instant::now();
    let deadline = (p.process.timeout_secs > 0).then(|| started + Duration::from_secs(p.process.timeout_secs));
    let grace = Duration::from_secs(p.process.kill_grace_secs);
    let mut kill_at: Option<Instant> = None;
    let mut timed_out = false;

    let status = loop {
        let now = Instant::now();
        if let Some(d) = deadline {
            if now >= d && !timed_out {
                timed_out = true;
                crate::log_error(&format!("timeout after {}s, killing sandbox", p.process.timeout_secs));
                kill_tree(child, am_pid1);
            }
        }
        if let Some(k) = kill_at {
            if now >= k {
                crate::log_info("grace period over, sending SIGKILL");
                kill_tree(child, am_pid1);
                kill_at = None;
            }
        }
        let next = [deadline.filter(|_| !timed_out), kill_at].into_iter().flatten().min();
        let ts = next.map(|n| {
            let d = n.saturating_duration_since(Instant::now());
            libc::timespec { tv_sec: d.as_secs() as libc::time_t, tv_nsec: d.subsec_nanos() as _ }
        });
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let sig = unsafe {
            libc::sigtimedwait(set, &mut info, ts.as_ref().map_or(std::ptr::null(), |t| t as *const _))
        };
        if sig < 0 {
            match errno() {
                libc::EAGAIN | libc::EINTR => continue,
                _ => {
                    crate::log_error(&os_err("sigtimedwait"));
                    kill_tree(child, am_pid1);
                }
            }
        }
        if sig == libc::SIGCHLD || sig < 0 {
            if let Some(st) = reap(child) {
                break st;
            }
            continue;
        }
        // Forward termination/user signals to the sandbox's process group.
        unsafe { libc::kill(-child, sig) };
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

    let code = if timed_out {
        124
    } else if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        let s = libc::WTERMSIG(status);
        if s == libc::SIGSYS {
            crate::log_error("program killed by SIGSYS: blocked syscall (seccomp on_violation=kill)");
        } else {
            crate::log_info(&format!("program killed by signal {s}"));
        }
        128 + s
    } else {
        125
    };
    crate::log_info(&format!("exit {code} after {:.1}s", started.elapsed().as_secs_f64()));
    code
}

/// Reap whatever has exited; return the main child's status once it has.
fn reap(child: libc::pid_t) -> Option<libc::c_int> {
    let mut main = None;
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if r <= 0 {
            return main;
        }
        if r == child {
            main = Some(st);
        }
    }
}

fn kill_tree(child: libc::pid_t, am_pid1: bool) {
    unsafe {
        libc::kill(-child, libc::SIGKILL);
        if am_pid1 {
            // As PID 1 of the container's PID namespace this hits every other process,
            // including ones that escaped the process group with setsid().
            libc::kill(-1, libc::SIGKILL);
        }
    }
    if !am_pid1 {
        // Subreaper: escapees are reparented to us once their parent dies.
        for pid in own_children() {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

fn reap_all(am_pid1: bool) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if r < 0 && errno() == libc::ECHILD {
            return;
        }
        if r == 0 {
            if Instant::now() > until {
                crate::log_error("some sandboxed processes did not exit");
                return;
            }
            if !am_pid1 {
                for pid in own_children() {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn own_children() -> Vec<libc::pid_t> {
    let me = unsafe { libc::getpid() };
    let Ok(dir) = std::fs::read_dir("/proc") else { return vec![] };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter(|&pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| s.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(1)?.parse().ok()))
                == Some(me)
        })
        .collect()
}
