//! What the kernel and the container must provide for a policy. `sbx probe`
//! prints every check; `sbx run` performs the same checks before starting
//! anything and refuses to run if one fails. Nothing is skipped or downgraded.
//!
//! The functional checks fork short-lived children; they run while sbx is
//! still single-threaded.

use crate::landlock_layer::{self, abi_kernel, Probe};
use crate::log::{errno, os_err};
use crate::notify::{self, Listener, Received};
use crate::policy::{NetMode, Policy, ResolvConfMode, RESOLV_CONF};
use crate::seccomp_layer::{self, AUDIT_ARCH};
use seccompiler::sock_filter;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub struct Check {
    pub name: &'static str,
    pub outcome: Result<String, String>,
}

const CAP_SYS_PTRACE: u32 = 19;

/// Every requirement of the policy, in order.
pub fn check(p: &Policy) -> Vec<Check> {
    let mut v = vec![
        Check {
            name: "kernel",
            outcome: kernel(),
        },
        Check {
            name: "landlock",
            outcome: landlock(p),
        },
        Check {
            name: "seccomp user notification",
            outcome: seccomp_roundtrip(),
        },
        Check {
            name: "close_range",
            outcome: close_range(),
        },
        Check {
            name: "identity",
            outcome: identity(p),
        },
    ];
    // SAFETY: getpid has no preconditions.
    if unsafe { libc::getpid() } != 1 {
        v.push(Check {
            name: "child subreaper",
            outcome: subreaper(),
        });
    }
    if p.network.mode == NetMode::Egress {
        v.push(Check {
            name: "CAP_SYS_PTRACE",
            outcome: cap_sys_ptrace(),
        });
        v.push(Check {
            name: "pidfd_getfd + process_vm_readv",
            outcome: ptrace_access(p),
        });
        if let Some(d) = &p.network.dns {
            v.push(Check {
                name: "DNS proxy listen",
                outcome: crate::dns::bind(d).map(|_| format!("can listen on {} (TCP)", d.listen)),
            });
            v.push(Check {
                name: "resolv.conf",
                outcome: resolv_conf(d),
            });
        }
    }
    v
}

/// The errors of every failed check.
pub fn require(p: &Policy) -> Result<(), Vec<String>> {
    let errs: Vec<String> = check(p)
        .into_iter()
        .filter_map(|c| {
            c.outcome
                .err()
                .map(|e| format!("required capability missing: {}: {e}", c.name))
        })
        .collect();
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn kernel() -> Result<String, String> {
    // SAFETY: zeroed utsname is valid; uname fills it.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err(os_err("uname"));
    }
    // SAFETY: uname NUL-terminates release.
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok(format!("Linux {release} ({})", std::env::consts::ARCH))
}

fn landlock(p: &Policy) -> Result<String, String> {
    let pinned = p.landlock.abi;
    match landlock_layer::probe() {
        Probe::Available(v) if v >= pinned => Ok(format!("ABI v{v}; the policy pins v{pinned}")),
        Probe::Available(v) => Err(format!(
            "kernel provides ABI v{v}, the policy pins v{pinned} (Linux {})",
            abi_kernel(pinned)
        )),
        other => Err(other.to_string()),
    }
}

fn close_range() -> Result<String, String> {
    // Closing a range that holds no open fds tests availability without side effects.
    let r = unsafe { libc::syscall(libc::SYS_close_range, u32::MAX - 1, u32::MAX - 1, 0u32) };
    if r != 0 {
        return Err(os_err("close_range (Linux 5.9+)"));
    }
    Ok("available".into())
}

fn identity(p: &Policy) -> Result<String, String> {
    let (uid, gid) = (p.process.uid, p.process.gid);
    // SAFETY: id getters have no preconditions.
    let (euid, ruid, rgid) = unsafe { (libc::geteuid(), libc::getuid(), libc::getgid()) };
    if euid == 0 {
        return Ok(format!("sbx runs as root and will run the program as {uid}:{gid}"));
    }
    if ruid != uid || rgid != gid {
        return Err(format!(
            "sbx runs as {ruid}:{rgid} (not root), so it cannot switch to process.uid:gid {uid}:{gid}; \
             start sbx as root or set the policy ids to {ruid}:{rgid}"
        ));
    }
    let groups = supplementary_groups()?;
    if groups.iter().any(|&g| g != gid) {
        return Err(format!(
            "sbx runs as non-root with supplementary groups {groups:?}, which it cannot drop; \
             start it without them (e.g. setpriv --clear-groups)"
        ));
    }
    Ok(format!("sbx runs as {ruid}:{rgid}; the program shares that identity"))
}

fn supplementary_groups() -> Result<Vec<libc::gid_t>, String> {
    // SAFETY: a zero-sized query returns the count.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 {
        return Err(os_err("getgroups"));
    }
    let mut g = vec![0; n as usize];
    // SAFETY: g has room for n entries.
    let n = unsafe { libc::getgroups(n, g.as_mut_ptr()) };
    if n < 0 {
        return Err(os_err("getgroups"));
    }
    g.truncate(n as usize);
    Ok(g)
}

fn subreaper() -> Result<String, String> {
    fork_check(|| {
        // SAFETY: prctl in the forked child only.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(os_err("prctl(PR_SET_CHILD_SUBREAPER)"));
        }
        Ok(())
    })
    .map(|_| "available".into())
}

/// Run `f` in a forked child; its error text comes back over a pipe.
fn fork_check(f: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    let (r, w) = pipe()?;
    // SAFETY: sbx is single-threaded here; the child only runs `f` and exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(os_err("fork"));
    }
    if pid == 0 {
        drop(r);
        let code = match f() {
            Ok(()) => 0,
            Err(e) => {
                // SAFETY: writing a buffer we own to our pipe.
                unsafe { libc::write(w.as_raw_fd(), e.as_ptr().cast(), e.len()) };
                1
            }
        };
        // SAFETY: terminate the child without running destructors.
        unsafe { libc::_exit(code) };
    }
    drop(w);
    let msg = read_all(r);
    wait_child(pid)?;
    if msg.is_empty() {
        Ok(())
    } else {
        Err(msg)
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

fn read_all(fd: OwnedFd) -> String {
    use std::io::Read;
    let mut s = String::new();
    let mut f = std::fs::File::from(fd);
    if let Err(e) = f.read_to_string(&mut s) {
        return format!("reading the check's result: {e}");
    }
    s
}

fn wait_child(pid: libc::pid_t) -> Result<libc::c_int, String> {
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

/// A filter that turns getppid() into a notification, to exercise the whole
/// listener path: install with the same flags as the policy filter, pass the
/// listener over SCM_RIGHTS, receive, answer.
fn getppid_filter() -> Vec<sock_filter> {
    let ins = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    vec![
        ins(0x20, 0, 0, 4),
        ins(0x15, 1, 0, AUDIT_ARCH),
        ins(0x06, 0, 0, 0x8000_0000),
        ins(0x20, 0, 0, 0),
        ins(0x15, 0, 1, libc::SYS_getppid as u32),
        ins(0x06, 0, 0, libc::SECCOMP_RET_USER_NOTIF),
        ins(0x06, 0, 0, 0x7fff_0000),
    ]
}

const ROUNDTRIP_VALUE: i64 = 4242;

/// In a forked test child: send the error text to the parent and exit.
fn report_and_exit(sock: RawFd, msg: &str) -> ! {
    // SAFETY: sending a buffer we own on our socket, then terminating the child.
    unsafe {
        libc::send(sock, msg.as_ptr().cast(), msg.len(), 0);
        libc::_exit(1)
    }
}

fn seccomp_roundtrip() -> Result<String, String> {
    notify::notif_sizes()?;
    let prog = getppid_filter();
    let mut sv = [0 as RawFd; 2];
    // SAFETY: sv has room for two descriptors.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(os_err("socketpair"));
    }
    // SAFETY: both fds are new and owned by us.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    // SAFETY: single-threaded; the child makes a few syscalls and exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(os_err("fork"));
    }
    if pid == 0 {
        drop(ours);
        let s = theirs.as_raw_fd();
        // SAFETY: prctl/syscall in the child only.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            report_and_exit(s, &os_err("prctl(PR_SET_NO_NEW_PRIVS)"));
        }
        let listener = match seccomp_layer::install_with_listener(&prog) {
            Ok(fd) => fd,
            Err(e) => report_and_exit(
                s,
                &format!(
                    "{e} (needs Linux 5.19+ for WAIT_KILLABLE_RECV, and no other seccomp listener in the chain, \
                     e.g. one installed by the container runtime)"
                ),
            ),
        };
        if let Err(e) = notify::send_fd(s, listener) {
            report_and_exit(s, &e);
        }
        // SAFETY: plain syscall, answered by the parent.
        let v = unsafe { libc::syscall(libc::SYS_getppid) };
        unsafe { libc::_exit(if v == ROUNDTRIP_VALUE { 0 } else { 2 }) };
    }
    drop(theirs);
    let result = (|| {
        let fd = match notify::recv_fd(ours.as_raw_fd())? {
            Received::Fd(fd) => fd,
            Received::Text(t) => return Err(t),
            Received::Eof => return Err("the test child exited before passing its listener".into()),
        };
        let l = Listener::new(fd)?;
        let n = l.recv(5000)?.ok_or("no notification within 5s")?;
        if n.data.nr as i64 != libc::SYS_getppid {
            return Err(format!("unexpected notification for syscall {}", n.data.nr));
        }
        l.respond(n.id, 0, ROUNDTRIP_VALUE)
    })();
    if result.is_err() {
        // SAFETY: killing our own test child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let st = wait_child(pid)?;
    result?;
    if !(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0) {
        return Err(format!(
            "the test child saw the wrong syscall result (wait status {st:#x})"
        ));
    }
    Ok("listener with WAIT_KILLABLE_RECV, fd passing and replies work".into())
}

fn cap_sys_ptrace() -> Result<String, String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| format!("read /proc/self/status: {e}"))?;
    let eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .ok_or("/proc/self/status has no CapEff line")?;
    if eff & (1 << CAP_SYS_PTRACE) == 0 {
        return Err(
            "network.mode = \"egress\" needs CAP_SYS_PTRACE in sbx's effective set to read connect() arguments \
             and the socket from the sandboxed process (docker run --cap-add=SYS_PTRACE; Kubernetes: \
             securityContext.capabilities.add: [SYS_PTRACE])"
                .into(),
        );
    }
    Ok("present".into())
}

static MARKER: [u8; 8] = *b"sbx-mark";

/// Open a pidfd on a child running as the sandbox identity, take one of its
/// fds and read its memory: exactly what the egress filter does.
fn ptrace_access(p: &Policy) -> Result<String, String> {
    let (r, w) = pipe()?;
    let (uid, gid) = (p.process.uid, p.process.gid);
    // SAFETY: single-threaded; the child switches identity and blocks.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(os_err("fork"));
    }
    if pid == 0 {
        drop(w);
        // SAFETY: identity switch and blocking read in the child only.
        unsafe {
            if libc::geteuid() == 0
                && (libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0)
            {
                libc::_exit(3);
            }
            let mut b = 0u8;
            libc::read(r.as_raw_fd(), (&mut b as *mut u8).cast(), 1);
            libc::_exit(0);
        }
    }
    let theirs = r.as_raw_fd();
    let result = (|| {
        let pidfd = notify::pidfd_open_thread(pid).map_err(|e| {
            format!(
                "pidfd_open(PIDFD_THREAD): {} (needs Linux 6.9+)",
                std::io::Error::from_raw_os_error(e)
            )
        })?;
        crate::egress::pidfd_getfd(&pidfd, theirs).map_err(|e| {
            format!(
                "pidfd_getfd: {} (needs CAP_SYS_PTRACE, Yama ptrace_scope < 3, and a seccomp profile that \
                 allows pidfd_getfd)",
                std::io::Error::from_raw_os_error(e)
            )
        })?;
        let got = crate::egress::read_memory(pid, MARKER.as_ptr() as u64, MARKER.len())
            .map_err(|e| format!("process_vm_readv: {}", std::io::Error::from_raw_os_error(e)))?;
        if got != MARKER {
            return Err("process_vm_readv returned the wrong bytes".into());
        }
        Ok(())
    })();
    drop(w);
    drop(r);
    // SAFETY: killing our own test child (it may be blocked or already gone).
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let st = wait_child(pid)?;
    if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 3 {
        return Err(format!("the test child could not switch to {uid}:{gid}"));
    }
    result.map(|_| format!("works on a process running as {uid}:{gid}"))
}

fn resolv_conf(d: &crate::policy::DnsCfg) -> Result<String, String> {
    match d.resolv_conf {
        ResolvConfMode::Write => {
            let meta = std::fs::symlink_metadata(RESOLV_CONF).map_err(|e| format!("{RESOLV_CONF}: {e}"))?;
            if !meta.file_type().is_file() {
                return Err(format!(
                    "{RESOLV_CONF} is not a regular file; sbx only writes regular files"
                ));
            }
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(RESOLV_CONF)
                .map_err(|e| format!("{RESOLV_CONF} is not writable: {e}"))?;
            Ok(format!("{RESOLV_CONF} is writable and will point at {}", d.listen))
        }
        ResolvConfMode::Verify => {
            let c = std::fs::read_to_string(RESOLV_CONF).map_err(|e| format!("{RESOLV_CONF}: {e}"))?;
            crate::dns::verify_resolv_conf(d.listen.ip(), &c).map(|_| format!("{RESOLV_CONF} points at {}", d.listen))
        }
    }
}
