//! Seccomp user notification: the supervisor side of the policy filter.
//!
//! Every syscall matched by a rule in the policy filter blocks in the kernel
//! until the dispatcher thread answers it. Deny-list matches are logged and
//! answered with EPERM (or the process is killed); `connect` in egress mode is
//! handed to the egress filter. The dispatcher never answers a deny-list match
//! with SECCOMP_USER_NOTIF_FLAG_CONTINUE.
//!
//! If the supervisor dies, the listener closes and every pending or future
//! notification fails with ENOSYS, so the sandbox fails closed.

use crate::egress::Egress;
use crate::log::{self, errno, os_err, raise_fatal};
use crate::policy::Violation;
use crate::seccomp_layer::{syscall_name, Reason, RuleTable};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};

/// SECCOMP_GET_NOTIF_SIZES: the kernel's view of the notification structs.
pub fn notif_sizes() -> Result<libc::seccomp_notif_sizes, String> {
    let mut s = libc::seccomp_notif_sizes {
        seccomp_notif: 0,
        seccomp_notif_resp: 0,
        seccomp_data: 0,
    };
    // SAFETY: the kernel fills the struct we pass.
    let r = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_GET_NOTIF_SIZES, 0, &mut s as *mut _) };
    if r != 0 {
        return Err(os_err("seccomp(SECCOMP_GET_NOTIF_SIZES)"));
    }
    if (s.seccomp_notif as usize) < size_of::<libc::seccomp_notif>()
        || (s.seccomp_notif_resp as usize) < size_of::<libc::seccomp_notif_resp>()
        || (s.seccomp_data as usize) < size_of::<libc::seccomp_data>()
    {
        return Err(format!(
            "kernel seccomp notification structs are smaller than expected (notif {}, resp {}, data {})",
            s.seccomp_notif, s.seccomp_notif_resp, s.seccomp_data
        ));
    }
    Ok(s)
}

pub struct Listener {
    fd: OwnedFd,
    sizes: libc::seccomp_notif_sizes,
}

impl Listener {
    pub fn new(fd: OwnedFd) -> Result<Self, String> {
        Ok(Listener {
            fd,
            sizes: notif_sizes()?,
        })
    }

    /// Wait for the next notification. `Ok(None)` means no sandboxed process
    /// is left (or `timeout_ms` expired).
    pub fn recv(&self, timeout_ms: i32) -> Result<Option<libc::seccomp_notif>, String> {
        loop {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                return Err(os_err("poll on the seccomp listener"));
            }
            if r == 0 {
                return Ok(None);
            }
            if pfd.revents & libc::POLLIN == 0 {
                // POLLHUP: every task using the filter has exited.
                return Ok(None);
            }
            let mut buf = vec![0u8; self.sizes.seccomp_notif as usize];
            // SAFETY: buf is at least as large as the kernel's struct seccomp_notif and zeroed.
            let r = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_RECV, buf.as_mut_ptr()) };
            if r < 0 {
                match errno() {
                    // Interrupted, or the target was killed before we read the notification.
                    libc::EINTR | libc::ENOENT => continue,
                    _ => return Err(os_err("ioctl(SECCOMP_IOCTL_NOTIF_RECV)")),
                }
            }
            // SAFETY: buf holds a seccomp_notif written by the kernel.
            return Ok(Some(unsafe {
                std::ptr::read_unaligned(buf.as_ptr() as *const libc::seccomp_notif)
            }));
        }
    }

    /// True while the notifying task is still blocked waiting for our answer.
    /// Checked after opening the target's pidfd and after reading its memory,
    /// so a recycled pid can never be mistaken for the caller.
    pub fn id_valid(&self, id: u64) -> bool {
        // SAFETY: the ioctl reads one u64.
        unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
                &id as *const u64,
            ) == 0
        }
    }

    fn send(&self, resp: libc::seccomp_notif_resp) -> Result<(), String> {
        let mut buf = vec![0u8; self.sizes.seccomp_notif_resp as usize];
        // SAFETY: buf is at least size_of::<seccomp_notif_resp>() bytes.
        unsafe { std::ptr::write_unaligned(buf.as_mut_ptr() as *mut libc::seccomp_notif_resp, resp) };
        // SAFETY: buf holds a valid response the size the kernel expects.
        let r = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SEND, buf.as_mut_ptr()) };
        if r == 0 {
            return Ok(());
        }
        if errno() == libc::ENOENT {
            // The target was killed while we were deciding; nothing to answer.
            return Ok(());
        }
        Err(os_err("ioctl(SECCOMP_IOCTL_NOTIF_SEND)"))
    }

    /// Complete the syscall with `-err` (if err != 0) or the value `val`.
    pub fn respond(&self, id: u64, err: i32, val: i64) -> Result<(), String> {
        self.send(libc::seccomp_notif_resp {
            id,
            val: if err == 0 { val } else { 0 },
            error: -err,
            flags: 0,
        })
    }

    /// Let the kernel execute the syscall itself. Only used where a race on
    /// the caller's memory or fd table cannot change the outcome (see egress).
    pub fn respond_continue(&self, id: u64) -> Result<(), String> {
        self.send(libc::seccomp_notif_resp {
            id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        })
    }
}

/// `comm[pid N]` (plus `tid M` for non-leader threads) for log lines.
pub fn describe(tid: i32) -> String {
    let comm = comm_of(tid);
    match tgid_of(tid) {
        Ok(tgid) if tgid != tid => format!("{comm}[pid {tgid} tid {tid}]"),
        _ => format!("{comm}[pid {tid}]"),
    }
}

/// The task's name, which the sandbox chooses (PR_SET_NAME), escaped for logs.
pub fn comm_of(tid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{tid}/comm"))
        .map(|s| log::untrusted(s.strip_suffix('\n').unwrap_or(&s)))
        .unwrap_or_else(|_| "<exited>".into())
}

/// Thread-group id of a task, from /proc/<tid>/status.
pub fn tgid_of(tid: i32) -> Result<i32, String> {
    let status =
        std::fs::read_to_string(format!("/proc/{tid}/status")).map_err(|e| format!("read /proc/{tid}/status: {e}"))?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| format!("/proc/{tid}/status has no Tgid line"))
}

pub fn pidfd_open(pid: i32) -> Result<OwnedFd, i32> {
    pidfd_open_flags(pid, 0)
}

/// pidfd for one thread (PIDFD_THREAD, Linux 6.9+): pidfd_getfd on it reads
/// that thread's own file descriptor table.
pub fn pidfd_open_thread(tid: i32) -> Result<OwnedFd, i32> {
    pidfd_open_flags(tid, libc::O_EXCL as libc::c_uint)
}

fn pidfd_open_flags(pid: i32, flags: libc::c_uint) -> Result<OwnedFd, i32> {
    // SAFETY: plain syscall; the returned fd is owned below.
    let r = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) };
    if r < 0 {
        return Err(errno());
    }
    // SAFETY: r is a new fd owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) })
}

/// Kill a sandboxed process (all its threads) while the notified syscall is
/// still blocked, so the denied call never runs.
fn kill_process(listener: &Listener, id: u64, tid: i32) -> Result<(), String> {
    // A target that is already gone needs no killing.
    let tgid = match tgid_of(tid) {
        Ok(t) => t,
        Err(e) => return if listener.id_valid(id) { Err(e) } else { Ok(()) },
    };
    let pidfd = match pidfd_open(tgid) {
        Ok(fd) => fd,
        Err(libc::ESRCH) => return Ok(()),
        Err(e) => return Err(format!("pidfd_open({tgid}): {}", std::io::Error::from_raw_os_error(e))),
    };
    if !listener.id_valid(id) {
        return Ok(());
    }
    // SAFETY: plain syscall on our pidfd.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if r != 0 && errno() != libc::ESRCH {
        return Err(os_err(format!("pidfd_send_signal(SIGKILL) to pid {tgid}")));
    }
    Ok(())
}

/// Counts policy events so each distinct one is logged once, with a summary
/// at exit, and denied syscalls for the report.
#[derive(Default)]
pub struct Stats {
    events: Mutex<BTreeMap<String, u64>>,
    denials: Mutex<BTreeMap<String, u64>>,
}

impl Stats {
    pub fn denied(&self, syscall: String) {
        if let Ok(mut m) = self.denials.lock() {
            *m.entry(syscall).or_insert(0) += 1;
        }
    }

    /// Denials per syscall, by name.
    pub fn denials(&self) -> Vec<(String, u64)> {
        match self.denials.lock() {
            Ok(m) => m.iter().map(|(k, &n)| (k.clone(), n)).collect(),
            Err(_) => vec![],
        }
    }

    /// Record an event; returns true the first time this key is seen.
    pub fn first(&self, key: String) -> bool {
        match self.events.lock() {
            Ok(mut m) => {
                let c = m.entry(key).or_insert(0);
                *c += 1;
                *c == 1
            }
            Err(_) => true,
        }
    }

    pub fn summary(&self) -> Vec<String> {
        match self.events.lock() {
            Ok(m) => m
                .iter()
                .filter(|(_, &n)| n > 1)
                .map(|(k, n)| format!("{k} (x{n})"))
                .collect(),
            Err(_) => vec![],
        }
    }
}

pub struct Dispatcher {
    pub listener: Arc<Listener>,
    pub table: RuleTable,
    pub on_violation: Violation,
    pub egress: Option<Arc<Egress>>,
    pub stats: Arc<Stats>,
}

impl Dispatcher {
    /// The thread returns once no sandboxed process is left.
    pub fn spawn(self) -> Result<std::thread::JoinHandle<()>, String> {
        std::thread::Builder::new()
            .name("sbx-notify".into())
            .spawn(move || self.run())
            .map_err(|e| format!("cannot start the seccomp notification thread: {e}"))
    }

    fn run(self) {
        loop {
            match self.listener.recv(-1) {
                Ok(Some(n)) => {
                    if let Err(e) = self.handle(&n) {
                        raise_fatal(&format!("seccomp notification handler: {e}"));
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    raise_fatal(&e);
                    return;
                }
            }
        }
    }

    fn handle(&self, n: &libc::seccomp_notif) -> Result<(), String> {
        let nr = n.data.nr as i64;
        let args = n.data.args;
        match self.table.evaluate(nr, &args) {
            Some(rule) if rule.reason == Reason::EgressConnect => match &self.egress {
                Some(e) => e.handle_connect(&self.listener, n, &self.stats),
                None => {
                    log::error("BUG: connect notification without an egress filter; denying");
                    self.listener.respond(n.id, libc::EPERM, 0)
                }
            },
            Some(rule) => {
                let reason = rule.reason.to_string();
                deny(
                    &self.listener,
                    &self.stats,
                    self.on_violation,
                    n,
                    &syscall_name(nr),
                    &reason,
                    libc::EPERM,
                )
            }
            None => {
                log::error(format!(
                    "BUG: notification for {} from {} matched no rule; denying",
                    syscall_name(nr),
                    describe(n.pid as i32)
                ));
                self.listener.respond(n.id, libc::EPERM, 0)
            }
        }
    }
}

/// Log a denial (first occurrence per program, syscall and reason) and
/// either fail the syscall with `err` or kill the process.
pub fn deny(
    listener: &Listener,
    stats: &Stats,
    on_violation: Violation,
    n: &libc::seccomp_notif,
    what: &str,
    reason: &str,
    err: i32,
) -> Result<(), String> {
    let tid = n.pid as i32;
    stats.denied(syscall_name(n.data.nr as i64));
    let key = format!("denied {what} for {}: {reason}", comm_of(tid));
    if stats.first(key) {
        log::error(format!("seccomp: denied {what} for {}: {reason}", describe(tid)));
    }
    match on_violation {
        Violation::Errno => listener.respond(n.id, err, 0),
        Violation::Kill => {
            let who = describe(tid);
            if let Err(e) = kill_process(listener, n.id, tid) {
                // The call must not run: fail it, then tear the sandbox down.
                listener.respond(n.id, err, 0)?;
                return Err(format!(
                    "could not kill {who} as seccomp.on_violation = \"kill\" requires: {e}"
                ));
            }
            log::error(format!("seccomp: killed {who} (seccomp.on_violation = \"kill\")"));
            Ok(())
        }
    }
}

/// Control-message buffer for one fd, aligned for struct cmsghdr.
#[repr(C, align(8))]
struct CmsgBuf([u8; 64]);

/// Send one fd over a connected AF_UNIX socket with SCM_RIGHTS. Makes no
/// allocation: the sandbox child calls it after its policy filter is installed.
pub fn send_fd(sock: RawFd, fd: RawFd) -> Result<(), String> {
    let byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut cbuf = CmsgBuf([0u8; 64]);
    if space > cbuf.0.len() {
        return Err("BUG: control buffer too small".into());
    }
    // SAFETY: zeroed msghdr is valid; pointers below reference live buffers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: msg_control has room for one cmsg carrying one fd.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
    }
    // SAFETY: msg is fully initialised.
    let r = unsafe { libc::sendmsg(sock, &msg, 0) };
    if r != 1 {
        return Err(os_err("sendmsg(SCM_RIGHTS)"));
    }
    Ok(())
}

/// What arrived on the fd-passing socket.
pub enum Received {
    Fd(OwnedFd),
    /// The peer closed without sending.
    Eof,
    /// A text message instead of an fd (an error report).
    Text(String),
}

/// Receive one message; returns the fd it carried, or its text.
pub fn recv_fd(sock: RawFd) -> Result<Received, String> {
    let mut data = [0u8; 512];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: pure size computation.
    let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: zeroed msghdr is valid; pointers reference live buffers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    let n = loop {
        // SAFETY: msg describes live buffers.
        let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 && errno() == libc::EINTR {
            continue;
        }
        break n;
    };
    if n < 0 {
        return Err(os_err("recvmsg"));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err("recvmsg: control data truncated".into());
    }
    // SAFETY: walking the control buffer the kernel filled.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        if !c.is_null() && (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const RawFd);
            return Ok(Received::Fd(OwnedFd::from_raw_fd(fd)));
        }
    }
    if n == 0 {
        return Ok(Received::Eof);
    }
    Ok(Received::Text(
        String::from_utf8_lossy(&data[..n as usize]).into_owned(),
    ))
}
