//! Egress filter for network.mode = "egress": decides every connect(2) made
//! in the sandbox.
//!
//! The decision is made on a private copy of the destination and carried out
//! by the supervisor itself, on the caller's socket obtained with
//! pidfd_getfd(2). The kernel never re-reads the caller's memory for an IP
//! destination, so a racing thread cannot swap the address after the check.
//!
//! Sockets of other families (AF_UNIX, ...) are left to the kernel with
//! SECCOMP_USER_NOTIF_FLAG_CONTINUE. That is safe even if another thread
//! swaps an IP socket into the same fd number in the meantime: the sandbox
//! can only hold TCP sockets (seccomp refuses every other IP socket type and
//! MSG_FASTOPEN), and Landlock denies any TCP connect made from inside the
//! sandbox, so the kernel-side connect would fail with EACCES.
//!
//! Allowed destinations: CIDR rules, addresses learned from DNS answers to
//! names matching domain rules (see dns.rs), and the DNS proxy itself.

use crate::log::{self, errno, os_err};
use crate::net::{classify, parse_sockaddr, AddrClass, AnswerScope, ConnectTarget};
use crate::notify::{comm_of, deny, describe, pidfd_open_thread, raise_fatal, Listener, Stats};
use crate::policy::{CompiledRule, EgressTarget, Policy, Violation};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, RwLock};

/// Largest sockaddr the kernel accepts (sizeof(struct sockaddr_storage)).
const MAX_SOCKADDR: u32 = 128;

#[derive(Default)]
struct Learned {
    ports: BTreeSet<u16>,
    names: BTreeSet<String>,
}

pub struct Egress {
    rules: Vec<CompiledRule>,
    dns_listen: Option<SocketAddr>,
    answer_scopes: Vec<AnswerScope>,
    learned: RwLock<HashMap<IpAddr, Learned>>,
    on_violation: Violation,
}

impl Egress {
    pub fn new(p: &Policy) -> Self {
        Egress {
            rules: p.egress_rules(),
            dns_listen: p.network.dns.as_ref().map(|d| d.listen),
            answer_scopes: p
                .network
                .dns
                .as_ref()
                .map(|d| d.answer_scopes.clone())
                .unwrap_or_default(),
            learned: RwLock::new(HashMap::new()),
            on_violation: p.seccomp.on_violation,
        }
    }

    pub fn summary(&self) -> String {
        let rules: Vec<String> = self.rules.iter().map(|r| r.to_string()).collect();
        format!(
            "egress: {} rule(s): {}{}",
            rules.len(),
            rules.join("; "),
            self.dns_listen
                .map(|d| format!("; DNS proxy on {d} (TCP)"))
                .unwrap_or_default()
        )
    }

    /// Ports allowed for a DNS name by the domain rules (empty: name not allowed).
    pub fn domain_ports(&self, labels: &[String]) -> BTreeSet<u16> {
        let mut ports = BTreeSet::new();
        for r in &self.rules {
            if let EgressTarget::Domain(d) = &r.target {
                if d.matches(labels) {
                    ports.extend(&r.ports);
                }
            }
        }
        ports
    }

    /// Add an address from an answer to an allowed DNS query. It stays allowed
    /// (for those ports) until sbx exits. Returns whether it was new, or why
    /// it was refused.
    pub fn learn(&self, ip: IpAddr, ports: &BTreeSet<u16>, name: &str) -> Result<bool, String> {
        match classify(ip) {
            AddrClass::Never(why) => Err(format!("{why} addresses are never learned from DNS")),
            AddrClass::Scope(s) if !self.answer_scopes.contains(&s) => {
                Err(format!("{s:?} addresses are not listed in network.dns.answer_scopes").to_lowercase())
            }
            AddrClass::Scope(_) => {
                let mut m = self
                    .learned
                    .write()
                    .map_err(|_| "egress allow-set lock poisoned".to_string())?;
                let e = m.entry(ip).or_default();
                let new = ports.iter().any(|p| !e.ports.contains(p));
                e.ports.extend(ports);
                e.names.insert(name.to_string());
                Ok(new)
            }
        }
    }

    /// Why the destination is allowed, or why it is not.
    fn decide(&self, ip: IpAddr, port: u16) -> Result<String, String> {
        if let Some(d) = self.dns_listen {
            if ip == d.ip() && port == d.port() {
                return Ok("sbx DNS proxy".into());
            }
        }
        for r in &self.rules {
            if let EgressTarget::Cidr(c) = &r.target {
                if c.contains(ip) && r.ports.contains(&port) {
                    return Ok(format!("rule {r}"));
                }
            }
        }
        let learned = self
            .learned
            .read()
            .map_err(|_| "egress allow-set lock poisoned".to_string())?;
        if let Some(l) = learned.get(&ip) {
            let names: Vec<&str> = l.names.iter().map(String::as_str).collect();
            if l.ports.contains(&port) {
                return Ok(format!("DNS answer for {}", names.join(", ")));
            }
            return Err(format!(
                "{ip} was resolved for {} but port {port} is not allowed for that name",
                names.join(", ")
            ));
        }
        Err("no egress rule matches (and no allowed DNS answer returned this address)".into())
    }

    pub fn handle_connect(
        self: &Arc<Self>,
        l: &Arc<Listener>,
        n: &libc::seccomp_notif,
        stats: &Arc<Stats>,
    ) -> Result<(), String> {
        let tid = n.pid as i32;
        let id = n.id;
        let fd_num = n.data.args[0] as u32 as i32;
        let addr_ptr = n.data.args[1];
        let addr_len = n.data.args[2] as u32;

        // 1. Pin the calling thread: the pidfd stays valid even if the tid is
        //    reused, and ID_VALID proves the caller was still waiting when we
        //    opened it. Every failure below answers the caller unless it is gone
        //    (internal() checks), so no thread is left blocked.
        let pidfd = match pidfd_open_thread(tid) {
            Ok(fd) => fd,
            Err(e) => {
                let e = std::io::Error::from_raw_os_error(e);
                return self.internal(l, n, &format!("pidfd_open(tid {tid}, PIDFD_THREAD): {e}"));
            }
        };
        if !l.id_valid(id) {
            return Ok(());
        }

        // 2. Our own reference to the caller's socket, from the caller's own fd table.
        let sock = match pidfd_getfd(&pidfd, fd_num) {
            Ok(s) => s,
            Err(libc::EBADF) => return l.respond(id, libc::EBADF, 0),
            Err(e) => {
                let e = std::io::Error::from_raw_os_error(e);
                return self.internal(l, n, &format!("pidfd_getfd(tid {tid}, fd {fd_num}): {e}"));
            }
        };
        let domain = match sockopt(&sock, libc::SO_DOMAIN) {
            Ok(d) => d,
            Err(libc::ENOTSOCK) => return l.respond(id, libc::ENOTSOCK, 0),
            Err(e) => {
                return self.internal(
                    l,
                    n,
                    &format!("getsockopt(SO_DOMAIN): {}", std::io::Error::from_raw_os_error(e)),
                )
            }
        };
        if domain != libc::AF_INET && domain != libc::AF_INET6 {
            return l.respond_continue(id);
        }
        let ty = sockopt(&sock, libc::SO_TYPE);
        let proto = sockopt(&sock, libc::SO_PROTOCOL);
        if ty != Ok(libc::SOCK_STREAM) || proto != Ok(libc::IPPROTO_TCP) {
            let why = format!("unexpected IP socket (type {ty:?}, protocol {proto:?}); only TCP is allowed");
            return deny(l, stats, self.on_violation, n, "connect", &why, libc::EACCES);
        }

        // 3. Private copy of the destination, read while the caller is blocked.
        if !(2..=MAX_SOCKADDR).contains(&addr_len) {
            return l.respond(id, libc::EINVAL, 0);
        }
        let bytes = match read_memory(tid, addr_ptr, addr_len as usize) {
            Ok(b) => b,
            Err(libc::ESRCH) => return self.internal(l, n, &format!("process_vm_readv(tid {tid}): no such task")),
            Err(libc::EPERM) => {
                return self.internal(
                    l,
                    n,
                    &format!("process_vm_readv(pid {tid}): permission denied (CAP_SYS_PTRACE?)"),
                )
            }
            Err(_) => return l.respond(id, libc::EFAULT, 0),
        };
        if !l.id_valid(id) {
            return Ok(());
        }
        let target = match parse_sockaddr(&bytes) {
            Ok(t) => t,
            Err(e) => return l.respond(id, e, 0),
        };
        match (domain, target) {
            (_, ConnectTarget::Unspec) => return l.respond(id, connect_fd(&sock, &bytes), 0),
            (libc::AF_INET, ConnectTarget::V4(_)) | (libc::AF_INET6, ConnectTarget::V6(_)) => {}
            _ => return l.respond(id, libc::EAFNOSUPPORT, 0),
        }
        let Some((ip, port)) = target.effective() else {
            return l.respond(id, libc::EINVAL, 0);
        };
        let what = format!("connect to {}", SocketAddr::new(ip, port));
        if ip.is_unspecified() {
            let why = "the unspecified address would reach this host; name the address explicitly";
            return deny(l, stats, self.on_violation, n, &what, why, libc::EACCES);
        }
        let why = match self.decide(ip, port) {
            Ok(why) => why,
            Err(why) => return deny(l, stats, self.on_violation, n, &what, &why, libc::EACCES),
        };
        if stats.first(format!("allowed {what} for {}", comm_of(tid))) {
            log::info(format!("egress: allowed {what} for {} ({why})", describe(tid)));
        }

        // 4. Connect the caller's socket ourselves, with our copy of the address.
        if nonblocking(&sock)? {
            return l.respond(id, connect_fd(&sock, &bytes), 0);
        }
        let l2 = Arc::clone(l);
        let spawned = std::thread::Builder::new().name("sbx-connect".into()).spawn(move || {
            let err = connect_fd(&sock, &bytes);
            if let Err(e) = l2.respond(id, err, 0) {
                raise_fatal(&format!("egress: {e}"));
            }
        });
        if let Err(e) = spawned {
            l.respond(id, libc::EAGAIN, 0)?;
            return Err(format!("egress: cannot start a thread for a blocking connect: {e}"));
        }
        Ok(())
    }

    /// An sbx-side failure while handling a connect: the call is refused and
    /// the failure logged.
    fn internal(&self, l: &Listener, n: &libc::seccomp_notif, what: &str) -> Result<(), String> {
        if !l.id_valid(n.id) {
            return Ok(()); // the caller is gone; nothing to report
        }
        log::error(format!(
            "egress: cannot decide connect for {}: {what}; refusing it",
            describe(n.pid as i32)
        ));
        l.respond(n.id, libc::EPERM, 0)
    }
}

pub fn pidfd_getfd(pidfd: &OwnedFd, fd: i32) -> Result<OwnedFd, i32> {
    if fd < 0 {
        return Err(libc::EBADF);
    }
    // SAFETY: plain syscall; the returned fd (close-on-exec) is owned below.
    let r = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if r < 0 {
        return Err(errno());
    }
    // SAFETY: r is a new fd owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) })
}

fn sockopt(fd: &OwnedFd, opt: i32) -> Result<i32, i32> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: v and len are valid for the duration of the call.
    let r = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            &mut v as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(errno());
    }
    Ok(v)
}

fn nonblocking(fd: &OwnedFd) -> Result<bool, String> {
    // SAFETY: plain fcntl on our fd.
    let fl = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if fl < 0 {
        return Err(os_err("fcntl(F_GETFL) on the sandbox's socket"));
    }
    Ok(fl & libc::O_NONBLOCK != 0)
}

/// connect(2) on our reference to the caller's socket; returns 0 or errno.
fn connect_fd(fd: &OwnedFd, addr: &[u8]) -> i32 {
    // SAFETY: addr is a live buffer of the given length.
    let r = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            addr.as_ptr() as *const libc::sockaddr,
            addr.len() as libc::socklen_t,
        )
    };
    if r == 0 {
        0
    } else {
        errno()
    }
}

/// Copy `len` bytes at `addr` out of task `tid`'s memory.
pub fn read_memory(tid: i32, addr: u64, len: usize) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: local points to len writable bytes; remote is only read by the kernel.
    let r = unsafe { libc::process_vm_readv(tid, &local, 1, &remote, 1, 0) };
    if r < 0 {
        return Err(errno());
    }
    if r as usize != len {
        return Err(libc::EFAULT);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn egress(rules: &str, scopes: &str) -> Egress {
        let src = crate::policy::tests::MINIMAL
            .replacen("mode = \"none\"", "mode = \"egress\"", 1)
            .replacen("egress = []", &format!("egress = [{rules}]"), 1)
            .replacen(
                "[seccomp]",
                &format!(
                    "[network.dns]\nlisten = \"127.0.0.53:53\"\nupstream = \"127.0.0.1:5353\"\nupstream_transport = \"tcp\"\n\
                     resolv_conf = \"verify\"\ntimeout_ms = 1000\nanswer_scopes = [{scopes}]\n[seccomp]"
                ),
                1,
            );
        Egress::new(&Policy::parse(&src, std::path::Path::new("t.toml")).unwrap())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn decisions() {
        let e = egress(
            r#"{ cidr = "10.0.0.0/8", ports = [5432] }, { domain = "*.example.com", ports = [443] }"#,
            "\"global\", \"loopback\"",
        );
        assert!(e.decide(ip("10.1.2.3"), 5432).is_ok());
        assert!(e.decide(ip("10.1.2.3"), 443).is_err());
        assert!(e.decide(ip("127.0.0.53"), 53).is_ok(), "the DNS proxy is reachable");
        assert!(e.decide(ip("127.0.0.53"), 80).is_err());
        assert!(e.decide(ip("93.184.215.14"), 443).is_err(), "not learned yet");

        let name = crate::net::parse_name("www.example.com").unwrap();
        let ports = e.domain_ports(&name);
        assert_eq!(ports.iter().copied().collect::<Vec<_>>(), vec![443]);
        assert!(e
            .domain_ports(&crate::net::parse_name("example.com").unwrap())
            .is_empty());

        assert_eq!(e.learn(ip("93.184.215.14"), &ports, "www.example.com"), Ok(true));
        assert_eq!(e.learn(ip("93.184.215.14"), &ports, "www.example.com"), Ok(false));
        assert!(e.decide(ip("93.184.215.14"), 443).is_ok());
        assert!(e.decide(ip("93.184.215.14"), 80).unwrap_err().contains("port 80"));
    }

    #[test]
    fn answers_outside_the_scopes_are_not_learned() {
        let e = egress(r#"{ domain = "a.example.com", ports = [443] }"#, "\"global\"");
        let p: BTreeSet<u16> = [443].into();
        assert!(e
            .learn(ip("169.254.169.254"), &p, "a.example.com")
            .unwrap_err()
            .contains("never"));
        assert!(e
            .learn(ip("10.0.0.1"), &p, "a.example.com")
            .unwrap_err()
            .contains("answer_scopes"));
        assert!(e.learn(ip("127.0.0.1"), &p, "a.example.com").is_err());
        assert!(e.decide(ip("10.0.0.1"), 443).is_err());
    }
}
