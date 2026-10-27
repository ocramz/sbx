//! DNS proxy for domain egress rules.
//!
//! The sandbox resolves names over TCP through this proxy
//! (/etc/resolv.conf: `nameserver <listen>` + `options use-vc`). For each
//! query the proxy:
//!   * answers NXDOMAIN if no domain rule matches the name (and logs it);
//!   * answers NODATA for record types other than A/AAAA;
//!   * otherwise forwards the query to the single configured upstream and
//!     adds every A/AAAA address in the answer to the egress allow-set, with
//!     the ports of the matching rules (subject to network.dns.answer_scopes).
//!
//! There is one upstream and no retry: a failed or truncated upstream reply
//! is answered with SERVFAIL and logged.

use crate::egress::Egress;
use crate::log;
use crate::notify::raise_fatal;
use crate::policy::{DnsCfg, ResolvConfMode, Transport, RESOLV_CONF};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// Concurrent client connections served; more are closed and logged.
const MAX_CONNECTIONS: usize = 64;
/// A client connection idle for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

fn u16_at(m: &[u8], pos: usize) -> Result<u16, String> {
    m.get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| format!("message truncated at offset {pos}"))
}

/// Read a (possibly compressed) domain name starting at `pos`. Returns the
/// lowercase labels and the offset just after the name at its original
/// position.
pub fn read_name(m: &[u8], start: usize) -> Result<(Vec<String>, usize), String> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut total = 0usize;
    let mut jumps = 0;
    loop {
        let len = *m.get(pos).ok_or("name runs past the end of the message")? as usize;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    return Ok((labels, end.unwrap_or(pos + 1)));
                }
                let label = m
                    .get(pos + 1..pos + 1 + len)
                    .ok_or("label runs past the end of the message")?;
                total += len + 1;
                if total > 255 {
                    return Err("name longer than 255 bytes".into());
                }
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                pos += 1 + len;
            }
            0xc0 => {
                let target = (u16_at(m, pos)? & 0x3fff) as usize;
                // Pointers must point backwards, which also rules out loops.
                if target >= pos {
                    return Err(format!("compression pointer at offset {pos} does not point backwards"));
                }
                jumps += 1;
                if jumps > 64 {
                    return Err("too many compression pointers".into());
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(format!("unsupported label type {len:#x} at offset {pos}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Query {
    pub id: u16,
    pub flags: u16,
    pub labels: Vec<String>,
    pub qtype: u16,
    pub qclass: u16,
    /// End offset of the question section.
    pub end: usize,
}

impl Query {
    pub fn name(&self) -> String {
        if self.labels.is_empty() {
            ".".into()
        } else {
            self.labels.join(".")
        }
    }
}

pub fn type_name(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_AAAA => "AAAA".into(),
        5 => "CNAME".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        t => format!("TYPE{t}"),
    }
}

/// Parse a client query. Errors carry the response code to answer with.
pub fn parse_query(m: &[u8]) -> Result<Query, (u8, String)> {
    let formerr = |e: String| (RCODE_FORMERR, e);
    if m.len() < 12 {
        return Err(formerr("message shorter than a DNS header".into()));
    }
    let id = u16_at(m, 0).map_err(formerr)?;
    let flags = u16_at(m, 2).map_err(formerr)?;
    if flags & 0x8000 != 0 {
        return Err(formerr("received a response, expected a query".into()));
    }
    let opcode = (flags >> 11) & 0xf;
    if opcode != 0 {
        return Err((RCODE_NOTIMP, format!("opcode {opcode} is not supported")));
    }
    let (qd, an, ns) = (
        u16_at(m, 4).map_err(formerr)?,
        u16_at(m, 6).map_err(formerr)?,
        u16_at(m, 8).map_err(formerr)?,
    );
    if qd != 1 || an != 0 || ns != 0 {
        return Err(formerr(format!(
            "expected exactly one question and no answers (qd={qd} an={an} ns={ns})"
        )));
    }
    let (labels, pos) = read_name(m, 12).map_err(formerr)?;
    let qtype = u16_at(m, pos).map_err(formerr)?;
    let qclass = u16_at(m, pos + 2).map_err(formerr)?;
    Ok(Query {
        id,
        flags,
        labels,
        qtype,
        qclass,
        end: pos + 4,
    })
}

/// A response to `q` with no records and the given response code. If the
/// question could not be parsed, `q` is None and only the id is echoed.
pub fn build_response(query: &[u8], q: Option<&Query>, rcode: u8) -> Vec<u8> {
    let id = if query.len() >= 2 { [query[0], query[1]] } else { [0, 0] };
    let qflags = q.map(|q| q.flags).unwrap_or(0);
    // QR, opcode and RD copied from the query, RA set.
    let flags: u16 = 0x8000 | (qflags & 0x7900) | 0x0080 | rcode as u16;
    let mut r = Vec::with_capacity(512);
    r.extend_from_slice(&id);
    r.extend_from_slice(&flags.to_be_bytes());
    r.extend_from_slice(&(q.is_some() as u16).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    if let Some(q) = q {
        r.extend_from_slice(&query[12..q.end]);
    }
    r
}

/// Validate an upstream response to `q` and return the A/AAAA addresses in
/// its answer section (none for NXDOMAIN and other error codes).
pub fn parse_answer(m: &[u8], q: &Query) -> Result<Vec<IpAddr>, String> {
    if m.len() < 12 {
        return Err("response shorter than a DNS header".into());
    }
    let id = u16_at(m, 0)?;
    let flags = u16_at(m, 2)?;
    if id != q.id {
        return Err(format!("response id {id} does not match query id {}", q.id));
    }
    if flags & 0x8000 == 0 {
        return Err("upstream sent a query, not a response".into());
    }
    if flags & 0x0200 != 0 {
        return Err("response is truncated (TC bit); use upstream_transport = \"tcp\"".into());
    }
    let (qd, an) = (u16_at(m, 4)?, u16_at(m, 6)?);
    if qd != 1 {
        return Err(format!("response has {qd} questions"));
    }
    let (labels, mut pos) = read_name(m, 12)?;
    if labels != q.labels || u16_at(m, pos)? != q.qtype || u16_at(m, pos + 2)? != q.qclass {
        return Err("response question does not match the query".into());
    }
    pos += 4;
    let rcode = (flags & 0xf) as u8;
    if rcode != RCODE_NOERROR {
        return Ok(vec![]);
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        let (_, p) = read_name(m, pos)?;
        let rtype = u16_at(m, p)?;
        let rclass = u16_at(m, p + 2)?;
        let rdlen = u16_at(m, p + 8)? as usize;
        let rdata = m
            .get(p + 10..p + 10 + rdlen)
            .ok_or("record data runs past the end of the message")?;
        match (rtype, rclass, rdlen) {
            (TYPE_A, CLASS_IN, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
            (TYPE_AAAA, CLASS_IN, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                ips.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            (TYPE_A, _, _) | (TYPE_AAAA, _, _) if rclass == CLASS_IN => {
                return Err(format!("malformed {} record ({rdlen} bytes)", type_name(rtype)))
            }
            _ => {}
        }
        pos = p + 10 + rdlen;
    }
    Ok(ips)
}

/// Bind the proxy's TCP listener (before fork, while sbx is still root).
pub fn bind(cfg: &DnsCfg) -> Result<TcpListener, String> {
    TcpListener::bind(cfg.listen).map_err(|e| format!("DNS proxy: cannot listen on {} (TCP): {e}", cfg.listen))
}

pub struct Proxy {
    cfg: DnsCfg,
    egress: Arc<Egress>,
    active: AtomicUsize,
}

impl Proxy {
    pub fn spawn(listener: TcpListener, cfg: DnsCfg, egress: Arc<Egress>) -> Result<(), String> {
        let proxy = Arc::new(Proxy {
            cfg,
            egress,
            active: AtomicUsize::new(0),
        });
        std::thread::Builder::new()
            .name("sbx-dns".into())
            .spawn(move || proxy.accept_loop(listener))
            .map(|_| ())
            .map_err(|e| format!("cannot start the DNS proxy thread: {e}"))
    }

    fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    log::error(format!("dns: accept on {}: {e}", self.cfg.listen));
                    continue;
                }
            };
            if self.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                self.active.fetch_sub(1, Ordering::SeqCst);
                log::error(format!(
                    "dns: more than {MAX_CONNECTIONS} concurrent connections; closing a new one"
                ));
                continue;
            }
            let me = Arc::clone(&self);
            let spawned = std::thread::Builder::new().name("sbx-dns-conn".into()).spawn(move || {
                me.serve(stream);
                me.active.fetch_sub(1, Ordering::SeqCst);
            });
            if let Err(e) = spawned {
                raise_fatal(&format!("dns: cannot start a connection thread: {e}"));
                return;
            }
        }
    }

    fn serve(&self, mut s: TcpStream) {
        if let Err(e) = s
            .set_read_timeout(Some(IDLE_TIMEOUT))
            .and_then(|_| s.set_write_timeout(Some(IDLE_TIMEOUT)))
        {
            log::error(format!("dns: setting socket timeouts: {e}"));
            return;
        }
        loop {
            let mut len = [0u8; 2];
            match s.read_exact(&mut len) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return,
                Err(e) => {
                    log::error(format!("dns: reading from client: {e}"));
                    return;
                }
            }
            let n = u16::from_be_bytes(len) as usize;
            let mut msg = vec![0u8; n];
            if let Err(e) = s.read_exact(&mut msg) {
                log::error(format!("dns: reading a {n}-byte query: {e}"));
                return;
            }
            let Some(resp) = self.answer(&msg) else { return };
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            if let Err(e) = s.write_all(&out) {
                log::error(format!("dns: writing a response: {e}"));
                return;
            }
        }
    }

    /// The response to one query; None closes the connection.
    fn answer(&self, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < 12 {
            log::error(format!(
                "dns: dropping a {}-byte message that is not a DNS query",
                msg.len()
            ));
            return None;
        }
        let q = match parse_query(msg) {
            Ok(q) => q,
            Err((rcode, e)) => {
                log::error(format!("dns: malformed query: {e}"));
                return Some(build_response(msg, None, rcode));
            }
        };
        let (name, ty) = (q.name(), type_name(q.qtype));
        if q.qclass != CLASS_IN {
            log::error(format!("dns: refused {ty} {name}: class {} is not IN", q.qclass));
            return Some(build_response(msg, Some(&q), RCODE_REFUSED));
        }
        let ports = self.egress.domain_ports(&q.labels);
        if ports.is_empty() {
            log::error(format!(
                "dns: denied {ty} {name}: no egress domain rule matches (answered NXDOMAIN)"
            ));
            return Some(build_response(msg, Some(&q), RCODE_NXDOMAIN));
        }
        if q.qtype != TYPE_A && q.qtype != TYPE_AAAA {
            log::info(format!(
                "dns: {ty} {name}: only A and AAAA are served (answered with no records)"
            ));
            return Some(build_response(msg, Some(&q), RCODE_NOERROR));
        }
        let resp = match self.forward(msg) {
            Ok(r) => r,
            Err(e) => {
                log::error(format!(
                    "dns: {ty} {name}: upstream {}: {e} (answered SERVFAIL)",
                    self.cfg.upstream
                ));
                return Some(build_response(msg, Some(&q), RCODE_SERVFAIL));
            }
        };
        match parse_answer(&resp, &q) {
            Ok(ips) => {
                self.learn(&name, &ips, &ports);
                Some(resp)
            }
            Err(e) => {
                log::error(format!(
                    "dns: {ty} {name}: bad upstream response: {e} (answered SERVFAIL)"
                ));
                Some(build_response(msg, Some(&q), RCODE_SERVFAIL))
            }
        }
    }

    fn learn(&self, name: &str, ips: &[IpAddr], ports: &BTreeSet<u16>) {
        for &ip in ips {
            match self.egress.learn(ip, ports, name) {
                Ok(true) => log::info(format!("dns: {name} -> {ip}: allowed for ports {ports:?}")),
                Ok(false) => {}
                Err(why) => log::warn(format!("dns: {name} -> {ip} not added to the egress allow-set: {why}")),
            }
        }
    }

    fn forward(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let timeout = Duration::from_millis(self.cfg.timeout_ms);
        match self.cfg.upstream_transport {
            Transport::Tcp => forward_tcp(self.cfg.upstream, msg, timeout),
            Transport::Udp => forward_udp(self.cfg.upstream, msg, timeout),
        }
    }
}

fn forward_tcp(upstream: SocketAddr, msg: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let mut s = TcpStream::connect_timeout(&upstream, timeout).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    s.write_all(&out).map_err(|e| format!("send: {e}"))?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).map_err(|e| format!("receive: {e}"))?;
    let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut resp).map_err(|e| format!("receive: {e}"))?;
    Ok(resp)
}

fn forward_udp(upstream: SocketAddr, msg: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let local: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse()
    } else {
        "[::]:0".parse()
    }
    .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let s = UdpSocket::bind(local).map_err(|e| format!("bind: {e}"))?;
    s.connect(upstream).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    s.send(msg).map_err(|e| format!("send: {e}"))?;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = s.recv(&mut buf).map_err(|e| format!("receive: {e}"))?;
        // A connected UDP socket only receives from the upstream; skip stale ids.
        if n >= 2 && buf[..2] == msg[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

/// The resolv.conf that makes the sandbox resolve through the proxy over TCP.
pub fn resolv_conf_contents(listen: IpAddr) -> String {
    format!(
        "# Written by sbx: the sandbox resolves names through the sbx DNS proxy over TCP.\n\
         nameserver {listen}\n\
         options use-vc\n"
    )
}

/// Check that resolv.conf names only the proxy and forces TCP.
pub fn verify_resolv_conf(listen: IpAddr, contents: &str) -> Result<(), String> {
    let mut nameservers = Vec::new();
    let mut use_vc = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => nameservers.push(words.next().unwrap_or("").to_string()),
            Some("options") => use_vc |= words.any(|w| w == "use-vc"),
            _ => {}
        }
    }
    let mut problems = Vec::new();
    if nameservers != [listen.to_string()] {
        problems.push(format!(
            "its nameservers are {nameservers:?}, expected exactly [\"{listen}\"]"
        ));
    }
    if !use_vc {
        problems.push("it lacks 'options use-vc' (the sandbox may only use TCP)".to_string());
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{RESOLV_CONF} does not point the sandbox at the sbx DNS proxy: {}",
            problems.join("; ")
        ))
    }
}

/// Apply network.dns.resolv_conf: write the file, or verify it. With
/// "write", the returned guard puts the original file back when dropped.
pub fn setup_resolv_conf(cfg: &DnsCfg) -> Result<Option<ResolvConfRestore>, String> {
    let listen = cfg.listen.ip();
    let mut restore = None;
    if cfg.resolv_conf == ResolvConfMode::Write {
        let original = std::fs::read(RESOLV_CONF).map_err(|e| format!("cannot read {RESOLV_CONF}: {e}"))?;
        let written = resolv_conf_contents(listen).into_bytes();
        if let Err(e) = write_resolv_conf(&written) {
            // A failed write may have truncated the file already.
            if let Err(e) = write_resolv_conf(&original) {
                log::error(format!("restoring {RESOLV_CONF}: {e}"));
            }
            return Err(e);
        }
        restore = Some(ResolvConfRestore { original, written });
        log::info(format!("wrote {RESOLV_CONF}: nameserver {listen}, options use-vc"));
    }
    let contents = std::fs::read_to_string(RESOLV_CONF).map_err(|e| format!("cannot read {RESOLV_CONF}: {e}"))?;
    verify_resolv_conf(listen, &contents)?;
    Ok(restore)
}

/// Rewrite the file in place: container runtimes often bind-mount it, so it
/// cannot be replaced by a rename.
fn write_resolv_conf(contents: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(RESOLV_CONF)
        .and_then(|mut f| f.write_all(contents))
        .map_err(|e| format!("cannot write {RESOLV_CONF}: {e}"))
}

/// The resolv.conf sbx found, written back when sbx exits so the rest of the
/// container (e.g. a service's own server) resolves names as before. If the
/// file no longer holds what sbx wrote, someone else changed it, and it is
/// left alone.
pub struct ResolvConfRestore {
    original: Vec<u8>,
    written: Vec<u8>,
}

impl Drop for ResolvConfRestore {
    fn drop(&mut self) {
        match std::fs::read(RESOLV_CONF) {
            Ok(now) if now == self.written => match write_resolv_conf(&self.original) {
                Ok(()) => log::info(format!("restored {RESOLV_CONF}")),
                Err(e) => log::error(format!("restoring {RESOLV_CONF}: {e}")),
            },
            Ok(_) => log::warn(format!(
                "{RESOLV_CONF} was changed by someone else while sbx ran; not restoring it"
            )),
            Err(e) => log::error(format!("restoring {RESOLV_CONF}: cannot read it: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::parse_name;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m
    }

    /// A response to `q` with answers given as (type, rdata), names compressed.
    fn response(q: &[u8], rcode: u8, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = q.to_vec();
        m[2] = 0x81;
        m[3] = 0x80 | rcode;
        m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (t, rdata) in answers {
            m.extend_from_slice(&[0xc0, 12]);
            m.extend_from_slice(&t.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&60u32.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn parses_queries() {
        let m = query("API.Example.com", TYPE_AAAA);
        let q = parse_query(&m).unwrap();
        assert_eq!(q.labels, vec!["api", "example", "com"]);
        assert_eq!(q.qtype, TYPE_AAAA);
        assert_eq!(q.end, m.len());
        assert_eq!(q.name(), "api.example.com");
    }

    #[test]
    fn rejects_bad_queries() {
        assert_eq!(parse_query(&[0; 5]).unwrap_err().0, RCODE_FORMERR);
        let mut m = query("a.com", TYPE_A);
        m[2] |= 0x80; // a response
        assert_eq!(parse_query(&m).unwrap_err().0, RCODE_FORMERR);
        let mut m = query("a.com", TYPE_A);
        m[2] |= 0x28; // opcode 5 (UPDATE)
        assert_eq!(parse_query(&m).unwrap_err().0, RCODE_NOTIMP);
        let mut m = query("a.com", TYPE_A);
        m[5] = 2; // two questions
        assert_eq!(parse_query(&m).unwrap_err().0, RCODE_FORMERR);
        let mut m = query("a.com", TYPE_A);
        m.truncate(m.len() - 3);
        assert!(parse_query(&m).is_err());
    }

    #[test]
    fn names_with_bad_pointers_are_rejected() {
        // A pointer to itself.
        let mut m = vec![0u8; 12];
        m.extend_from_slice(&[0xc0, 12]);
        assert!(read_name(&m, 12).is_err());
        // A forward pointer.
        let mut m = vec![0u8; 12];
        m.extend_from_slice(&[0xc0, 20, 0, 0, 0, 0, 0, 0, 1, b'a', 0]);
        assert!(read_name(&m, 12).is_err());
        // Extended label type.
        let mut m = vec![0u8; 12];
        m.extend_from_slice(&[0x40, 0]);
        assert!(read_name(&m, 12).is_err());
        // Label running off the end.
        let mut m = vec![0u8; 12];
        m.extend_from_slice(&[5, b'a']);
        assert!(read_name(&m, 12).is_err());
        // Over-long name.
        let mut m = vec![0u8; 12];
        for _ in 0..5 {
            m.push(63);
            m.extend_from_slice(&[b'a'; 63]);
        }
        m.push(0);
        assert!(read_name(&m, 12).unwrap_err().contains("255"));
    }

    #[test]
    fn extracts_answers() {
        let qm = query("www.example.com", TYPE_A);
        let q = parse_query(&qm).unwrap();
        let cname = {
            let mut v = vec![3, b'c', b'd', b'n', 0xc0, 16];
            v.truncate(6);
            v
        };
        let r = response(
            &qm,
            RCODE_NOERROR,
            &[(5, cname), (TYPE_A, vec![93, 184, 215, 14]), (TYPE_A, vec![1, 2, 3, 4])],
        );
        assert_eq!(parse_answer(&r, &q).unwrap(), vec![ip("93.184.215.14"), ip("1.2.3.4")]);
        let nx = response(&qm, RCODE_NXDOMAIN, &[]);
        assert!(parse_answer(&nx, &q).unwrap().is_empty());
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rejects_mismatched_or_truncated_answers() {
        let qm = query("a.example.com", TYPE_A);
        let q = parse_query(&qm).unwrap();
        let mut r = response(&qm, 0, &[(TYPE_A, vec![1, 2, 3, 4])]);
        r[1] ^= 1;
        assert!(parse_answer(&r, &q).unwrap_err().contains("id"));
        let mut r = response(&qm, 0, &[(TYPE_A, vec![1, 2, 3, 4])]);
        r[2] |= 0x02;
        assert!(parse_answer(&r, &q).unwrap_err().contains("truncated"));
        let other = query("b.example.com", TYPE_A);
        let r = response(&other, 0, &[(TYPE_A, vec![1, 2, 3, 4])]);
        assert!(parse_answer(&r, &q).is_err());
        let r = response(&qm, 0, &[(TYPE_A, vec![1, 2, 3])]);
        assert!(parse_answer(&r, &q).unwrap_err().contains("malformed"));
        let mut r = response(&qm, 0, &[(TYPE_A, vec![1, 2, 3, 4])]);
        r.truncate(r.len() - 2);
        assert!(parse_answer(&r, &q).is_err());
    }

    #[test]
    fn builds_error_responses() {
        let qm = query("evil.test", TYPE_A);
        let q = parse_query(&qm).unwrap();
        let r = build_response(&qm, Some(&q), RCODE_NXDOMAIN);
        assert_eq!(&r[..2], &qm[..2]);
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[2] & 0x01, 0x01, "RD copied");
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(&r[12..], &qm[12..]);
        let again = parse_query(&{
            let mut x = r.clone();
            x[2] &= 0x7f;
            x
        })
        .unwrap();
        assert_eq!(again.labels, q.labels);
    }

    #[test]
    fn resolv_conf_checks() {
        let l = ip("127.0.0.53");
        verify_resolv_conf(l, &resolv_conf_contents(l)).unwrap();
        verify_resolv_conf(l, "search corp\nnameserver 127.0.0.53\noptions ndots:2 use-vc\n").unwrap();
        assert!(verify_resolv_conf(l, "nameserver 127.0.0.53\n")
            .unwrap_err()
            .contains("use-vc"));
        assert!(verify_resolv_conf(l, "nameserver 8.8.8.8\noptions use-vc\n")
            .unwrap_err()
            .contains("nameservers"));
        assert!(verify_resolv_conf(l, "nameserver 127.0.0.53\nnameserver 8.8.8.8\noptions use-vc\n").is_err());
    }

    #[test]
    fn name_parsing_helper_is_consistent() {
        assert_eq!(parse_name("a.b").unwrap(), vec!["a", "b"]);
    }
}
