//! Seccomp-BPF. Two stacked filters, both inherited by every descendant:
//!
//!  1. prelude (hand-written, no listener): wrong architecture -> kill;
//!     x32 ABI -> ENOSYS; clone3 -> ENOSYS (its flags live in memory where BPF
//!     cannot see them, so libc falls back to clone(2), whose flags we check).
//!  2. policy filter (seccompiler, installed with a user-notification
//!     listener): every rule in the [`RuleTable`] returns
//!     SECCOMP_RET_USER_NOTIF, so the supervisor sees each match. Deny-list
//!     matches are logged and refused; `connect` matches in egress mode go to
//!     the egress filter. Everything else is allowed.
//!
//! When filters stack the kernel picks the most restrictive verdict, so the
//! prelude's ENOSYS/KILL always win over USER_NOTIF.
//!
//! The same rule table drives the BPF program and [`RuleTable::evaluate`],
//! which the supervisor uses to name the rule behind every notification.
//! Unit tests run the compiled BPF through a small interpreter and check that
//! both agree.

use crate::log::os_err;
use crate::policy::{LandlockAbi, NetMode, Policy, SocketFamily};
use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("sbx supports x86_64 and aarch64 only");

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;

macro_rules! syscalls {
    ($($name:ident),* $(,)?) => { &[ $( (stringify!($name), libc::$name as i64) ),* ] };
}

/// Denied by default. `seccomp.allow` may lift these.
#[rustfmt::skip]
const DEFAULT_DENY: &[(&str, i64)] = syscalls![
    // debugging / cross-process memory and fd access
    SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev, SYS_pidfd_getfd, SYS_kcmp,
    SYS_process_madvise,
    // mounts and namespaces
    SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot, SYS_move_mount, SYS_open_tree,
    SYS_fsopen, SYS_fsconfig, SYS_fsmount, SYS_fspick, SYS_mount_setattr, SYS_unshare, SYS_setns,
    // large kernel attack surface
    SYS_bpf, SYS_perf_event_open, SYS_userfaultfd, SYS_io_uring_setup, SYS_io_uring_enter,
    SYS_io_uring_register, SYS_keyctl, SYS_add_key, SYS_request_key, SYS_fanotify_init,
    SYS_name_to_handle_at, SYS_open_by_handle_at,
    // system administration
    SYS_kexec_load, SYS_init_module, SYS_finit_module, SYS_delete_module,
    SYS_acct, SYS_swapon, SYS_swapoff, SYS_reboot, SYS_sethostname, SYS_setdomainname,
    SYS_syslog, SYS_quotactl, SYS_settimeofday, SYS_clock_settime, SYS_clock_adjtime,
    SYS_adjtimex, SYS_vhangup,
];

#[cfg(target_arch = "x86_64")]
const DEFAULT_DENY_ARCH: &[(&str, i64)] = syscalls![
    SYS_kexec_file_load,
    SYS_iopl,
    SYS_ioperm,
    SYS_modify_ldt,
    SYS_uselib,
    SYS__sysctl,
    SYS_ustat,
    SYS_sysfs
];
// libc's aarch64 musl bindings lack kexec_file_load; 294 is its number in
// the generic syscall table aarch64 uses.
#[cfg(target_arch = "aarch64")]
const DEFAULT_DENY_ARCH: &[(&str, i64)] = &[("SYS_kexec_file_load", 294)];

/// Extra names accepted in `seccomp.deny`.
#[rustfmt::skip]
const EXTRA_NAMES: &[(&str, i64)] = syscalls![
    SYS_execveat, SYS_clone, SYS_kill, SYS_tkill, SYS_tgkill, SYS_socket,
    SYS_socketpair, SYS_connect, SYS_bind, SYS_listen, SYS_accept, SYS_accept4, SYS_sendto,
    SYS_sendmmsg, SYS_recvfrom, SYS_recvmsg, SYS_memfd_create, SYS_mprotect,
    SYS_pkey_mprotect, SYS_prctl, SYS_seccomp, SYS_inotify_init1, SYS_fanotify_mark,
    SYS_sched_setaffinity, SYS_setpriority, SYS_mknodat, SYS_symlinkat, SYS_linkat,
    SYS_mbind, SYS_migrate_pages, SYS_move_pages, SYS_set_mempolicy, SYS_personality,
    SYS_ioctl, SYS_pidfd_open, SYS_pidfd_send_signal, SYS_landlock_create_ruleset,
];
#[cfg(target_arch = "x86_64")]
const EXTRA_NAMES_ARCH: &[(&str, i64)] = syscalls![SYS_fork, SYS_vfork, SYS_open, SYS_mknod];
#[cfg(target_arch = "aarch64")]
const EXTRA_NAMES_ARCH: &[(&str, i64)] = &[];

/// Syscalls sbx itself makes after the policy filter is installed (to hand
/// the listener to the supervisor and start the program), so they can never
/// be denied by policy.
pub const RESERVED: &[&str] = &["execve", "sendmsg"];

/// Names of every syscall a rule may refer to, for log messages.
const OTHER_NAMES: &[(&str, i64)] = syscalls![SYS_execve, SYS_sendmsg, SYS_setsockopt];

fn strip(n: &str) -> &str {
    n.strip_prefix("SYS_").unwrap_or(n)
}

/// Syscall number for a name accepted in `seccomp.deny`.
pub fn lookup(name: &str) -> Option<i64> {
    DEFAULT_DENY
        .iter()
        .chain(DEFAULT_DENY_ARCH)
        .chain(EXTRA_NAMES)
        .chain(EXTRA_NAMES_ARCH)
        .find(|(n, _)| strip(n) == name)
        .map(|(_, nr)| *nr)
}

pub fn is_default_denied(name: &str) -> bool {
    DEFAULT_DENY
        .iter()
        .chain(DEFAULT_DENY_ARCH)
        .any(|(n, _)| strip(n) == name)
}

pub fn syscall_name(nr: i64) -> String {
    DEFAULT_DENY
        .iter()
        .chain(DEFAULT_DENY_ARCH)
        .chain(EXTRA_NAMES)
        .chain(EXTRA_NAMES_ARCH)
        .chain(OTHER_NAMES)
        .find(|(_, n)| *n == nr)
        .map(|(n, _)| strip(n).to_string())
        .unwrap_or_else(|| format!("syscall {nr}"))
}

// Socket options that change where packets go (source routing). uapi values.
const IP_OPTIONS: u64 = 4;
const IPV6_2292RTHDR: u64 = 5;
const IPV6_2292PKTOPTIONS: u64 = 6;
const IPV6_RTHDR: u64 = 57;
const SOCK_TYPE_MASK: u64 = 0xf;

/// Why a rule matched; the supervisor logs this for every notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    DenyList {
        source: &'static str,
    },
    NamespaceClone,
    SubprocessesDisabled,
    SocketFamily,
    EgressSocketType,
    FastOpen,
    SourceRouting,
    TerminalInjection,
    Personality,
    BindWithoutLandlock,
    /// Not a denial: the egress filter decides.
    EgressConnect,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::DenyList { source } => write!(f, "denied by {source}"),
            Reason::NamespaceClone => write!(f, "creating namespaces is not allowed"),
            Reason::SubprocessesDisabled => write!(f, "process.subprocesses = false: only threads may be created"),
            Reason::SocketFamily => write!(f, "address family not in seccomp.socket_families"),
            Reason::EgressSocketType => write!(
                f,
                "network.mode = \"egress\" allows TCP sockets only (no UDP, raw, ICMP, SCTP or MPTCP); \
                 DNS works over TCP with 'options use-vc' in resolv.conf"
            ),
            Reason::FastOpen => write!(f, "TCP Fast Open (MSG_FASTOPEN) would bypass connect filtering"),
            Reason::SourceRouting => write!(f, "IP source routing options would change the destination"),
            Reason::TerminalInjection => write!(f, "terminal input injection (TIOCSTI/TIOCLINUX)"),
            Reason::Personality => write!(f, "personality flag outside the allowed set"),
            Reason::BindWithoutLandlock => write!(
                f,
                "bind and listen are denied in egress mode without Landlock (landlock.abi = \"off\")"
            ),
            Reason::EgressConnect => write!(f, "egress filter"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    /// (arg & mask) == value
    MaskedEq(u64),
}

/// A comparison on one syscall argument. `dword` compares the low 32 bits
/// only, which is correct for int-typed arguments: the kernel ignores the
/// upper half of the register for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cond {
    pub arg: u8,
    pub dword: bool,
    pub op: Op,
    pub value: u64,
}

impl Cond {
    fn int(arg: u8, op: Op, value: u64) -> Self {
        Cond {
            arg,
            dword: true,
            op,
            value,
        }
    }

    fn holds(&self, args: &[u64; 6]) -> bool {
        let a = args[self.arg as usize];
        let a = if self.dword { a & 0xffff_ffff } else { a };
        match self.op {
            Op::Eq => a == self.value,
            Op::Ne => a != self.value,
            Op::MaskedEq(m) => a & m == self.value,
        }
    }

    fn to_seccompiler(self) -> Result<SeccompCondition, String> {
        let len = if self.dword {
            SeccompCmpArgLen::Dword
        } else {
            SeccompCmpArgLen::Qword
        };
        let op = match self.op {
            Op::Eq => SeccompCmpOp::Eq,
            Op::Ne => SeccompCmpOp::Ne,
            Op::MaskedEq(m) => SeccompCmpOp::MaskedEq(m),
        };
        SeccompCondition::new(self.arg, len, op, self.value).map_err(|e| format!("seccomp condition {self:?}: {e}"))
    }
}

/// Matches when every condition holds (an empty list matches always).
#[derive(Debug, Clone)]
pub struct Rule {
    pub nr: i64,
    pub conds: Vec<Cond>,
    pub reason: Reason,
}

#[derive(Debug, Clone, Default)]
pub struct RuleTable {
    pub rules: Vec<Rule>,
}

impl RuleTable {
    fn add(&mut self, nr: i64, conds: Vec<Cond>, reason: Reason) {
        self.rules.push(Rule { nr, conds, reason });
    }

    /// The first rule matching this syscall, in table order. Denials come
    /// before the egress `connect` rule, so an explicit deny wins.
    pub fn evaluate(&self, nr: i64, args: &[u64; 6]) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|r| r.nr == nr && r.conds.iter().all(|c| c.holds(args)))
    }

    pub fn syscalls(&self) -> BTreeSet<i64> {
        self.rules.iter().map(|r| r.nr).collect()
    }
}

/// The rule table for a policy.
pub fn build_table(p: &Policy) -> Result<RuleTable, String> {
    let cfg = &p.seccomp;
    let mut t = RuleTable::default();
    let egress = p.network.mode == NetMode::Egress;

    for &(name, nr) in DEFAULT_DENY.iter().chain(DEFAULT_DENY_ARCH) {
        if !cfg.allow.iter().any(|a| a == strip(name)) {
            t.add(
                nr,
                vec![],
                Reason::DenyList {
                    source: "the built-in deny-list",
                },
            );
        }
    }
    for name in &cfg.deny {
        let nr = lookup(name).ok_or_else(|| format!("seccomp.deny: unknown syscall {name:?}"))?;
        t.add(nr, vec![], Reason::DenyList { source: "seccomp.deny" });
    }

    // clone(2): no new namespaces (user namespaces are a big kernel attack surface).
    for f in [
        libc::CLONE_NEWNS,
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
    ] {
        let f = f as u64;
        t.add(
            libc::SYS_clone,
            vec![Cond::int(0, Op::MaskedEq(f), f)],
            Reason::NamespaceClone,
        );
    }
    if !p.process.subprocesses {
        let thread = libc::CLONE_THREAD as u64;
        t.add(
            libc::SYS_clone,
            vec![Cond::int(0, Op::MaskedEq(thread), 0)],
            Reason::SubprocessesDisabled,
        );
        #[cfg(target_arch = "x86_64")]
        {
            t.add(libc::SYS_fork, vec![], Reason::SubprocessesDisabled);
            t.add(libc::SYS_vfork, vec![], Reason::SubprocessesDisabled);
        }
    }

    // socket(2)/socketpair(2): address families.
    let families: BTreeSet<u64> = cfg.socket_families.iter().map(|f| f.af() as u64).collect();
    for nr in [libc::SYS_socket, libc::SYS_socketpair] {
        t.add(
            nr,
            families.iter().map(|&f| Cond::int(0, Op::Ne, f)).collect(),
            Reason::SocketFamily,
        );
    }

    if egress {
        // Only plain TCP: every other socket type, and stream sockets with a
        // protocol other than TCP (SCTP, MPTCP), are refused.
        for fam in [SocketFamily::Inet, SocketFamily::Inet6] {
            if !cfg.socket_families.contains(&fam) {
                continue;
            }
            let af = fam.af() as u64;
            for ty in (0..=SOCK_TYPE_MASK).filter(|&ty| ty != libc::SOCK_STREAM as u64) {
                t.add(
                    libc::SYS_socket,
                    vec![Cond::int(0, Op::Eq, af), Cond::int(1, Op::MaskedEq(SOCK_TYPE_MASK), ty)],
                    Reason::EgressSocketType,
                );
            }
            t.add(
                libc::SYS_socket,
                vec![
                    Cond::int(0, Op::Eq, af),
                    Cond::int(1, Op::MaskedEq(SOCK_TYPE_MASK), libc::SOCK_STREAM as u64),
                    Cond::int(2, Op::Ne, 0),
                    Cond::int(2, Op::Ne, libc::IPPROTO_TCP as u64),
                ],
                Reason::EgressSocketType,
            );
        }
        // TCP Fast Open connects from inside sendto/sendmsg, outside connect().
        let fo = libc::MSG_FASTOPEN as u64;
        t.add(
            libc::SYS_sendto,
            vec![Cond::int(3, Op::MaskedEq(fo), fo)],
            Reason::FastOpen,
        );
        t.add(
            libc::SYS_sendmsg,
            vec![Cond::int(2, Op::MaskedEq(fo), fo)],
            Reason::FastOpen,
        );
        t.add(
            libc::SYS_sendmmsg,
            vec![Cond::int(3, Op::MaskedEq(fo), fo)],
            Reason::FastOpen,
        );
        // Source routing: the first hop becomes the real destination.
        for (level, opt) in [
            (libc::IPPROTO_IP as u64, IP_OPTIONS),
            (libc::IPPROTO_IPV6 as u64, IPV6_RTHDR),
            (libc::IPPROTO_IPV6 as u64, IPV6_2292RTHDR),
            (libc::IPPROTO_IPV6 as u64, IPV6_2292PKTOPTIONS),
        ] {
            t.add(
                libc::SYS_setsockopt,
                vec![Cond::int(1, Op::Eq, level), Cond::int(2, Op::Eq, opt)],
                Reason::SourceRouting,
            );
        }
        // Landlock limits TCP binds to network.bind_tcp; without it, no binds
        // at all. listen() is included because it binds an unbound socket.
        if p.landlock.abi == LandlockAbi::Off {
            for nr in [libc::SYS_bind, libc::SYS_listen] {
                t.add(nr, vec![], Reason::BindWithoutLandlock);
            }
        }
    }

    // ioctl(2): no injecting keystrokes into a terminal outside the sandbox.
    for req in [ioctl_request(libc::TIOCSTI), ioctl_request(libc::TIOCLINUX)] {
        t.add(
            libc::SYS_ioctl,
            vec![Cond::int(1, Op::Eq, req)],
            Reason::TerminalInjection,
        );
    }
    // personality(2): only the values runtimes actually use (no ADDR_NO_RANDOMIZE etc.).
    t.add(
        libc::SYS_personality,
        [0x0u64, 0x8, 0x20000, 0x20008, 0xffff_ffff]
            .iter()
            .map(|&v| Cond::int(0, Op::Ne, v))
            .collect(),
        Reason::Personality,
    );

    if egress {
        // Last, so that an explicit deny of connect wins in `evaluate`.
        t.add(libc::SYS_connect, vec![], Reason::EgressConnect);
    }
    Ok(t)
}

/// ioctl request numbers are `c_ulong` with glibc and `c_int` with musl.
#[allow(clippy::unnecessary_cast)]
fn ioctl_request(r: libc::Ioctl) -> u64 {
    r as u64
}

/// Marker used for the seccompiler match action before it is rewritten into
/// SECCOMP_RET_USER_NOTIF (which seccompiler cannot emit).
const NOTIFY_MARKER: u32 = 0xa5b;
const BPF_RET_K: u16 = 0x06;

/// Compile the rule table: every match returns USER_NOTIF, everything else is allowed.
pub fn compile(t: &RuleTable) -> Result<BpfProgram, String> {
    let mut map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let unconditional: BTreeSet<i64> = t.rules.iter().filter(|r| r.conds.is_empty()).map(|r| r.nr).collect();
    for r in &t.rules {
        let chain = map.entry(r.nr).or_default();
        if unconditional.contains(&r.nr) {
            continue; // an empty chain matches unconditionally
        }
        let conds = r
            .conds
            .iter()
            .map(|c| c.to_seccompiler())
            .collect::<Result<Vec<_>, _>>()?;
        chain.push(SeccompRule::new(conds).map_err(|e| format!("seccomp rule for {}: {e}", syscall_name(r.nr)))?);
    }
    let marker = SeccompAction::Trace(NOTIFY_MARKER);
    let filter = SeccompFilter::new(map, SeccompAction::Allow, marker.clone(), ARCH)
        .map_err(|e| format!("seccomp filter: {e}"))?;
    let mut prog: BpfProgram = filter.try_into().map_err(|e| format!("seccomp filter: {e:?}"))?;
    let marker_k = u32::from(marker);
    let mut rewritten = 0;
    for ins in prog.iter_mut() {
        if ins.code == BPF_RET_K && ins.k == marker_k {
            ins.k = libc::SECCOMP_RET_USER_NOTIF;
            rewritten += 1;
        }
    }
    if rewritten == 0 && !t.rules.is_empty() {
        return Err("seccomp filter: no match action found to rewrite into USER_NOTIF".into());
    }
    if prog.iter().any(|i| i.k == marker_k) {
        return Err("seccomp filter: marker value left in the program after rewriting".into());
    }
    Ok(prog)
}

pub fn prelude() -> BpfProgram {
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    #[cfg(target_arch = "x86_64")]
    const JGE_K: u16 = 0x35;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO_ENOSYS: u32 = 0x0005_0000 | libc::ENOSYS as u32;
    const RET_ALLOW: u32 = 0x7fff_0000;
    let ins = |code, jt, jf, k| sock_filter { code, jt, jf, k };

    let mut p = vec![
        ins(LD_W_ABS, 0, 0, 4), // seccomp_data.arch
        ins(JEQ_K, 1, 0, AUDIT_ARCH),
        ins(BPF_RET_K, 0, 0, RET_KILL_PROCESS),
        ins(LD_W_ABS, 0, 0, 0), // seccomp_data.nr
        ins(JEQ_K, 0, 1, libc::SYS_clone3 as u32),
        ins(BPF_RET_K, 0, 0, RET_ERRNO_ENOSYS),
    ];
    #[cfg(target_arch = "x86_64")]
    p.extend([ins(JGE_K, 0, 1, 0x4000_0000), ins(BPF_RET_K, 0, 0, RET_ERRNO_ENOSYS)]);
    p.push(ins(BPF_RET_K, 0, 0, RET_ALLOW));
    p
}

/// Compiled filters plus the table the supervisor evaluates notifications with.
pub struct Programs {
    pub prelude: BpfProgram,
    pub main: BpfProgram,
    pub table: RuleTable,
    pub summary: String,
}

pub fn build(p: &Policy) -> Result<Programs, String> {
    let table = build_table(p)?;
    let main = compile(&table)?;
    let fams: Vec<String> = p
        .seccomp
        .socket_families
        .iter()
        .map(|f| format!("{f:?}").to_lowercase())
        .collect();
    let summary = format!(
        "seccomp: {} rules on {} syscalls ({} BPF instructions), on_violation={}, socket families [{}]{}",
        table.rules.len(),
        table.syscalls().len(),
        main.len(),
        format!("{:?}", p.seccomp.on_violation).to_lowercase(),
        fams.join(", "),
        if p.network.mode == NetMode::Egress {
            ", connect() filtered by the egress allow-list"
        } else {
            ""
        }
    );
    Ok(Programs {
        prelude: prelude(),
        main,
        table,
        summary,
    })
}

fn install(prog: &BpfProgram, flags: libc::c_ulong, what: &str) -> Result<libc::c_long, String> {
    let len = u16::try_from(prog.len()).map_err(|_| format!("{what}: program has {} instructions", prog.len()))?;
    let fprog = libc::sock_fprog {
        len,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: fprog points to a live, correctly sized instruction array.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &fprog as *const libc::sock_fprog,
        )
    };
    if r < 0 {
        Err(os_err(format!("seccomp(SECCOMP_SET_MODE_FILTER) for the {what}")))
    } else {
        Ok(r)
    }
}

pub fn install_prelude(prog: &BpfProgram) -> Result<(), String> {
    install(prog, 0, "prelude filter").map(|_| ())
}

/// Install the policy filter with a user-notification listener and return
/// the listener fd (close-on-exec). WAIT_KILLABLE_RECV keeps a notified
/// syscall from being interrupted by non-fatal signals once the supervisor
/// has picked it up, so emulated connects cannot be half-applied.
pub fn install_with_listener(prog: &BpfProgram) -> Result<i32, String> {
    let flags = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER | libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    install(prog, flags, "policy filter").map(|fd| fd as i32)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::policy::Policy;

    /// Minimal classic-BPF interpreter for the instructions seccompiler and
    /// the prelude emit. Panics on anything else so gaps are noticed.
    pub fn run_bpf(prog: &[sock_filter], nr: i64, arch: u32, args: &[u64; 6]) -> u32 {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&(nr as i32).to_ne_bytes());
        data.extend_from_slice(&arch.to_ne_bytes());
        data.extend_from_slice(&0u64.to_ne_bytes());
        for a in args {
            data.extend_from_slice(&a.to_ne_bytes());
        }
        let (mut a, mut x): (u32, u32) = (0, 0);
        let mut mem = [0u32; 16];
        let mut pc = 0usize;
        loop {
            let i = &prog[pc];
            pc += 1;
            let k = i.k;
            match i.code {
                0x20 => a = u32::from_ne_bytes(data[k as usize..k as usize + 4].try_into().unwrap()),
                0x00 => a = k,
                0x01 => x = k,
                0x60 => a = mem[k as usize],
                0x61 => x = mem[k as usize],
                0x02 => mem[k as usize] = a,
                0x03 => mem[k as usize] = x,
                0x04 => a = a.wrapping_add(k),
                0x14 => a = a.wrapping_sub(k),
                0x54 => a &= k,
                0x44 => a |= k,
                0x5c => a &= x,
                0x07 => x = a,
                0x87 => a = x,
                0x05 => pc += k as usize,
                0x15 | 0x25 | 0x35 | 0x45 | 0x1d | 0x2d | 0x3d | 0x4d => {
                    let rhs = if i.code & 0x08 != 0 { x } else { k };
                    let taken = match i.code & 0xf0 {
                        0x10 => a == rhs,
                        0x20 => a > rhs,
                        0x30 => a >= rhs,
                        0x40 => a & rhs != 0,
                        _ => unreachable!(),
                    };
                    pc += if taken { i.jt as usize } else { i.jf as usize };
                }
                0x06 => return k,
                0x16 => return a,
                c => panic!("unsupported BPF opcode {c:#x} at {}", pc - 1),
            }
        }
    }

    const NOTIF: u32 = libc::SECCOMP_RET_USER_NOTIF;
    const ALLOW: u32 = 0x7fff_0000;

    fn policy(mode: &str, families: &str, subprocesses: bool) -> Policy {
        let src = crate::policy::tests::MINIMAL
            .replacen("mode = \"none\"", &format!("mode = \"{mode}\""), 1)
            .replacen(
                "socket_families = [\"unix\"]",
                &format!("socket_families = [{families}]"),
                1,
            )
            .replacen("subprocesses = true", &format!("subprocesses = {subprocesses}"), 1)
            .replacen("deny = []", "deny = [\"memfd_create\"]", 1)
            .replacen("allow = []", "allow = [\"ptrace\"]", 1);
        Policy::parse(&src, std::path::Path::new("t.toml")).unwrap()
    }

    /// Interesting argument values for each syscall the rules look at.
    fn samples() -> Vec<(i64, [u64; 6])> {
        let hi = 0xdead_beef_0000_0000u64; // garbage in the upper half of int arguments
        let mut v = vec![];
        let fams = [
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
            libc::AF_PACKET,
            libc::AF_VSOCK,
            1234,
        ];
        for &f in &fams {
            for ty in [
                libc::SOCK_STREAM,
                libc::SOCK_DGRAM,
                libc::SOCK_RAW,
                libc::SOCK_SEQPACKET,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                7,
            ] {
                for proto in [
                    0,
                    libc::IPPROTO_TCP,
                    libc::IPPROTO_UDP,
                    262, /* MPTCP */
                    libc::IPPROTO_SCTP,
                ] {
                    for upper in [0, hi] {
                        v.push((
                            libc::SYS_socket,
                            [f as u64 | upper, ty as u64 | upper, proto as u64 | upper, 0, 0, 0],
                        ));
                    }
                }
            }
            v.push((libc::SYS_socketpair, [f as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]));
        }
        let cl = |f: i32| (libc::SYS_clone, [f as u64, 0, 0, 0, 0, 0]);
        v.push(cl(libc::SIGCHLD));
        v.push(cl(libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM));
        v.push(cl(libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD));
        v.push(cl(libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD));
        v.push(cl(libc::CLONE_NEWUSER));
        v.push(cl(libc::CLONE_NEWNET | libc::SIGCHLD));
        for flags in [
            0u64,
            libc::MSG_NOSIGNAL as u64,
            libc::MSG_FASTOPEN as u64,
            (libc::MSG_FASTOPEN | libc::MSG_NOSIGNAL) as u64,
        ] {
            v.push((libc::SYS_sendto, [3, 0, 10, flags, 0, 0]));
            v.push((libc::SYS_sendto, [3, 0, 10, flags | hi, 1, 16]));
            v.push((libc::SYS_sendmsg, [3, 0, flags, 0, 0, 0]));
            v.push((libc::SYS_sendmmsg, [3, 0, 2, flags, 0, 0]));
        }
        for (level, opt) in [
            (0u64, 4u64),
            (0, 1),
            (41, 57),
            (41, 5),
            (41, 6),
            (41, 26),
            (6, 1),
            (1, 25),
        ] {
            v.push((libc::SYS_setsockopt, [3, level, opt, 0, 4, 0]));
        }
        for req in [
            ioctl_request(libc::TIOCSTI),
            ioctl_request(libc::TIOCLINUX),
            ioctl_request(libc::TIOCGWINSZ),
        ] {
            v.push((libc::SYS_ioctl, [0, req, 0, 0, 0, 0]));
        }
        for pers in [0u64, 8, 0x20000, 0x0040000, 0xffff_ffff] {
            v.push((libc::SYS_personality, [pers, 0, 0, 0, 0, 0]));
        }
        for nr in [
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_memfd_create,
            libc::SYS_unshare,
            libc::SYS_execve,
        ] {
            v.push((nr, [0; 6]));
        }
        #[cfg(target_arch = "x86_64")]
        for nr in [libc::SYS_fork, libc::SYS_vfork] {
            v.push((nr, [0; 6]));
        }
        v
    }

    fn check_agreement(p: &Policy) {
        let t = build_table(p).unwrap();
        let prog = compile(&t).unwrap();
        for (nr, args) in samples() {
            let bpf = run_bpf(&prog, nr, AUDIT_ARCH, &args);
            let eval = t.evaluate(nr, &args);
            let want = if eval.is_some() { NOTIF } else { ALLOW };
            assert_eq!(
                bpf,
                want,
                "nr {} args {args:x?}: bpf {bpf:#x} vs evaluator {eval:?}",
                syscall_name(nr)
            );
        }
    }

    #[test]
    fn bpf_matches_evaluator() {
        check_agreement(&policy("none", "\"unix\"", true));
        check_agreement(&policy("none", "\"unix\", \"netlink\"", false));
        check_agreement(&policy("egress", "\"unix\", \"inet\", \"inet6\"", true));
        check_agreement(&policy("egress", "\"unix\", \"inet\"", false));
        check_agreement(&policy("unrestricted", "\"unix\", \"inet\", \"inet6\"", true));
        check_agreement(&without_landlock(policy(
            "egress",
            "\"unix\", \"inet\", \"inet6\"",
            true,
        )));
        check_agreement(&without_landlock(policy("none", "\"unix\"", true)));
    }

    fn without_landlock(mut p: Policy) -> Policy {
        p.landlock.abi = LandlockAbi::Off;
        p
    }

    #[test]
    fn bind_and_listen_without_landlock() {
        let args = [3, 0, 16, 0, 0, 0];
        let off = without_landlock(policy("egress", "\"unix\", \"inet\"", true));
        for nr in [libc::SYS_bind, libc::SYS_listen] {
            assert_eq!(
                reason(&off, nr, args),
                Some(Reason::BindWithoutLandlock),
                "{}",
                syscall_name(nr)
            );
            let on = policy("egress", "\"unix\", \"inet\"", true);
            assert_eq!(reason(&on, nr, args), None, "Landlock limits binds to bind_tcp");
            let none = without_landlock(policy("none", "\"unix\"", true));
            assert_eq!(reason(&none, nr, args), None, "mode none has no IP sockets to bind");
        }
        assert_eq!(reason(&off, libc::SYS_connect, args), Some(Reason::EgressConnect));
    }

    fn reason(p: &Policy, nr: i64, args: [u64; 6]) -> Option<Reason> {
        build_table(p).unwrap().evaluate(nr, &args).map(|r| r.reason.clone())
    }

    #[test]
    fn egress_rules_in_detail() {
        let p = policy("egress", "\"unix\", \"inet\", \"inet6\"", true);
        let inet = libc::AF_INET as u64;
        let tcp = |ty: i32, proto: i32| reason(&p, libc::SYS_socket, [inet, ty as u64, proto as u64, 0, 0, 0]);
        assert_eq!(tcp(libc::SOCK_STREAM, 0), None);
        assert_eq!(tcp(libc::SOCK_STREAM | libc::SOCK_CLOEXEC, libc::IPPROTO_TCP), None);
        assert_eq!(tcp(libc::SOCK_DGRAM, 0), Some(Reason::EgressSocketType));
        assert_eq!(tcp(libc::SOCK_STREAM, 262), Some(Reason::EgressSocketType));
        assert_eq!(tcp(libc::SOCK_RAW, 1), Some(Reason::EgressSocketType));
        assert_eq!(
            reason(&p, libc::SYS_socket, [libc::AF_PACKET as u64, 3, 0, 0, 0, 0]),
            Some(Reason::SocketFamily)
        );
        assert_eq!(
            reason(&p, libc::SYS_connect, [3, 0, 16, 0, 0, 0]),
            Some(Reason::EgressConnect)
        );
        assert_eq!(
            reason(&p, libc::SYS_sendto, [3, 0, 1, libc::MSG_FASTOPEN as u64, 1, 16]),
            Some(Reason::FastOpen)
        );
        assert_eq!(reason(&p, libc::SYS_sendto, [3, 0, 1, 0, 0, 0]), None);
        assert_eq!(
            reason(&p, libc::SYS_setsockopt, [3, 0, 4, 0, 40, 0]),
            Some(Reason::SourceRouting)
        );
        assert_eq!(
            reason(&p, libc::SYS_setsockopt, [3, 41, 57, 0, 8, 0]),
            Some(Reason::SourceRouting)
        );
        assert_eq!(reason(&p, libc::SYS_setsockopt, [3, 6, 1, 0, 4, 0]), None);
    }

    #[test]
    fn deny_and_allow_lists() {
        let p = policy("none", "\"unix\"", true);
        assert!(matches!(
            reason(&p, libc::SYS_memfd_create, [0; 6]),
            Some(Reason::DenyList { source: "seccomp.deny" })
        ));
        assert_eq!(
            reason(&p, libc::SYS_ptrace, [0; 6]),
            None,
            "ptrace was lifted by seccomp.allow"
        );
        assert!(matches!(
            reason(&p, libc::SYS_bpf, [0; 6]),
            Some(Reason::DenyList { .. })
        ));
        assert_eq!(
            reason(&p, libc::SYS_socket, [libc::AF_INET as u64, 1, 0, 0, 0, 0]),
            Some(Reason::SocketFamily)
        );
        assert_eq!(
            reason(&p, libc::SYS_connect, [3, 0, 16, 0, 0, 0]),
            None,
            "connect is not filtered outside egress mode"
        );
        let thread = (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64;
        assert_eq!(reason(&p, libc::SYS_clone, [thread, 0, 0, 0, 0, 0]), None);
        let userns = (libc::CLONE_NEWUSER | libc::SIGCHLD) as u64;
        assert_eq!(
            reason(&p, libc::SYS_clone, [userns, 0, 0, 0, 0, 0]),
            Some(Reason::NamespaceClone)
        );
    }

    #[test]
    fn explicit_deny_of_connect_wins_over_egress() {
        let mut p = policy("egress", "\"unix\", \"inet\"", true);
        p.seccomp.deny.push("connect".into());
        assert!(matches!(
            reason(&p, libc::SYS_connect, [3, 0, 16, 0, 0, 0]),
            Some(Reason::DenyList { .. })
        ));
    }

    #[test]
    fn prelude_verdicts() {
        let p = prelude();
        assert_eq!(run_bpf(&p, libc::SYS_read, AUDIT_ARCH, &[0; 6]), ALLOW);
        assert_eq!(
            run_bpf(&p, libc::SYS_clone3, AUDIT_ARCH, &[0; 6]),
            0x0005_0000 | libc::ENOSYS as u32
        );
        assert_eq!(run_bpf(&p, libc::SYS_read, 0x4000_0003, &[0; 6]), 0x8000_0000);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            run_bpf(&p, 0x4000_0000, AUDIT_ARCH, &[0; 6]),
            0x0005_0000 | libc::ENOSYS as u32
        );
    }

    #[test]
    fn names() {
        assert_eq!(lookup("ptrace"), Some(libc::SYS_ptrace));
        assert_eq!(lookup("read"), None);
        assert!(is_default_denied("bpf"));
        assert!(!is_default_denied("memfd_create"));
        assert_eq!(syscall_name(libc::SYS_setsockopt), "setsockopt");
        assert_eq!(syscall_name(libc::SYS_connect), "connect");
    }
}
