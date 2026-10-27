//! Seccomp-BPF. Two stacked filters (the kernel applies the most restrictive
//! verdict across all filters, and both are inherited by every descendant):
//!
//!  1. prelude (hand-written): wrong architecture -> kill; x32 ABI -> ENOSYS;
//!     clone3 -> ENOSYS (its flags live in memory seccomp can't inspect, so
//!     libc falls back to clone(2), whose flags we *can* check).
//!  2. policy filter (seccompiler): default-allow deny-list of kernel attack
//!     surface + argument checks on clone, socket, ioctl, personality.
//!
//! A deny-list is used rather than an allow-list because the payload is an
//! arbitrary program (interpreters, compilers, ...). Filesystem and network
//! scoping are Landlock's job; seccomp removes syscalls that let code escape
//! or attack the kernel.

use crate::policy::{NetMode, Policy, Violation};
use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op,
    SeccompCondition as Cond, SeccompFilter, SeccompRule, TargetArch,
};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;

macro_rules! syscalls {
    ($($name:ident),* $(,)?) => { &[ $( (stringify!($name), libc::$name as i64) ),* ] };
}

/// Denied unconditionally by default. `seccomp.allow` may lift these.
const DEFAULT_DENY: &[(&str, i64)] = syscalls![
    // debugging / cross-process memory access
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
    SYS_kexec_load, SYS_kexec_file_load, SYS_init_module, SYS_finit_module, SYS_delete_module,
    SYS_acct, SYS_swapon, SYS_swapoff, SYS_reboot, SYS_sethostname, SYS_setdomainname,
    SYS_syslog, SYS_quotactl, SYS_settimeofday, SYS_clock_settime, SYS_clock_adjtime,
    SYS_adjtimex, SYS_vhangup,
];

#[cfg(target_arch = "x86_64")]
const DEFAULT_DENY_ARCH: &[(&str, i64)] =
    syscalls![SYS_iopl, SYS_ioperm, SYS_modify_ldt, SYS_uselib, SYS__sysctl, SYS_ustat, SYS_sysfs];
#[cfg(target_arch = "aarch64")]
const DEFAULT_DENY_ARCH: &[(&str, i64)] = &[];

/// Extra names accepted in `seccomp.deny`.
const EXTRA_NAMES: &[(&str, i64)] = syscalls![
    SYS_execve, SYS_execveat, SYS_clone, SYS_kill, SYS_tkill, SYS_tgkill, SYS_socket,
    SYS_socketpair, SYS_connect, SYS_bind, SYS_listen, SYS_accept, SYS_accept4, SYS_sendto,
    SYS_sendmsg, SYS_sendmmsg, SYS_recvfrom, SYS_recvmsg, SYS_memfd_create, SYS_mprotect,
    SYS_pkey_mprotect, SYS_prctl, SYS_seccomp, SYS_inotify_init1, SYS_fanotify_mark,
    SYS_sched_setaffinity, SYS_setpriority, SYS_mknodat, SYS_symlinkat, SYS_linkat,
    SYS_mbind, SYS_migrate_pages, SYS_move_pages, SYS_set_mempolicy, SYS_personality,
    SYS_ioctl, SYS_pidfd_open, SYS_pidfd_send_signal, SYS_landlock_create_ruleset,
];
#[cfg(target_arch = "x86_64")]
const EXTRA_NAMES_ARCH: &[(&str, i64)] = syscalls![SYS_fork, SYS_vfork, SYS_open, SYS_mknod];
#[cfg(target_arch = "aarch64")]
const EXTRA_NAMES_ARCH: &[(&str, i64)] = &[];

fn lookup(name: &str) -> Option<i64> {
    DEFAULT_DENY
        .iter()
        .chain(DEFAULT_DENY_ARCH)
        .chain(EXTRA_NAMES)
        .chain(EXTRA_NAMES_ARCH)
        .find(|(n, _)| n.strip_prefix("SYS_") == Some(name))
        .map(|(_, nr)| *nr)
}

fn family(name: &str) -> Result<u64, String> {
    Ok(match name {
        "unix" | "local" => libc::AF_UNIX,
        "inet" => libc::AF_INET,
        "inet6" => libc::AF_INET6,
        "netlink" => libc::AF_NETLINK,
        "packet" => libc::AF_PACKET,
        "vsock" => libc::AF_VSOCK,
        _ => return Err(format!("seccomp: unknown socket family {name:?} (unix|inet|inet6|netlink|packet|vsock)")),
    } as u64)
}

fn cond(arg: u8, op: Op, val: u64) -> Cond {
    Cond::new(arg, Len::Dword, op, val).expect("valid seccomp condition")
}

fn rule(conds: Vec<Cond>) -> SeccompRule {
    SeccompRule::new(conds).expect("valid seccomp rule")
}

struct Rules {
    map: BTreeMap<i64, Vec<SeccompRule>>,
    unconditional: BTreeSet<i64>,
}

impl Rules {
    fn deny(&mut self, nr: i64) {
        self.unconditional.insert(nr);
        self.map.insert(nr, vec![]); // empty chain = match unconditionally
    }
    fn deny_if(&mut self, nr: i64, conds: Vec<Cond>) {
        if !self.unconditional.contains(&nr) {
            self.map.entry(nr).or_default().push(rule(conds));
        }
    }
}

pub struct Programs {
    pub filters: Vec<BpfProgram>,
    pub summary: String,
}

pub fn build(p: &Policy) -> Result<Option<Programs>, String> {
    if !p.seccomp.enabled {
        return Ok(None);
    }
    let cfg = &p.seccomp;
    let mut allow = BTreeSet::new();
    for name in &cfg.allow {
        let nr = DEFAULT_DENY
            .iter()
            .chain(DEFAULT_DENY_ARCH)
            .find(|(n, _)| n.strip_prefix("SYS_") == Some(name.as_str()))
            .map(|(_, nr)| *nr)
            .ok_or_else(|| format!("seccomp.allow: {name:?} is not an unconditional default denial"))?;
        allow.insert(nr);
    }

    let mut r = Rules { map: BTreeMap::new(), unconditional: BTreeSet::new() };
    for &(_, nr) in DEFAULT_DENY.iter().chain(DEFAULT_DENY_ARCH) {
        if !allow.contains(&nr) {
            r.deny(nr);
        }
    }
    for name in &cfg.deny {
        r.deny(lookup(name).ok_or_else(|| format!("seccomp.deny: unknown syscall {name:?}"))?);
    }

    // clone(2): no new namespaces (user namespaces are a big kernel attack surface).
    const NS_FLAGS: [u64; 7] = [
        libc::CLONE_NEWNS as u64,
        libc::CLONE_NEWCGROUP as u64,
        libc::CLONE_NEWUTS as u64,
        libc::CLONE_NEWIPC as u64,
        libc::CLONE_NEWUSER as u64,
        libc::CLONE_NEWPID as u64,
        libc::CLONE_NEWNET as u64,
    ];
    for f in NS_FLAGS {
        r.deny_if(libc::SYS_clone, vec![cond(0, Op::MaskedEq(f), f)]);
    }
    if !p.process.subprocesses {
        // Threads (CLONE_THREAD) stay allowed; anything creating a process does not.
        r.deny_if(libc::SYS_clone, vec![cond(0, Op::MaskedEq(libc::CLONE_THREAD as u64), 0)]);
        #[cfg(target_arch = "x86_64")]
        {
            r.deny(libc::SYS_fork);
            r.deny(libc::SYS_vfork);
        }
    }

    // socket(2)/socketpair(2): address families.
    let families: Vec<u64> = match &cfg.socket_families {
        Some(list) => list.iter().map(|f| family(f)).collect::<Result<_, _>>()?,
        None if p.network.mode == NetMode::None => vec![libc::AF_UNIX as u64],
        None => vec![libc::AF_UNIX as u64, libc::AF_INET as u64, libc::AF_INET6 as u64],
    };
    for nr in [libc::SYS_socket, libc::SYS_socketpair] {
        r.deny_if(nr, families.iter().map(|&f| cond(0, Op::Ne, f)).collect());
    }

    // Restricted network: Landlock only governs TCP, so seccomp blocks every
    // other IP socket kind (UDP, raw, SCTP, MPTCP, ...) unless UDP is allowed.
    if p.network.mode == NetMode::Restricted {
        let stream = libc::SOCK_STREAM as u64;
        let dgram = libc::SOCK_DGRAM as u64;
        for fam in [libc::AF_INET as u64, libc::AF_INET6 as u64] {
            for ty in [2u64, 3, 4, 5, 6, 10] {
                // DGRAM RAW RDM SEQPACKET DCCP PACKET
                if ty == dgram && p.network.allow_udp {
                    continue;
                }
                r.deny_if(libc::SYS_socket, vec![cond(0, Op::Eq, fam), cond(1, Op::MaskedEq(0xf), ty)]);
            }
            r.deny_if(
                libc::SYS_socket,
                vec![
                    cond(0, Op::Eq, fam),
                    cond(1, Op::MaskedEq(0xf), stream),
                    cond(2, Op::Ne, 0),
                    cond(2, Op::Ne, libc::IPPROTO_TCP as u64),
                ],
            );
            if p.network.allow_udp {
                r.deny_if(
                    libc::SYS_socket,
                    vec![
                        cond(0, Op::Eq, fam),
                        cond(1, Op::MaskedEq(0xf), dgram),
                        cond(2, Op::Ne, 0),
                        cond(2, Op::Ne, libc::IPPROTO_UDP as u64),
                    ],
                );
            }
        }
    }

    // ioctl(2): no injecting keystrokes into a terminal outside the sandbox.
    for req in [libc::TIOCSTI as u64, libc::TIOCLINUX as u64] {
        r.deny_if(libc::SYS_ioctl, vec![cond(1, Op::Eq, req)]);
    }
    // personality(2): only the values runtimes actually use (no ADDR_NO_RANDOMIZE etc.).
    r.deny_if(
        libc::SYS_personality,
        [0x0u64, 0x8, 0x20000, 0x20008, 0xffff_ffff].iter().map(|&v| cond(0, Op::Ne, v)).collect(),
    );

    let on_match = match cfg.on_violation {
        Violation::Errno => SeccompAction::Errno(libc::EPERM as u32),
        Violation::Kill => SeccompAction::KillProcess,
        Violation::Log => SeccompAction::Log,
    };
    let denied = r.map.len();
    let filter = SeccompFilter::new(r.map, SeccompAction::Allow, on_match, ARCH)
        .map_err(|e| format!("seccomp: {e}"))?;
    let main: BpfProgram = filter.try_into().map_err(|e| format!("seccomp: {e:?}"))?;

    Ok(Some(Programs {
        filters: vec![prelude(), main],
        summary: format!(
            "seccomp: {denied} syscalls filtered, on_violation={:?}, socket families={:?}",
            cfg.on_violation, families
        ),
    }))
}

fn prelude() -> BpfProgram {
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    #[cfg(target_arch = "x86_64")]
    const JGE_K: u16 = 0x35;
    const RET_K: u16 = 0x06;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO_ENOSYS: u32 = 0x0005_0000 | libc::ENOSYS as u32;
    const RET_ALLOW: u32 = 0x7fff_0000;
    let ins = |code, jt, jf, k| sock_filter { code, jt, jf, k };

    let mut p = vec![
        ins(LD_W_ABS, 0, 0, 4), // seccomp_data.arch
        ins(JEQ_K, 1, 0, AUDIT_ARCH),
        ins(RET_K, 0, 0, RET_KILL_PROCESS),
        ins(LD_W_ABS, 0, 0, 0), // seccomp_data.nr
        ins(JEQ_K, 0, 1, libc::SYS_clone3 as u32),
        ins(RET_K, 0, 0, RET_ERRNO_ENOSYS),
    ];
    #[cfg(target_arch = "x86_64")]
    p.extend([ins(JGE_K, 0, 1, 0x4000_0000), ins(RET_K, 0, 0, RET_ERRNO_ENOSYS)]);
    p.push(ins(RET_K, 0, 0, RET_ALLOW));
    p
}

/// Called in the child after fork; filters are inherited across fork/exec.
pub fn enforce(progs: &Programs) -> Result<(), String> {
    for f in &progs.filters {
        seccompiler::apply_filter(f).map_err(|e| format!("seccomp: {e}"))?;
    }
    Ok(())
}
