//! Landlock: path-based filesystem rules, TCP port rules (ABI v4+) and IPC
//! scoping (ABI v6+). Rules are tied to inodes opened here, *before* fork, so
//! volumes must already be mounted (they are: the platform mounts them before
//! the entrypoint starts).

use crate::policy::{NetMode, Policy};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};


#[derive(Debug, Clone, Copy)]
pub enum Probe {
    Available(i32),
    /// ENOSYS: not built in (or the "kernel" is gVisor, e.g. Cloud Run gen1).
    NotImplemented,
    /// EOPNOTSUPP: built in but not enabled at boot.
    NotEnabled,
    Error(i32),
}

pub fn probe() -> Probe {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: version query; NULL attr and size 0 are required by the API.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r >= 1 {
        return Probe::Available(r as i32);
    }
    match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        libc::ENOSYS => Probe::NotImplemented,
        libc::EOPNOTSUPP => Probe::NotEnabled,
        e => Probe::Error(e),
    }
}

impl std::fmt::Display for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Probe::Available(v) => write!(f, "available, ABI v{v}"),
            Probe::NotImplemented => write!(
                f,
                "not implemented (ENOSYS): kernel built without Landlock, or a gVisor sandbox \
                 such as Cloud Run gen1; use --execution-environment=gen2"
            ),
            Probe::NotEnabled => write!(f, "built in but disabled at boot (EOPNOTSUPP): add landlock to lsm="),
            Probe::Error(e) => write!(f, "probe failed: errno {e}"),
        }
    }
}

fn abi_of(v: i32) -> ABI {
    match v {
        i32::MIN..=0 => ABI::Unsupported,
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        6 => ABI::V6,
        7 => ABI::V7,
        8 => ABI::V8,
        _ => ABI::V9, // newest the crate knows; newer kernels are backward compatible
    }
}

/// Map r/w/x to Landlock rights. Device-node creation is never granted.
fn rights(letters: &str, abi: ABI) -> BitFlags<AccessFs> {
    let mut a = BitFlags::<AccessFs>::empty();
    if letters.contains('r') {
        a |= AccessFs::ReadFile | AccessFs::ReadDir;
    }
    if letters.contains('w') {
        a |= AccessFs::WriteFile
            | AccessFs::Truncate
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::MakeSym
            | AccessFs::MakeFifo
            | AccessFs::MakeSock
            | AccessFs::Refer
            | AccessFs::IoctlDev
            | AccessFs::ResolveUnix;
    }
    if letters.contains('x') {
        a |= AccessFs::Execute;
    }
    a & AccessFs::from_all(abi)
}

pub struct Prepared {
    pub ruleset: Option<RulesetCreated>,
    pub summary: String,
}

/// Build the ruleset in the supervisor (before fork) so policy errors are
/// reported clearly and the child only has to call landlock_restrict_self().
pub fn prepare(p: &Policy) -> Result<Prepared, String> {
    let net_restricted = p.network.mode == NetMode::Restricted;
    let kernel = match probe() {
        Probe::Available(v) => v,
        other => {
            if p.landlock.required {
                return Err(format!("Landlock required but {other}"));
            }
            if net_restricted {
                return Err(format!("network.mode=restricted needs Landlock, but {other}"));
            }
            return Ok(Prepared { ruleset: None, summary: format!("landlock: SKIPPED ({other})") });
        }
    };

    let needed = p.landlock.min_abi.max(if net_restricted { 4 } else { 1 });
    if kernel < needed {
        return Err(format!(
            "kernel Landlock ABI v{kernel} < required v{needed}{}",
            if net_restricted { " (TCP port rules need v4, Linux 6.7+)" } else { "" }
        ));
    }

    let abi = abi_of(kernel);
    // We only request what this kernel supports, so anything that cannot be
    // enforced is a real error rather than a silent downgrade.
    let mut rs = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("landlock: {e}"))?;

    // Handle TCP unless unrestricted: in "none" mode no port rules are added,
    // so every TCP bind/connect is denied (on top of seccomp's socket filter).
    let net_handled = p.network.mode != NetMode::Unrestricted && kernel >= 4;
    if net_handled {
        rs = rs.handle_access(AccessNet::from_all(abi)).map_err(|e| format!("landlock: {e}"))?;
    }
    let mut scopes = Vec::new();
    if kernel >= 6 {
        if p.landlock.scope_signals {
            rs = rs.scope(Scope::Signal).map_err(|e| format!("landlock: {e}"))?;
            scopes.push("signal");
        }
        if p.landlock.scope_abstract_unix {
            rs = rs.scope(Scope::AbstractUnixSocket).map_err(|e| format!("landlock: {e}"))?;
            scopes.push("abstract-unix");
        }
    }

    let mut created = rs.create().map_err(|e| format!("landlock: {e}"))?;
    let mut granted = 0usize;
    for rule in &p.fs {
        let meta = match std::fs::metadata(&rule.path) {
            Ok(m) => m,
            Err(_) if rule.optional => continue,
            Err(e) => return Err(format!("fs rule {}: {e}", rule.path.display())),
        };
        let mut access = rights(&rule.access, abi);
        if !meta.is_dir() {
            access &= AccessFs::from_file(abi); // directory-only rights are invalid on files
        }
        if access.is_empty() {
            continue;
        }
        let fd = PathFd::new(&rule.path).map_err(|e| format!("fs rule {}: {e}", rule.path.display()))?;
        created = created
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| format!("fs rule {}: {e}", rule.path.display()))?;
        granted += 1;
    }
    if net_restricted {
        for &port in &p.network.connect_tcp {
            created = created
                .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
                .map_err(|e| format!("tcp connect {port}: {e}"))?;
        }
        for &port in &p.network.bind_tcp {
            created = created
                .add_rule(NetPort::new(port, AccessNet::BindTcp))
                .map_err(|e| format!("tcp bind {port}: {e}"))?;
        }
    }

    let summary = format!(
        "landlock: ABI v{kernel}, {granted} path rules, tcp={}, scopes=[{}]",
        if !net_handled {
            "unfiltered".to_string()
        } else if net_restricted {
            format!("connect{:?} bind{:?}", p.network.connect_tcp, p.network.bind_tcp)
        } else {
            "denied".to_string()
        },
        scopes.join(",")
    );
    Ok(Prepared { ruleset: Some(created.no_new_privs(true)), summary })
}

/// Called in the child after fork. Irreversible; inherited by every descendant.
pub fn enforce(ruleset: RulesetCreated) -> Result<(), String> {
    let status = ruleset.restrict_self().map_err(|e| format!("landlock_restrict_self: {e}"))?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        other => Err(format!("landlock ruleset not fully enforced: {other:?}")),
    }
}

