//! Landlock: path-based filesystem rules, TCP port rules (ABI v4+) and IPC
//! scoping (ABI v6+). The policy pins the ABI whose access rights are
//! enforced and the kernel must support it; nothing is silently downgraded.
//! Rules are tied to inodes opened here, before fork, so volumes must already
//! be mounted (the platform mounts them before the entrypoint starts).

use crate::log;
use crate::policy::{LandlockAbi, NetMode, Policy};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};

#[derive(Debug, Clone, Copy)]
pub enum Probe {
    Available(u8),
    /// ENOSYS: not built in, denied by the container runtime's seccomp
    /// profile, or the "kernel" is gVisor (e.g. Cloud Run gen1).
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
        return Probe::Available(u8::try_from(r).unwrap_or(u8::MAX));
    }
    match log::errno() {
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
                "not implemented (ENOSYS): kernel built without Landlock, a container seccomp \
                 profile that denies it, or a gVisor sandbox such as Cloud Run gen1"
            ),
            Probe::NotEnabled => write!(f, "built in but disabled at boot (EOPNOTSUPP): add landlock to lsm="),
            Probe::Error(e) => write!(f, "probe failed: {}", std::io::Error::from_raw_os_error(*e)),
        }
    }
}

/// Kernel release that introduced each Landlock ABI, for error messages.
pub fn abi_kernel(v: u8) -> &'static str {
    match v {
        1 => "5.13",
        2 => "5.19",
        3 => "6.2",
        4 => "6.7",
        5 => "6.10",
        6 => "6.12",
        7 => "6.15",
        8 => "7.0",
        9 => "7.1",
        _ => "an unknown release",
    }
}

fn abi(v: u8) -> Result<ABI, String> {
    Ok(match v {
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        6 => ABI::V6,
        7 => ABI::V7,
        8 => ABI::V8,
        9 => ABI::V9,
        _ => return Err(format!("landlock.abi {v} is not supported by this build of sbx")),
    })
}

/// Map r/w/x to the rights defined by `abi`. Device-node creation is never granted.
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
    /// None only for landlock.abi = "off".
    pub ruleset: Option<RulesetCreated>,
    pub summary: String,
}

/// Check the kernel and build the ruleset in the supervisor (before fork) so
/// policy errors are reported clearly and the child only has to call
/// landlock_restrict_self().
pub fn prepare(p: &Policy) -> Result<Prepared, String> {
    let LandlockAbi::V(pinned) = p.landlock.abi else {
        return Ok(Prepared {
            ruleset: None,
            summary: "landlock: off (landlock.abi = \"off\"): file access is limited by permissions only".into(),
        });
    };
    let kernel = match probe() {
        Probe::Available(v) => v,
        other => return Err(format!("Landlock is required but {other}")),
    };
    if kernel < pinned {
        return Err(format!(
            "the policy pins Landlock ABI v{pinned} (Linux {}) but this kernel provides v{kernel}; \
             run on a newer kernel or lower landlock.abi (and the features that need it) explicitly",
            abi_kernel(pinned)
        ));
    }
    if kernel > pinned {
        log::warn(format!(
            "kernel supports Landlock ABI v{kernel} but the policy pins v{pinned}: access rights added after \
             v{pinned} are not restricted"
        ));
    }
    let abi = abi(pinned)?;
    let ll = |e: landlock::RulesetError| format!("landlock: {e}");
    let mut rs = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(ll)?;

    // In "none" and "egress" modes the kernel denies every TCP bind/connect
    // made from the sandbox; only bind_tcp ports get rules. In egress mode the
    // supervisor makes approved connects itself, outside the Landlock domain.
    let net_handled = p.network.mode != NetMode::Unrestricted;
    if net_handled {
        rs = rs.handle_access(AccessNet::from_all(abi)).map_err(ll)?;
    }
    let mut scopes = Vec::new();
    if p.landlock.scope_signals {
        rs = rs.scope(Scope::Signal).map_err(ll)?;
        scopes.push("signal");
    }
    if p.landlock.scope_abstract_unix {
        rs = rs.scope(Scope::AbstractUnixSocket).map_err(ll)?;
        scopes.push("abstract-unix");
    }

    let mut created = rs.create().map_err(ll)?;
    for rule in &p.fs {
        let path = rule.path.display();
        let meta = std::fs::metadata(&rule.path).map_err(|e| format!("fs rule {path}: {e}"))?;
        let mut access = rights(&rule.access, abi);
        if !meta.is_dir() {
            access &= AccessFs::from_file(abi); // directory-only rights are invalid on files
        }
        if access.is_empty() {
            return Err(format!(
                "fs rule {path}: access {:?} grants nothing on this file at ABI v{pinned}",
                rule.access
            ));
        }
        let fd = PathFd::new(&rule.path).map_err(|e| format!("fs rule {path}: {e}"))?;
        created = created
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| format!("fs rule {path}: {e}"))?;
    }
    if p.network.mode == NetMode::Egress {
        for &port in &p.network.bind_tcp {
            created = created
                .add_rule(NetPort::new(port, AccessNet::BindTcp))
                .map_err(|e| format!("network.bind_tcp {port}: {e}"))?;
        }
    }

    let summary = format!(
        "landlock: ABI v{pinned} (kernel v{kernel}), {} path rules, tcp {}, scopes [{}]",
        p.fs.len(),
        match p.network.mode {
            NetMode::None => "bind+connect denied".to_string(),
            NetMode::Egress => format!(
                "connect denied in-sandbox (egress filter connects), bind {:?}",
                p.network.bind_tcp
            ),
            NetMode::Unrestricted => "unrestricted".to_string(),
        },
        scopes.join(", ")
    );
    Ok(Prepared {
        ruleset: Some(created.no_new_privs(true)),
        summary,
    })
}

/// Called in the child after fork. Irreversible; inherited by every descendant.
pub fn enforce(ruleset: RulesetCreated) -> Result<(), String> {
    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("landlock_restrict_self: {e}"))?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        other => Err(format!("landlock ruleset not fully enforced: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_follow_the_pinned_abi() {
        let w1 = rights("w", ABI::V1);
        assert!(!w1.contains(AccessFs::Truncate), "truncate is not part of ABI v1");
        assert!(rights("w", ABI::V3).contains(AccessFs::Truncate));
        assert!(!rights("w", ABI::V4).contains(AccessFs::IoctlDev));
        assert!(rights("w", ABI::V5).contains(AccessFs::IoctlDev));
        let r = rights("r", ABI::V6);
        assert!(r.contains(AccessFs::ReadFile) && !r.contains(AccessFs::Execute));
        assert!(!rights("rwx", ABI::V6).contains(AccessFs::MakeChar));
        assert!(abi(0).is_err() && abi(10).is_err());
    }
}
