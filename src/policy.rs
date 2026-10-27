//! Sandbox policy: what the untrusted program may touch.
//!
//! Sources, lowest to highest precedence:
//!   1. policy file   (--policy / SBX_POLICY_FILE, else /etc/sbx/policy.toml, else built-in default)
//!   2. environment   (SBX_FS_RO, SBX_FS_RW, SBX_NET, ...)
//!   3. CLI flags     (--ro, --rw, --net, ...)
//! Filesystem grants are additive across layers; scalar settings are overridden.
//! All sources are operator-controlled deployment config, never the untrusted payload.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_POLICY_PATH: &str = "/etc/sbx/policy.toml";
pub const BUILTIN_POLICY: &str = include_str!("../policy/default.toml");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub landlock: LandlockCfg,
    pub process: ProcessCfg,
    pub limits: Limits,
    pub env: EnvCfg,
    pub network: NetworkCfg,
    pub seccomp: SeccompCfg,
    pub fs: Vec<FsRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LandlockCfg {
    /// Refuse to run if Landlock is unavailable (fail closed).
    pub required: bool,
    /// Minimum kernel Landlock ABI to accept. Raised automatically to 4 when
    /// network.mode = "restricted" (TCP port rules need ABI v4).
    pub min_abi: i32,
    /// Block signals to processes outside the sandbox (ABI v6+, best effort).
    pub scope_signals: bool,
    /// Block connecting to abstract UNIX sockets outside the sandbox (ABI v6+, best effort).
    pub scope_abstract_unix: bool,
}

impl Default for LandlockCfg {
    fn default() -> Self {
        Self { required: true, min_abi: 1, scope_signals: true, scope_abstract_unix: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessCfg {
    /// UID/GID the program runs as when sbx starts as root.
    pub uid: u32,
    pub gid: u32,
    pub workdir: Option<PathBuf>,
    /// Wall-clock limit; 0 = none. Exceeding it kills the whole tree (exit 124).
    pub timeout_secs: u64,
    /// Time between forwarding SIGTERM and sending SIGKILL.
    pub kill_grace_secs: u64,
    /// false = threads allowed, fork/vfork/process-creating clone denied.
    pub subprocesses: bool,
}

impl Default for ProcessCfg {
    fn default() -> Self {
        Self {
            uid: 65534,
            gid: 65534,
            workdir: None,
            timeout_secs: 0,
            kill_grace_secs: 5,
            subprocesses: true,
        }
    }
}

/// Resource limits (setrlimit). `None` = inherit. Core dumps are always disabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub nofile: Option<u64>,
    pub nproc: Option<u64>,
    pub fsize_mb: Option<u64>,
    pub as_mb: Option<u64>,
    pub cpu_secs: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self { nofile: Some(1024), nproc: Some(512), fsize_mb: Some(1024), as_mb: None, cpu_secs: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvCfg {
    /// Variables copied from sbx's environment. Everything else is dropped,
    /// so platform-injected secrets/config never reach the sandbox.
    pub pass: Vec<String>,
    /// Variables set explicitly (override `pass`).
    pub set: BTreeMap<String, String>,
}

impl Default for EnvCfg {
    fn default() -> Self {
        let mut set = BTreeMap::new();
        set.insert("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into());
        set.insert("HOME".into(), "/tmp".into());
        Self { pass: vec!["LANG".into(), "LC_ALL".into(), "TZ".into(), "TERM".into()], set }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    /// Only AF_UNIX sockets (seccomp) and no TCP bind/connect (Landlock).
    #[default]
    None,
    /// TCP to/from allow-listed ports only (Landlock ABI v4). UDP only if allow_udp.
    Restricted,
    /// No network restrictions.
    Unrestricted,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkCfg {
    pub mode: NetMode,
    pub connect_tcp: Vec<u16>,
    pub bind_tcp: Vec<u16>,
    /// In "restricted" mode, permit UDP sockets (any destination: Landlock has no UDP rules).
    pub allow_udp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Violation {
    /// Denied syscalls fail with EPERM (most compatible).
    #[default]
    Errno,
    /// Denied syscalls kill the process with SIGSYS.
    Kill,
    /// Audit mode: denied syscalls are allowed but logged by the kernel.
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SeccompCfg {
    pub enabled: bool,
    pub on_violation: Violation,
    /// Extra syscalls to deny unconditionally (by name).
    pub deny: Vec<String>,
    /// Built-in unconditional denials to lift (e.g. "ptrace" for debuggers).
    pub allow: Vec<String>,
    /// Override permitted socket families (default derives from network.mode).
    pub socket_families: Option<Vec<String>>,
}

impl Default for SeccompCfg {
    fn default() -> Self {
        Self { enabled: true, on_violation: Violation::Errno, deny: vec![], allow: vec![], socket_families: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsRule {
    pub path: PathBuf,
    /// Any combination of r (read), w (write/create/delete), x (execute).
    pub access: String,
    /// Skip silently if the path does not exist (otherwise it is an error).
    #[serde(default)]
    pub optional: bool,
}

/// Settings that can come from env vars or CLI flags.
#[derive(Debug, Default)]
pub struct Overrides {
    pub policy_file: Option<PathBuf>,
    pub ro: Vec<PathBuf>,
    pub rw: Vec<PathBuf>,
    pub rx: Vec<PathBuf>,
    pub net: Option<String>,
    pub timeout_secs: Option<u64>,
    pub workdir: Option<PathBuf>,
    pub subprocesses: Option<bool>,
    pub env_pass: Vec<String>,
    pub best_effort: Option<bool>,
    pub on_violation: Option<String>,
}

impl Overrides {
    pub fn from_env() -> Result<Self, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let paths = |k: &str| var(k).map(|v| split_paths(&v)).unwrap_or_default();
        Ok(Self {
            policy_file: var("SBX_POLICY_FILE").map(PathBuf::from),
            ro: paths("SBX_FS_RO"),
            rw: paths("SBX_FS_RW"),
            rx: paths("SBX_FS_RX"),
            net: var("SBX_NET"),
            timeout_secs: var("SBX_TIMEOUT").map(|v| parse_u64("SBX_TIMEOUT", &v)).transpose()?,
            workdir: var("SBX_WORKDIR").map(PathBuf::from),
            subprocesses: var("SBX_SUBPROCESSES").map(|v| parse_bool("SBX_SUBPROCESSES", &v)).transpose()?,
            env_pass: var("SBX_ENV_PASS").map(|v| split_list(&v)).unwrap_or_default(),
            best_effort: var("SBX_BEST_EFFORT").map(|v| parse_bool("SBX_BEST_EFFORT", &v)).transpose()?,
            on_violation: var("SBX_SECCOMP_ACTION"),
        })
    }

    /// Layer `other` (higher precedence) on top of `self`.
    pub fn merge(mut self, other: Overrides) -> Self {
        self.policy_file = other.policy_file.or(self.policy_file);
        self.ro.extend(other.ro);
        self.rw.extend(other.rw);
        self.rx.extend(other.rx);
        self.net = other.net.or(self.net);
        self.timeout_secs = other.timeout_secs.or(self.timeout_secs);
        self.workdir = other.workdir.or(self.workdir);
        self.subprocesses = other.subprocesses.or(self.subprocesses);
        self.env_pass.extend(other.env_pass);
        self.best_effort = other.best_effort.or(self.best_effort);
        self.on_violation = other.on_violation.or(self.on_violation);
        self
    }
}

pub fn split_paths(s: &str) -> Vec<PathBuf> {
    s.split([':', ',']).filter(|p| !p.is_empty()).map(PathBuf::from).collect()
}

pub fn split_list(s: &str) -> Vec<String> {
    s.split([',', ':']).map(str::trim).filter(|p| !p.is_empty()).map(String::from).collect()
}

pub fn parse_u64(what: &str, v: &str) -> Result<u64, String> {
    v.trim().parse().map_err(|_| format!("{what}: expected a non-negative integer, got {v:?}"))
}

pub fn parse_bool(what: &str, v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{what}: expected a boolean, got {v:?}")),
    }
}

impl Policy {
    pub fn parse(src: &str, origin: &str) -> Result<Self, String> {
        toml::from_str(src).map_err(|e| format!("invalid policy {origin}: {e}"))
    }

    /// Resolve the effective policy from file + overrides, then validate it.
    pub fn resolve(ov: Overrides) -> Result<(Self, Vec<String>), String> {
        let mut p = match &ov.policy_file {
            Some(f) => Self::parse(&read(f)?, &f.display().to_string())?,
            None if Path::new(DEFAULT_POLICY_PATH).exists() => {
                Self::parse(&read(Path::new(DEFAULT_POLICY_PATH))?, DEFAULT_POLICY_PATH)?
            }
            None => Self::parse(BUILTIN_POLICY, "(built-in)")?,
        };

        let mut add = |paths: &[PathBuf], access: &str| {
            for path in paths {
                p.fs.push(FsRule { path: path.clone(), access: access.into(), optional: false });
            }
        };
        add(&ov.ro, "r");
        add(&ov.rw, "rw");
        add(&ov.rx, "rx");

        if let Some(net) = &ov.net {
            p.network = parse_net(net, &p.network)?;
        }
        if let Some(t) = ov.timeout_secs {
            p.process.timeout_secs = t;
        }
        if let Some(w) = ov.workdir {
            p.process.workdir = Some(w);
        }
        if let Some(s) = ov.subprocesses {
            p.process.subprocesses = s;
        }
        p.env.pass.extend(ov.env_pass);
        if let Some(be) = ov.best_effort {
            p.landlock.required = !be;
        }
        if let Some(v) = &ov.on_violation {
            p.seccomp.on_violation = match v.as_str() {
                "errno" => Violation::Errno,
                "kill" => Violation::Kill,
                "log" => Violation::Log,
                _ => return Err(format!("seccomp action must be errno|kill|log, got {v:?}")),
            };
        }

        let warnings = p.validate()?;
        Ok((p, warnings))
    }

    /// Hard errors for nonsense, warnings for risky-but-legal settings.
    pub fn validate(&self) -> Result<Vec<String>, String> {
        let mut warn = Vec::new();
        for r in &self.fs {
            if !r.path.is_absolute() {
                return Err(format!("fs path must be absolute: {}", r.path.display()));
            }
            if r.access.is_empty() || !r.access.chars().all(|c| matches!(c, 'r' | 'w' | 'x')) {
                return Err(format!("fs access for {} must be a combination of r/w/x, got {:?}", r.path.display(), r.access));
            }
            if r.path == Path::new("/") && r.access.contains('w') {
                warn.push("fs: write access to / defeats the filesystem sandbox".into());
            }
        }
        if let Some(w) = &self.process.workdir {
            if !w.is_absolute() {
                return Err(format!("workdir must be absolute: {}", w.display()));
            }
        }
        let net = &self.network;
        if net.mode != NetMode::Restricted && (!net.connect_tcp.is_empty() || !net.bind_tcp.is_empty()) {
            warn.push(format!("network: port lists are ignored in mode {:?}", net.mode));
        }
        if net.mode == NetMode::Restricted && net.connect_tcp.contains(&80) {
            warn.push("network: allowing TCP/80 lets the sandbox reach the cloud metadata server (169.254.169.254) and request the service account's token".into());
        }
        if net.mode == NetMode::Unrestricted {
            warn.push("network: unrestricted mode exposes the metadata server and service account token to the sandbox".into());
        }
        if net.allow_udp {
            warn.push("network: allow_udp permits UDP to any host/port (Landlock cannot filter UDP)".into());
        }
        if !self.landlock.required {
            warn.push("landlock: best-effort mode; filesystem rules may not be enforced on this kernel".into());
        }
        if !self.seccomp.enabled {
            warn.push("seccomp: disabled".into());
        }
        if self.seccomp.on_violation == Violation::Log {
            warn.push("seccomp: audit (log) mode, denied syscalls are ALLOWED and only logged".into());
        }
        Ok(warn)
    }
}

/// SBX_NET / --net syntax:  none | unrestricted | tcp:443,8443 | tcp:443+udp
fn parse_net(s: &str, base: &NetworkCfg) -> Result<NetworkCfg, String> {
    let s = s.trim();
    match s {
        "none" => return Ok(NetworkCfg { mode: NetMode::None, ..Default::default() }),
        "all" | "unrestricted" => return Ok(NetworkCfg { mode: NetMode::Unrestricted, ..Default::default() }),
        _ => {}
    }
    let rest = s.strip_prefix("tcp:").ok_or_else(|| format!("--net: expected none|unrestricted|tcp:PORT[,PORT...][+udp], got {s:?}"))?;
    let (ports, udp) = match rest.strip_suffix("+udp") {
        Some(p) => (p, true),
        None => (rest, false),
    };
    let mut cfg = NetworkCfg { mode: NetMode::Restricted, bind_tcp: base.bind_tcp.clone(), allow_udp: udp, connect_tcp: vec![] };
    for p in split_list(ports) {
        cfg.connect_tcp.push(p.parse().map_err(|_| format!("--net: bad port {p:?}"))?);
    }
    Ok(cfg)
}

fn read(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("cannot read policy {}: {e}", p.display()))
}
