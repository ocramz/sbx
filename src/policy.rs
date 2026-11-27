//! Sandbox policy: what the untrusted program may touch.
//!
//! The policy file is the only source of defaults: every field must be
//! present, unknown fields are rejected, and sbx has no built-in policy or
//! default path. SBX_* environment variables and command-line flags can then
//! add filesystem grants and egress rules, or replace a few scalars (flags win
//! over the environment). All sources are operator-controlled deployment
//! config, never the untrusted payload.
//!
//! Validation reports every problem it finds, not just the first one.

use crate::net::{AnswerScope, Cidr, DomainPattern};
use crate::seccomp_layer;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

/// Every SBX_* variable sbx understands. Any other SBX_* variable is an error,
/// so a typo cannot silently leave a setting at its file value.
pub const ENV_VARS: &[&str] = &[
    "SBX_POLICY_FILE",
    "SBX_FS_RO",
    "SBX_FS_RW",
    "SBX_FS_RX",
    "SBX_NET",
    "SBX_EGRESS",
    "SBX_TIMEOUT",
    "SBX_WORKDIR",
    "SBX_SUBPROCESSES",
    "SBX_ENV_PASS",
    "SBX_SECCOMP_ACTION",
    "SBX_QUIET",
    "SBX_REPORT_FILE",
    "SBX_LOG_FILE",
    "SBX_SERIES_FILE",
];

/// Highest Landlock ABI this build knows how to enforce.
pub const MAX_LANDLOCK_ABI: u8 = 9;

pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Longest interval between two memory samples.
pub const MAX_SAMPLE_MS: u64 = 60_000;

/// Most samples a memory series keeps (plus the final one).
pub const MAX_SERIES_SAMPLES: u32 = 1_000_000;

/// Most processes a row of a memory series lists.
pub const MAX_SERIES_PROCESSES: u32 = 4096;

/// Most memory a series may take in sbx, worst case ([`crate::series::bound`]).
pub const SERIES_CEILING_BYTES: u64 = 256 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub landlock: LandlockCfg,
    pub process: ProcessCfg,
    pub limits: Limits,
    pub cgroup: CgroupCfg,
    pub measure: MeasureCfg,
    pub env: EnvCfg,
    pub network: NetworkCfg,
    pub seccomp: SeccompCfg,
    pub fs: Vec<FsRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockCfg {
    /// The Landlock ABI whose access rights are enforced. The kernel must
    /// support at least this version; rights added by newer ABIs are not
    /// handled (sbx warns when the kernel is newer). "off" runs without
    /// Landlock, for kernels built without it.
    pub abi: LandlockAbi,
    /// Deny signals to processes outside the sandbox (needs abi >= 6).
    pub scope_signals: bool,
    /// Deny connecting to abstract UNIX sockets created outside the sandbox (needs abi >= 6).
    pub scope_abstract_unix: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCfg {
    /// Identity of the sandboxed program. sbx switches to it when started as
    /// root; otherwise it must equal sbx's own uid/gid.
    pub uid: u32,
    pub gid: u32,
    pub workdir: PathBuf,
    /// Wall-clock limit for the whole process tree (exit 124), or "none".
    pub timeout_secs: Timeout,
    /// Time between forwarding SIGTERM and sending SIGKILL.
    pub kill_grace_secs: u64,
    /// false: threads only, every process-creating fork/clone is denied.
    pub subprocesses: bool,
}

/// setrlimit values for the sandbox. Core dumps are always disabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub nofile: u64,
    pub nproc: Limit,
    pub fsize_mb: Limit,
    pub as_mb: Limit,
    pub cpu_secs: Limit,
}

/// cgroup v2 limits for the whole sandbox (see docs/cgroup.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCgroup", into = "RawCgroup")]
pub enum CgroupCfg {
    /// No cgroup of its own: the sandbox shares the container's limits.
    Off,
    /// The program runs in a child of sbx's own cgroup, which must be
    /// delegated to sbx: memory.max (swap off) and pids.max.
    Delegated { memory_mb: Limit, pids: Limit },
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CgroupMode {
    Off,
    Delegated,
}

/// The `[cgroup]` table as written: the limits exist only with "delegated".
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCgroup {
    mode: CgroupMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory_mb: Option<Limit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pids: Option<Limit>,
}

impl TryFrom<RawCgroup> for CgroupCfg {
    type Error = String;
    fn try_from(r: RawCgroup) -> Result<Self, String> {
        match (r.mode, r.memory_mb, r.pids) {
            (CgroupMode::Off, None, None) => Ok(CgroupCfg::Off),
            (CgroupMode::Off, _, _) => {
                Err("cgroup.memory_mb and cgroup.pids are only used with mode = \"delegated\"".into())
            }
            (CgroupMode::Delegated, Some(memory_mb), Some(pids)) => Ok(CgroupCfg::Delegated { memory_mb, pids }),
            (CgroupMode::Delegated, m, _) => Err(format!(
                "cgroup.mode = \"delegated\" needs cgroup.{} (a number or \"unlimited\")",
                if m.is_none() { "memory_mb" } else { "pids" }
            )),
        }
    }
}

impl From<CgroupCfg> for RawCgroup {
    fn from(c: CgroupCfg) -> Self {
        match c {
            CgroupCfg::Off => RawCgroup {
                mode: CgroupMode::Off,
                memory_mb: None,
                pids: None,
            },
            CgroupCfg::Delegated { memory_mb, pids } => RawCgroup {
                mode: CgroupMode::Delegated,
                memory_mb: Some(memory_mb),
                pids: Some(pids),
            },
        }
    }
}

/// What sbx measures while the program runs, besides rusage (see
/// docs/report.md, "Memory by kind").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawMeasure", into = "RawMeasure")]
pub enum MeasureCfg {
    /// No sampling: the report's `memory` is null.
    Off,
    /// Sample the sandbox's memory by kind every `interval_ms`, and the use
    /// of each tmpfs mount in `tmpfs` above its level when sbx started.
    Sampled {
        interval_ms: NonZeroU64,
        tmpfs: Vec<PathBuf>,
        series: SeriesCfg,
    },
}

impl MeasureCfg {
    /// The series policy; off without sampling.
    pub fn series(&self) -> SeriesCfg {
        match self {
            MeasureCfg::Off => SeriesCfg::Off,
            MeasureCfg::Sampled { series, .. } => *series,
        }
    }
}

/// The `[measure]` table as written: tmpfs mounts and a series only with
/// sampling on.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMeasure {
    memory_sample_ms: u64,
    tmpfs: Vec<PathBuf>,
    // Last: a table follows the plain values in TOML.
    series: SeriesCfg,
}

impl TryFrom<RawMeasure> for MeasureCfg {
    type Error = String;
    fn try_from(r: RawMeasure) -> Result<Self, String> {
        match (NonZeroU64::new(r.memory_sample_ms), r.tmpfs, r.series) {
            (None, tmpfs, _) if !tmpfs.is_empty() => {
                Err("measure.tmpfs is only used when measure.memory_sample_ms is above 0".into())
            }
            (None, _, SeriesCfg::On { .. }) => {
                Err("measure.series.mode = \"on\" needs measure.memory_sample_ms above 0".into())
            }
            (None, _, SeriesCfg::Off) => Ok(MeasureCfg::Off),
            (Some(interval_ms), tmpfs, series) => Ok(MeasureCfg::Sampled {
                interval_ms,
                tmpfs,
                series,
            }),
        }
    }
}

impl From<MeasureCfg> for RawMeasure {
    fn from(m: MeasureCfg) -> Self {
        match m {
            MeasureCfg::Off => RawMeasure {
                memory_sample_ms: 0,
                tmpfs: vec![],
                series: SeriesCfg::Off,
            },
            MeasureCfg::Sampled {
                interval_ms,
                tmpfs,
                series,
            } => RawMeasure {
                memory_sample_ms: interval_ms.get(),
                tmpfs,
                series,
            },
        }
    }
}

/// Whether sbx keeps every memory sample for `--series FILE` (see
/// docs/report.md, "Time series"). Without `--series` nothing is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSeries", into = "RawSeries")]
pub enum SeriesCfg {
    Off,
    /// Keep the first `max_samples` samples and the one after the program
    /// exits; count the others. Each row lists the sample's `max_processes`
    /// largest processes (0: none) and sums the rest. The file is written
    /// as `compression` says.
    On {
        max_samples: NonZeroU32,
        max_processes: u32,
        compression: SeriesCompression,
    },
}

/// How the series file is written. The series sbx holds in memory is the
/// same either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeriesCompression {
    /// The JSON as is.
    None,
    /// The gzip of the same JSON.
    Gzip,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SeriesMode {
    Off,
    On,
}

/// The `[measure.series]` table as written: the settings exist only with "on".
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSeries {
    mode: SeriesMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_samples: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_processes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compression: Option<SeriesCompression>,
}

impl TryFrom<RawSeries> for SeriesCfg {
    type Error = String;
    fn try_from(r: RawSeries) -> Result<Self, String> {
        match r.mode {
            SeriesMode::Off => {
                let set = [
                    ("max_samples", r.max_samples.is_some()),
                    ("max_processes", r.max_processes.is_some()),
                    ("compression", r.compression.is_some()),
                ];
                match set.into_iter().find(|(_, set)| *set) {
                    Some((field, _)) => Err(format!("measure.series.{field} is only used with mode = \"on\"")),
                    None => Ok(SeriesCfg::Off),
                }
            }
            SeriesMode::On => {
                let needs = |what: &str| format!("measure.series.mode = \"on\" needs measure.series.{what}");
                let n = r.max_samples.ok_or_else(|| needs("max_samples"))?;
                let max_processes = r.max_processes.ok_or_else(|| needs("max_processes (0 lists none)"))?;
                let compression = r
                    .compression
                    .ok_or_else(|| needs("compression (\"none\" or \"gzip\")"))?;
                let max_samples =
                    NonZeroU32::new(n).ok_or_else(|| "measure.series.max_samples must be at least 1".to_string())?;
                Ok(SeriesCfg::On {
                    max_samples,
                    max_processes,
                    compression,
                })
            }
        }
    }
}

impl From<SeriesCfg> for RawSeries {
    fn from(s: SeriesCfg) -> Self {
        match s {
            SeriesCfg::Off => RawSeries {
                mode: SeriesMode::Off,
                max_samples: None,
                max_processes: None,
                compression: None,
            },
            SeriesCfg::On {
                max_samples,
                max_processes,
                compression,
            } => RawSeries {
                mode: SeriesMode::On,
                max_samples: Some(max_samples.get()),
                max_processes: Some(max_processes),
                compression: Some(compression),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvCfg {
    /// Variables copied from sbx's environment; each must be set.
    pub pass: Vec<String>,
    /// Variables set to fixed values.
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCfg {
    pub mode: NetMode,
    /// TCP ports the program may bind (mode = "egress" only).
    pub bind_tcp: Vec<u16>,
    /// Outbound TCP allow-list (mode = "egress" only).
    pub egress: Vec<EgressRule>,
    /// DNS proxy; required exactly when an egress rule names a domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsCfg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    /// No IP sockets at all.
    None,
    /// TCP only, to destinations allowed by `network.egress`.
    Egress,
    /// No network restrictions.
    Unrestricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsCfg {
    /// Loopback address, port 53, where sbx serves DNS over TCP to the sandbox.
    pub listen: SocketAddr,
    /// The single resolver allowed queries are forwarded to.
    pub upstream: SocketAddr,
    pub upstream_transport: Transport,
    pub resolv_conf: ResolvConfMode,
    pub timeout_ms: u64,
    /// Address classes a DNS answer may add to the egress allow-set.
    /// Link-local, multicast and reserved addresses are never added.
    pub answer_scopes: Vec<AnswerScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolvConfMode {
    /// sbx writes /etc/resolv.conf so the sandbox uses the proxy over TCP.
    Write,
    /// /etc/resolv.conf must already point at the proxy with `options use-vc`.
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Violation {
    /// The denied syscall fails with EPERM (egress denials: EACCES).
    Errno,
    /// The offending process is killed: with SIGKILL by the supervisor with
    /// the listener, with SIGSYS by the kernel without it.
    Kill,
}

/// Who sees the policy filter's matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Notify {
    /// A seccomp user-notification listener: the supervisor logs and counts
    /// every match, applies `on_violation`, and decides egress connects.
    Listener,
    /// No listener, for kernels without seccomp user notification (gVisor):
    /// the kernel applies `on_violation` itself, and matches are neither
    /// logged nor counted (see docs/platforms.md, "Without the listener").
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SocketFamily {
    Unix,
    Inet,
    Inet6,
    Netlink,
    Packet,
    Vsock,
}

impl SocketFamily {
    pub fn af(self) -> i32 {
        match self {
            SocketFamily::Unix => libc::AF_UNIX,
            SocketFamily::Inet => libc::AF_INET,
            SocketFamily::Inet6 => libc::AF_INET6,
            SocketFamily::Netlink => libc::AF_NETLINK,
            SocketFamily::Packet => libc::AF_PACKET,
            SocketFamily::Vsock => libc::AF_VSOCK,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompCfg {
    pub notify: Notify,
    pub on_violation: Violation,
    /// Extra syscalls to deny (by name).
    pub deny: Vec<String>,
    /// Built-in denials to lift (by name), e.g. "ptrace" for debuggers.
    pub allow: Vec<String>,
    /// Socket address families the program may create.
    pub socket_families: Vec<SocketFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsRule {
    /// Absolute, canonical (no symlinks) path that must exist.
    pub path: PathBuf,
    /// Any combination of r (read), w (write/create/delete), x (execute).
    pub access: String,
}

/// A number, or a keyword meaning "no limit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Value(u64),
    Unlimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timeout {
    Secs(u64),
    None,
}

/// A Landlock ABI version, or "off": no Landlock at all, so files are
/// protected by their permissions only (see docs/platforms.md, "Without Landlock").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockAbi {
    V(u8),
    Off,
}

fn ser_keyword<S: Serializer>(s: S, n: Option<u64>, kw: &str) -> Result<S::Ok, S::Error> {
    match n {
        Some(n) => s.serialize_u64(n),
        None => s.serialize_str(kw),
    }
}

struct KeywordVisitor(&'static str);

impl de::Visitor<'_> for KeywordVisitor {
    type Value = Option<u64>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a non-negative integer or \"{}\"", self.0)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Some(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        u64::try_from(v)
            .map(Some)
            .map_err(|_| E::custom(format!("{v} is negative; expected {}", self.0)))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v == self.0 {
            Ok(None)
        } else {
            Err(E::custom(format!(
                "expected a non-negative integer or \"{}\", got {v:?}",
                self.0
            )))
        }
    }
}

impl Serialize for Limit {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_keyword(
            s,
            match self {
                Limit::Value(n) => Some(*n),
                Limit::Unlimited => None,
            },
            "unlimited",
        )
    }
}

impl<'de> Deserialize<'de> for Limit {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match d.deserialize_any(KeywordVisitor("unlimited"))? {
            Some(n) => Limit::Value(n),
            None => Limit::Unlimited,
        })
    }
}

impl Serialize for Timeout {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_keyword(
            s,
            match self {
                Timeout::Secs(n) => Some(*n),
                Timeout::None => None,
            },
            "none",
        )
    }
}

impl<'de> Deserialize<'de> for Timeout {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match d.deserialize_any(KeywordVisitor("none"))? {
            Some(n) => Timeout::Secs(n),
            None => Timeout::None,
        })
    }
}

impl Serialize for LandlockAbi {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_keyword(
            s,
            match self {
                LandlockAbi::V(v) => Some(u64::from(*v)),
                LandlockAbi::Off => None,
            },
            "off",
        )
    }
}

impl<'de> Deserialize<'de> for LandlockAbi {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match d.deserialize_any(KeywordVisitor("off"))? {
            Some(n) => u8::try_from(n)
                .map(LandlockAbi::V)
                .map_err(|_| de::Error::custom(format!("Landlock ABI {n} is out of range"))),
            None => Ok(LandlockAbi::Off),
        }
    }
}

/// An egress rule after parsing.
#[derive(Debug, Clone)]
pub enum EgressTarget {
    Cidr(Cidr),
    Domain(DomainPattern),
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub target: EgressTarget,
    pub ports: Vec<u16>,
}

impl fmt::Display for CompiledRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();
        match &self.target {
            EgressTarget::Cidr(c) => write!(f, "cidr {c} ports {}", ports.join("+")),
            EgressTarget::Domain(d) => write!(f, "domain {d} ports {}", ports.join("+")),
        }
    }
}

impl EgressRule {
    pub fn compile(&self) -> Result<CompiledRule, String> {
        let target = match (&self.cidr, &self.domain) {
            (Some(c), None) => EgressTarget::Cidr(Cidr::parse(c)?),
            (None, Some(d)) => {
                if d.parse::<IpAddr>().is_ok() {
                    return Err(format!(
                        "egress domain {d:?} is an IP address; use cidr = \"{d}/32\" (or /128)"
                    ));
                }
                EgressTarget::Domain(DomainPattern::parse(d)?)
            }
            (Some(_), Some(_)) => return Err("egress rule has both cidr and domain; use one rule for each".into()),
            (None, None) => return Err("egress rule needs either cidr or domain".into()),
        };
        if self.ports.is_empty() {
            return Err("egress rule has an empty ports list".into());
        }
        let mut seen = BTreeSet::new();
        for &p in &self.ports {
            if p == 0 {
                return Err("egress rule lists port 0".into());
            }
            if !seen.insert(p) {
                return Err(format!("egress rule lists port {p} twice"));
            }
        }
        Ok(CompiledRule {
            target,
            ports: self.ports.clone(),
        })
    }
}

/// Settings that can come from SBX_* variables or command-line flags.
#[derive(Debug, Default)]
pub struct Overrides {
    pub policy_file: Option<PathBuf>,
    pub ro: Vec<PathBuf>,
    pub rw: Vec<PathBuf>,
    pub rx: Vec<PathBuf>,
    pub net: Option<NetMode>,
    pub egress: Vec<EgressRule>,
    pub timeout: Option<Timeout>,
    pub workdir: Option<PathBuf>,
    pub subprocesses: Option<bool>,
    pub env_pass: Vec<String>,
    pub on_violation: Option<Violation>,
    pub quiet: Option<bool>,
    pub report: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub series: Option<PathBuf>,
}

impl Overrides {
    /// Read SBX_* variables. Unknown SBX_* names and empty values are errors.
    pub fn from_env() -> Result<Self, Vec<String>> {
        let mut errs = Vec::new();
        for (k, _) in std::env::vars_os() {
            match k.to_str() {
                Some(k) if k.starts_with("SBX_") && !ENV_VARS.contains(&k) => errs.push(format!(
                    "unknown environment variable {k}; sbx understands {}",
                    ENV_VARS.join(", ")
                )),
                None if k.as_encoded_bytes().starts_with(b"SBX_") => {
                    errs.push(format!("environment variable name {k:?} is not valid UTF-8"))
                }
                _ => {}
            }
        }
        let get = |k: &str, errs: &mut Vec<String>| -> Option<String> {
            match std::env::var_os(k)?.into_string() {
                Ok(v) if v.is_empty() => {
                    errs.push(format!("{k} is set but empty; unset it instead"));
                    None
                }
                Ok(v) => Some(v),
                Err(_) => {
                    errs.push(format!("{k} is not valid UTF-8"));
                    None
                }
            }
        };
        let mut o = Overrides::default();
        let mut set = |r: Result<(), String>| {
            if let Err(e) = r {
                errs.push(e);
            }
        };
        let mut e2 = Vec::new();
        if let Some(v) = get("SBX_POLICY_FILE", &mut e2) {
            o.policy_file = Some(PathBuf::from(v));
        }
        if let Some(v) = get("SBX_FS_RO", &mut e2) {
            set(split_paths("SBX_FS_RO", &v).map(|p| o.ro = p));
        }
        if let Some(v) = get("SBX_FS_RW", &mut e2) {
            set(split_paths("SBX_FS_RW", &v).map(|p| o.rw = p));
        }
        if let Some(v) = get("SBX_FS_RX", &mut e2) {
            set(split_paths("SBX_FS_RX", &v).map(|p| o.rx = p));
        }
        if let Some(v) = get("SBX_NET", &mut e2) {
            set(parse_net("SBX_NET", &v).map(|n| o.net = Some(n)));
        }
        if let Some(v) = get("SBX_EGRESS", &mut e2) {
            set(parse_egress_list("SBX_EGRESS", &v).map(|r| o.egress = r));
        }
        if let Some(v) = get("SBX_TIMEOUT", &mut e2) {
            set(parse_timeout("SBX_TIMEOUT", &v).map(|t| o.timeout = Some(t)));
        }
        if let Some(v) = get("SBX_WORKDIR", &mut e2) {
            o.workdir = Some(PathBuf::from(v));
        }
        if let Some(v) = get("SBX_SUBPROCESSES", &mut e2) {
            set(parse_bool("SBX_SUBPROCESSES", &v).map(|b| o.subprocesses = Some(b)));
        }
        if let Some(v) = get("SBX_ENV_PASS", &mut e2) {
            set(split_names("SBX_ENV_PASS", &v).map(|n| o.env_pass = n));
        }
        if let Some(v) = get("SBX_SECCOMP_ACTION", &mut e2) {
            set(parse_violation("SBX_SECCOMP_ACTION", &v).map(|a| o.on_violation = Some(a)));
        }
        if let Some(v) = get("SBX_QUIET", &mut e2) {
            set(parse_bool("SBX_QUIET", &v).map(|b| o.quiet = Some(b)));
        }
        if let Some(v) = get("SBX_REPORT_FILE", &mut e2) {
            o.report = Some(PathBuf::from(v));
        }
        if let Some(v) = get("SBX_LOG_FILE", &mut e2) {
            o.log = Some(PathBuf::from(v));
        }
        if let Some(v) = get("SBX_SERIES_FILE", &mut e2) {
            o.series = Some(PathBuf::from(v));
        }
        errs.extend(e2);
        if errs.is_empty() {
            Ok(o)
        } else {
            Err(errs)
        }
    }

    /// Layer `flags` (higher precedence) over `self` (the environment):
    /// scalars set by a flag replace the environment's, lists are concatenated.
    pub fn merge(mut self, flags: Overrides) -> Self {
        self.policy_file = flags.policy_file.or(self.policy_file);
        self.ro.extend(flags.ro);
        self.rw.extend(flags.rw);
        self.rx.extend(flags.rx);
        self.net = flags.net.or(self.net);
        self.egress.extend(flags.egress);
        self.timeout = flags.timeout.or(self.timeout);
        self.workdir = flags.workdir.or(self.workdir);
        self.subprocesses = flags.subprocesses.or(self.subprocesses);
        self.env_pass.extend(flags.env_pass);
        self.on_violation = flags.on_violation.or(self.on_violation);
        self.quiet = flags.quiet.or(self.quiet);
        self.report = flags.report.or(self.report);
        self.log = flags.log.or(self.log);
        self.series = flags.series.or(self.series);
        self
    }
}

/// `PATH[:PATH...]`. Empty entries are errors.
pub fn split_paths(what: &str, s: &str) -> Result<Vec<PathBuf>, String> {
    s.split(':')
        .map(|p| {
            if p.is_empty() {
                Err(format!("{what}: empty path in {s:?} (paths are separated by ':')"))
            } else {
                Ok(PathBuf::from(p))
            }
        })
        .collect()
}

/// `NAME[:NAME...]` for environment variable names.
pub fn split_names(what: &str, s: &str) -> Result<Vec<String>, String> {
    s.split(':')
        .map(|n| {
            if n.is_empty() || n.contains('=') {
                Err(format!(
                    "{what}: invalid variable name {n:?} in {s:?} (names are separated by ':')"
                ))
            } else {
                Ok(n.to_string())
            }
        })
        .collect()
}

pub fn parse_bool(what: &str, v: &str) -> Result<bool, String> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{what}: expected true or false, got {v:?}")),
    }
}

pub fn parse_net(what: &str, v: &str) -> Result<NetMode, String> {
    match v {
        "none" => Ok(NetMode::None),
        "egress" => Ok(NetMode::Egress),
        "unrestricted" => Ok(NetMode::Unrestricted),
        _ => Err(format!("{what}: expected none, egress or unrestricted, got {v:?}")),
    }
}

pub fn parse_timeout(what: &str, v: &str) -> Result<Timeout, String> {
    if v == "none" {
        return Ok(Timeout::None);
    }
    v.parse()
        .map(Timeout::Secs)
        .map_err(|_| format!("{what}: expected a number of seconds or \"none\", got {v:?}"))
}

pub fn parse_violation(what: &str, v: &str) -> Result<Violation, String> {
    match v {
        "errno" => Ok(Violation::Errno),
        "kill" => Ok(Violation::Kill),
        _ => Err(format!("{what}: expected errno or kill, got {v:?}")),
    }
}

/// `RULE[,RULE...]`, see [`parse_egress_rule`].
pub fn parse_egress_list(what: &str, s: &str) -> Result<Vec<EgressRule>, String> {
    s.split(',')
        .map(|r| parse_egress_rule(r).map_err(|e| format!("{what}: {e}")))
        .collect()
}

/// `DOMAIN:PORT[+PORT...]`, `CIDR:PORT[+PORT...]` or `[IPV6-CIDR]:PORT[+PORT...]`.
pub fn parse_egress_rule(s: &str) -> Result<EgressRule, String> {
    let (target, ports) = if let Some(rest) = s.strip_prefix('[') {
        let (t, p) = rest
            .split_once("]:")
            .ok_or_else(|| format!("egress rule {s:?}: expected [IPV6/PREFIX]:PORT"))?;
        (t, p)
    } else {
        s.rsplit_once(':')
            .ok_or_else(|| format!("egress rule {s:?}: expected HOST-OR-CIDR:PORT[+PORT...]"))?
    };
    if target.is_empty() {
        return Err(format!("egress rule {s:?}: missing host or CIDR"));
    }
    let ports = ports
        .split('+')
        .map(|p| {
            p.parse::<u16>()
                .map_err(|_| format!("egress rule {s:?}: bad port {p:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rule = if target.contains('/') {
        EgressRule {
            cidr: Some(target.to_string()),
            domain: None,
            ports,
        }
    } else {
        EgressRule {
            cidr: None,
            domain: Some(target.to_string()),
            ports,
        }
    };
    rule.compile().map_err(|e| format!("egress rule {s:?}: {e}"))?;
    Ok(rule)
}

/// A limit is never 0, and `n << shift` (MiB to bytes) must fit in a u64.
fn check_limit(name: &str, v: Limit, shift: u32, errs: &mut Vec<String>) {
    if let Limit::Value(n) = v {
        if n == 0 {
            errs.push(format!("{name} = 0 is not allowed"));
        } else if n.checked_shl(shift).filter(|s| s >> shift == n).is_none() {
            errs.push(format!("{name} = {n} is too large"));
        }
    }
}

impl Policy {
    pub fn parse(src: &str, origin: &Path) -> Result<Self, String> {
        toml::from_str(src).map_err(|e| {
            let hint = if e.message().contains("missing field `cgroup`") {
                "\nhint: [cgroup] is new in sbx v0.3; add it with mode = \"off\" to keep v0.2's behaviour"
            } else if e.message().contains("missing field `measure`") {
                "\nhint: [measure] is new in sbx v0.4 and [measure.series] in v0.5; add [measure] with \
                 memory_sample_ms = 0 and tmpfs = [], and [measure.series] with mode = \"off\", to keep v0.3's \
                 behaviour"
            } else if e.message().contains("missing field `series`") {
                "\nhint: [measure.series] is new in sbx v0.5; add it with mode = \"off\" to keep v0.4's behaviour"
            } else if e.message().contains("missing field `notify`") {
                "\nhint: seccomp.notify is new in sbx v0.6; add notify = \"listener\" to [seccomp] to keep v0.5's \
                 behaviour"
            } else {
                ""
            };
            format!("invalid policy {}: {e}{hint}", origin.display())
        })
    }

    /// Load the policy file named by the overrides, apply the overrides and
    /// validate the result. Returns the policy and its warnings, or every error.
    pub fn resolve(ov: Overrides) -> Result<(Self, Vec<String>), Vec<String>> {
        let file = ov.policy_file.clone().ok_or_else(|| {
            vec!["no policy file: pass --policy FILE or set SBX_POLICY_FILE (sbx has no built-in policy)".to_string()]
        })?;
        let src = std::fs::read_to_string(&file)
            .map_err(|e| vec![format!("cannot read policy file {}: {e}", file.display())])?;
        let mut p = Policy::parse(&src, &file).map_err(|e| vec![e])?;
        p.apply(ov).map_err(|e| vec![e])?;
        let warnings = p.validate()?;
        Ok((p, warnings))
    }

    fn apply(&mut self, ov: Overrides) -> Result<(), String> {
        for (paths, access) in [(ov.ro, "r"), (ov.rw, "rw"), (ov.rx, "rx")] {
            for path in paths {
                self.fs.push(FsRule {
                    path,
                    access: access.into(),
                });
            }
        }
        if let Some(n) = ov.net {
            self.network.mode = n;
        }
        self.network.egress.extend(ov.egress);
        if let Some(t) = ov.timeout {
            self.process.timeout_secs = t;
        }
        if let Some(w) = ov.workdir {
            self.process.workdir = w;
        }
        if let Some(s) = ov.subprocesses {
            self.process.subprocesses = s;
        }
        self.env.pass.extend(ov.env_pass);
        if let Some(v) = ov.on_violation {
            self.seccomp.on_violation = v;
        }
        Ok(())
    }

    /// Parsed egress rules. Only valid after [`Policy::validate`] succeeded.
    pub fn egress_rules(&self) -> Vec<CompiledRule> {
        self.network.egress.iter().filter_map(|r| r.compile().ok()).collect()
    }

    /// Hard errors for anything inconsistent, unenforceable or ambiguous;
    /// warnings for risky settings that are nonetheless explicit.
    pub fn validate(&self) -> Result<Vec<String>, Vec<String>> {
        let mut errs = Vec::new();
        let mut warn = Vec::new();
        self.validate_landlock(&mut errs, &mut warn);
        self.validate_fs(&mut errs, &mut warn);
        self.validate_process(&mut errs);
        self.validate_limits(&mut errs);
        self.validate_measure(&mut errs);
        self.validate_env(&mut errs);
        self.validate_network(&mut errs, &mut warn);
        self.validate_seccomp(&mut errs, &mut warn);
        if errs.is_empty() {
            Ok(warn)
        } else {
            Err(errs)
        }
    }

    fn validate_landlock(&self, errs: &mut Vec<String>, warn: &mut Vec<String>) {
        let LandlockAbi::V(abi) = self.landlock.abi else {
            self.validate_without_landlock(errs, warn);
            return;
        };
        if !(1..=MAX_LANDLOCK_ABI).contains(&abi) {
            errs.push(format!(
                "landlock.abi must be between 1 and {MAX_LANDLOCK_ABI}, got {abi}"
            ));
        }
        if (self.landlock.scope_signals || self.landlock.scope_abstract_unix) && abi < 6 {
            errs.push(format!(
                "landlock.scope_signals/scope_abstract_unix need landlock.abi >= 6 (Linux 6.12), but abi = {abi}; \
                 set them to false or raise abi"
            ));
        }
        if self.network.mode != NetMode::Unrestricted && abi < 4 {
            errs.push(format!(
                "network.mode = {:?} needs landlock.abi >= 4 (Linux 6.7) so the kernel denies TCP connect/bind \
                 from the sandbox, but abi = {abi}",
                self.network.mode
            ));
        }
    }

    /// landlock.abi = "off": refuse every setting that only Landlock can
    /// enforce, so nothing in the policy promises more than sbx delivers.
    fn validate_without_landlock(&self, errs: &mut Vec<String>, warn: &mut Vec<String>) {
        if self.landlock.scope_signals || self.landlock.scope_abstract_unix {
            errs.push(
                "landlock.scope_signals/scope_abstract_unix need Landlock, but landlock.abi = \"off\"; \
                 set them to false"
                    .into(),
            );
        }
        if !self.fs.is_empty() {
            let paths: Vec<String> = self.fs.iter().map(|r| r.path.display().to_string()).collect();
            errs.push(format!(
                "fs rules need Landlock, but landlock.abi = \"off\": the program can access every file its uid \
                 can, so remove the rules for {} (including --ro/--rw/--rx and SBX_FS_*)",
                paths.join(", ")
            ));
        }
        if self.network.mode == NetMode::Egress && !self.network.bind_tcp.is_empty() {
            errs.push(
                "network.bind_tcp needs Landlock, but landlock.abi = \"off\" (bind and listen are then denied \
                 in egress mode); remove the ports"
                    .into(),
            );
        }
        warn.push(format!(
            "landlock.abi = \"off\": files are protected by their permissions only, so make sure nothing \
             uid {} must not read is world-readable; sbx must start as root and no other process may run \
             as uid {}",
            self.process.uid, self.process.uid
        ));
    }

    fn validate_fs(&self, errs: &mut Vec<String>, warn: &mut Vec<String>) {
        let mut seen = BTreeSet::new();
        for r in &self.fs {
            let p = r.path.display();
            if !r.path.is_absolute() {
                errs.push(format!("fs rule {p}: path must be absolute"));
                continue;
            }
            if !seen.insert(r.path.clone()) {
                errs.push(format!(
                    "fs rule {p} appears more than once; merge the access letters into one rule"
                ));
            }
            let letters: BTreeSet<char> = r.access.chars().collect();
            if r.access.is_empty()
                || !r.access.chars().all(|c| matches!(c, 'r' | 'w' | 'x'))
                || letters.len() != r.access.len()
            {
                errs.push(format!(
                    "fs rule {p}: access must be a combination of r, w and x, got {:?}",
                    r.access
                ));
            }
            if r.path == Path::new("/") && r.access.contains('w') {
                errs.push("fs rule /: write access to / defeats the filesystem sandbox".into());
            }
            if r.access.contains('w') && r.access.contains('x') {
                warn.push(format!(
                    "fs rule {p}: 'w' and 'x' together let the program write and run new binaries"
                ));
            }
            match std::fs::canonicalize(&r.path) {
                Err(e) => errs.push(format!("fs rule {p}: {e}")),
                Ok(c) if c != r.path => errs.push(format!(
                    "fs rule {p} is not canonical: it resolves to {}; write the resolved path",
                    c.display()
                )),
                Ok(_) => {}
            }
        }
    }

    /// The fs rule granting `letter` on `path` or one of its ancestors. With
    /// Landlock off only file permissions apply, so every path counts.
    pub fn covered(&self, path: &Path, letter: char) -> bool {
        self.landlock.abi == LandlockAbi::Off
            || self
                .fs
                .iter()
                .any(|r| path.starts_with(&r.path) && r.access.contains(letter))
    }

    fn validate_process(&self, errs: &mut Vec<String>) {
        let pr = &self.process;
        if pr.uid == 0 || pr.gid == 0 {
            errs.push("process.uid and process.gid must not be 0: the sandbox never runs as root".into());
        }
        let w = &pr.workdir;
        if !w.is_absolute() {
            errs.push(format!("process.workdir {} must be absolute", w.display()));
        } else {
            match std::fs::canonicalize(w) {
                Err(e) => errs.push(format!("process.workdir {}: {e}", w.display())),
                Ok(c) if &c != w => errs.push(format!(
                    "process.workdir {} is not canonical: it resolves to {}",
                    w.display(),
                    c.display()
                )),
                Ok(c) if !c.is_dir() => errs.push(format!("process.workdir {} is not a directory", w.display())),
                Ok(_) => {}
            }
            if !self.covered(w, 'r') {
                errs.push(format!(
                    "process.workdir {} is not readable in the sandbox: add an fs rule with 'r' for it",
                    w.display()
                ));
            }
        }
        if pr.timeout_secs == Timeout::Secs(0) {
            errs.push("process.timeout_secs = 0 is not allowed; use \"none\" for no limit".into());
        }
    }

    fn validate_limits(&self, errs: &mut Vec<String>) {
        let l = &self.limits;
        if l.nofile == 0 {
            errs.push("limits.nofile must be at least 1".into());
        }
        check_limit("limits.nproc", l.nproc, 0, errs);
        check_limit("limits.fsize_mb", l.fsize_mb, 20, errs);
        check_limit("limits.as_mb", l.as_mb, 20, errs);
        check_limit("limits.cpu_secs", l.cpu_secs, 0, errs);
        if let CgroupCfg::Delegated { memory_mb, pids } = self.cgroup {
            check_limit("cgroup.memory_mb", memory_mb, 20, errs);
            check_limit("cgroup.pids", pids, 0, errs);
        }
    }

    fn validate_measure(&self, errs: &mut Vec<String>) {
        let MeasureCfg::Sampled {
            interval_ms,
            tmpfs,
            series,
        } = &self.measure
        else {
            return;
        };
        if interval_ms.get() > MAX_SAMPLE_MS {
            errs.push(format!(
                "measure.memory_sample_ms must be at most {MAX_SAMPLE_MS}, got {interval_ms}"
            ));
        }
        if let SeriesCfg::On {
            max_samples,
            max_processes,
            ..
        } = series
        {
            if max_samples.get() > MAX_SERIES_SAMPLES {
                errs.push(format!(
                    "measure.series.max_samples must be at most {MAX_SERIES_SAMPLES}, got {max_samples}"
                ));
            }
            if *max_processes > MAX_SERIES_PROCESSES {
                errs.push(format!(
                    "measure.series.max_processes must be at most {MAX_SERIES_PROCESSES}, got {max_processes}"
                ));
            }
            let bound = crate::series::bound(*max_samples, tmpfs.len(), *max_processes);
            if bound > SERIES_CEILING_BYTES {
                errs.push(format!(
                    "measure.series: max_samples = {max_samples} and max_processes = {max_processes} with {} tmpfs \
                     mount(s) may take up to {} MiB, above sbx's ceiling of {} MiB; lower max_samples or \
                     max_processes",
                    tmpfs.len(),
                    bound.div_ceil(1 << 20),
                    SERIES_CEILING_BYTES >> 20
                ));
            }
        }
        let mut seen = BTreeSet::new();
        let mut filesystems: BTreeMap<u64, &Path> = BTreeMap::new();
        for t in tmpfs {
            let p = t.display();
            if !t.is_absolute() {
                errs.push(format!("measure.tmpfs {p}: path must be absolute"));
                continue;
            }
            if !seen.insert(t) {
                errs.push(format!("measure.tmpfs lists {p} more than once"));
                continue;
            }
            match std::fs::canonicalize(t) {
                Err(e) => errs.push(format!("measure.tmpfs {p}: {e}")),
                Ok(c) if &c != t => errs.push(format!(
                    "measure.tmpfs {p} is not canonical: it resolves to {}; write the resolved path",
                    c.display()
                )),
                Ok(_) => match crate::memory::tmpfs_mount(t) {
                    Err(e) => errs.push(format!("measure.tmpfs {p}: {e}")),
                    Ok(dev) => {
                        if let Some(other) = filesystems.insert(dev, t) {
                            errs.push(format!(
                                "measure.tmpfs {p} and {} are the same filesystem; list it once",
                                other.display()
                            ));
                        }
                    }
                },
            }
        }
    }

    fn validate_env(&self, errs: &mut Vec<String>) {
        let valid = |n: &str| !n.is_empty() && !n.contains('=') && !n.contains('\0');
        let mut seen = BTreeSet::new();
        for n in &self.env.pass {
            if !valid(n) {
                errs.push(format!("env.pass: invalid variable name {n:?}"));
            }
            if !seen.insert(n) {
                errs.push(format!("env.pass lists {n} more than once"));
            }
            if self.env.set.contains_key(n) {
                errs.push(format!("env variable {n} is both passed through and set; keep one"));
            }
        }
        for (k, v) in &self.env.set {
            if !valid(k) {
                errs.push(format!("env.set: invalid variable name {k:?}"));
            }
            if v.contains('\0') {
                errs.push(format!("env.set.{k} contains a NUL byte"));
            }
        }
    }

    fn validate_network(&self, errs: &mut Vec<String>, warn: &mut Vec<String>) {
        let n = &self.network;
        if n.mode != NetMode::Egress {
            if !n.bind_tcp.is_empty() {
                errs.push(format!(
                    "network.bind_tcp is only used with mode = \"egress\" (mode is {:?})",
                    n.mode
                ));
            }
            if !n.egress.is_empty() {
                errs.push(format!(
                    "network.egress rules are only used with mode = \"egress\" (mode is {:?})",
                    n.mode
                ));
            }
            if n.dns.is_some() {
                errs.push(format!(
                    "[network.dns] is only used with mode = \"egress\" (mode is {:?})",
                    n.mode
                ));
            }
            if n.mode == NetMode::Unrestricted {
                warn.push(
                    "network: unrestricted mode lets the sandbox reach any host, including the cloud metadata \
                     server and its service-account token"
                        .into(),
                );
            }
            return;
        }
        match self.seccomp.notify {
            Notify::Listener => {}
            Notify::Off => errs.push(
                "network.mode = \"egress\" needs seccomp.notify = \"listener\": the supervisor decides every \
                 connect() through the listener"
                    .into(),
            ),
        }
        if n.egress.is_empty() && n.bind_tcp.is_empty() {
            errs.push(
                "network.mode = \"egress\" with no egress rules and no bind_tcp ports; use mode = \"none\"".into(),
            );
        }
        let mut seen = BTreeSet::new();
        for &p in &n.bind_tcp {
            if p == 0 {
                errs.push("network.bind_tcp lists port 0".into());
            }
            if !seen.insert(p) {
                errs.push(format!("network.bind_tcp lists port {p} twice"));
            }
        }
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        let mut domains = false;
        for (i, r) in n.egress.iter().enumerate() {
            match r.compile() {
                Err(e) => errs.push(format!("network.egress[{i}]: {e}")),
                Ok(c) => match c.target {
                    EgressTarget::Domain(_) => domains = true,
                    EgressTarget::Cidr(cidr) if cidr.contains(metadata) => warn.push(format!(
                        "network.egress[{i}]: {cidr} includes the cloud metadata server 169.254.169.254, \
                         which hands out the service account's access token"
                    )),
                    EgressTarget::Cidr(_) => {}
                },
            }
        }
        match (&n.dns, domains) {
            (None, true) => errs.push("network.egress names a domain, so [network.dns] is required".into()),
            (Some(_), false) => errs.push("[network.dns] is set but no network.egress rule names a domain".into()),
            (Some(d), true) => self.validate_dns(d, errs),
            (None, false) => {}
        }
    }

    fn validate_dns(&self, d: &DnsCfg, errs: &mut Vec<String>) {
        if !d.listen.ip().is_loopback() || d.listen.port() != 53 {
            errs.push(format!(
                "network.dns.listen {} must be a loopback address on port 53 (resolv.conf cannot name another port)",
                d.listen
            ));
        }
        if d.upstream.port() == 0 {
            errs.push(format!("network.dns.upstream {} has port 0", d.upstream));
        }
        if d.upstream == d.listen {
            errs.push("network.dns.upstream must not be the proxy itself".into());
        }
        if !(1..=60_000).contains(&d.timeout_ms) {
            errs.push(format!(
                "network.dns.timeout_ms must be between 1 and 60000, got {}",
                d.timeout_ms
            ));
        }
        if d.answer_scopes.is_empty() {
            errs.push("network.dns.answer_scopes must list at least one of global, private, loopback".into());
        }
        let uniq: BTreeSet<_> = d.answer_scopes.iter().map(|s| format!("{s:?}")).collect();
        if uniq.len() != d.answer_scopes.len() {
            errs.push("network.dns.answer_scopes lists a scope twice".into());
        }
        match std::fs::canonicalize(RESOLV_CONF) {
            Err(e) => errs.push(format!("{RESOLV_CONF}: {e}")),
            Ok(c) => {
                if !self.covered(&c, 'r') {
                    errs.push(format!(
                        "the DNS proxy needs the sandbox to read {RESOLV_CONF} ({}): add an fs rule with 'r' for it",
                        c.display()
                    ));
                }
                if d.resolv_conf == ResolvConfMode::Write && c != Path::new(RESOLV_CONF) {
                    errs.push(format!(
                        "network.dns.resolv_conf = \"write\" but {RESOLV_CONF} is a symlink to {}; sbx does not \
                         write through symlinks (use \"verify\" and configure the file yourself)",
                        c.display()
                    ));
                }
            }
        }
    }

    fn validate_seccomp(&self, errs: &mut Vec<String>, warn: &mut Vec<String>) {
        let s = &self.seccomp;
        let mut seen = BTreeSet::new();
        for name in &s.deny {
            if !seen.insert(name) {
                errs.push(format!("seccomp.deny lists {name} twice"));
            }
            if seccomp_layer::lookup(name).is_none() {
                errs.push(format!("seccomp.deny: unknown or unsupported syscall {name:?}"));
            }
            if let Some(why) = seccomp_layer::reserved(name, s.notify) {
                errs.push(format!("seccomp.deny must not include {name}: sbx needs it {why}"));
            }
        }
        match (s.notify, s.on_violation) {
            (Notify::Listener, _) => {}
            (Notify::Off, Violation::Errno) => warn.push(
                "seccomp.notify = \"off\": a denied syscall fails with EPERM, and is neither logged nor counted \
                 (the report's denials is null); on_violation = \"kill\" at least shows it, as SIGSYS"
                    .into(),
            ),
            (Notify::Off, Violation::Kill) => warn.push(
                "seccomp.notify = \"off\": a denied syscall kills the process with SIGSYS (signal 31), and is \
                 neither logged nor counted (the report's denials is null)"
                    .into(),
            ),
        }
        let mut seen = BTreeSet::new();
        for name in &s.allow {
            if !seen.insert(name) {
                errs.push(format!("seccomp.allow lists {name} twice"));
            }
            if !seccomp_layer::is_default_denied(name) {
                errs.push(format!("seccomp.allow: {name:?} is not one of the built-in denials"));
            } else {
                warn.push(format!("seccomp.allow lifts the built-in denial of {name}"));
            }
            if s.deny.contains(name) {
                errs.push(format!("{name} is in both seccomp.allow and seccomp.deny"));
            }
        }
        let fams: BTreeSet<SocketFamily> = s.socket_families.iter().copied().collect();
        if fams.len() != s.socket_families.len() {
            errs.push("seccomp.socket_families lists a family twice".into());
        }
        let ip = fams.contains(&SocketFamily::Inet) || fams.contains(&SocketFamily::Inet6);
        match self.network.mode {
            NetMode::None if ip => {
                errs.push("seccomp.socket_families includes inet/inet6 but network.mode = \"none\"; remove them".into())
            }
            NetMode::Egress | NetMode::Unrestricted if !ip => errs.push(format!(
                "network.mode = {:?} needs inet and/or inet6 in seccomp.socket_families",
                self.network.mode
            )),
            _ => {}
        }
        for f in [SocketFamily::Packet, SocketFamily::Vsock] {
            if fams.contains(&f) {
                if self.network.mode == NetMode::Unrestricted {
                    warn.push(format!("seccomp.socket_families allows {f:?} sockets"));
                } else {
                    errs.push(format!(
                        "seccomp.socket_families must not include {f:?} unless network.mode = \"unrestricted\": \
                         it would bypass network.mode"
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub const MINIMAL: &str = r#"
[landlock]
abi = 4
scope_signals = false
scope_abstract_unix = false

[process]
uid = 65534
gid = 65534
workdir = "/tmp"
timeout_secs = "none"
kill_grace_secs = 5
subprocesses = true

[limits]
nofile = 1024
nproc = 512
fsize_mb = 1024
as_mb = "unlimited"
cpu_secs = "unlimited"

[cgroup]
mode = "off"

[measure]
memory_sample_ms = 0
tmpfs = []

[measure.series]
mode = "off"

[env]
pass = []
[env.set]
PATH = "/usr/bin:/bin"

[network]
mode = "none"
bind_tcp = []
egress = []

[seccomp]
notify = "listener"
on_violation = "errno"
deny = []
allow = []
socket_families = ["unix"]

[[fs]]
path = "/tmp"
access = "rw"
"#;

    /// A temporary directory removed when dropped.
    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmpdir() -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "sbx-policy-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&d).unwrap();
        TempDir(std::fs::canonicalize(d).unwrap())
    }

    fn parse(src: &str) -> Result<Policy, String> {
        Policy::parse(src, Path::new("test.toml"))
    }

    #[test]
    fn minimal_policy_is_valid() {
        let p = parse(MINIMAL).unwrap();
        assert_eq!(p.validate().unwrap(), Vec::<String>::new());
        assert_eq!(p.process.timeout_secs, Timeout::None);
        assert_eq!(p.limits.as_mb, Limit::Unlimited);
        assert_eq!(p.limits.nproc, Limit::Value(512));
    }

    #[test]
    fn every_field_is_required() {
        for line in [
            "kill_grace_secs = 5",
            "nofile = 1024",
            "pass = []",
            "bind_tcp = []",
            "notify = \"listener\"",
            "on_violation = \"errno\"",
            "mode = \"off\"",
            "memory_sample_ms = 0",
            "tmpfs = []",
        ] {
            let src = MINIMAL.replacen(line, "", 1);
            let e = parse(&src).unwrap_err();
            assert!(e.contains("missing field"), "{line}: {e}");
        }
    }

    #[test]
    fn unknown_fields_and_removed_options_are_rejected() {
        for (anchor, extra) in [
            ("[landlock]", "required = true"),
            ("[landlock]", "min_abi = 1"),
            ("[network]", "allow_udp = false"),
            ("[seccomp]", "enabled = true"),
        ] {
            let src = MINIMAL.replacen(anchor, &format!("{anchor}\n{extra}"), 1);
            assert!(parse(&src).unwrap_err().contains("unknown field"), "{extra}");
        }
        let src = MINIMAL.replacen("access = \"rw\"", "access = \"rw\"\noptional = true", 1);
        assert!(parse(&src).unwrap_err().contains("unknown field"));
        let src = MINIMAL.replacen("on_violation = \"errno\"", "on_violation = \"log\"", 1);
        assert!(parse(&src).is_err());
        let src = MINIMAL.replacen("mode = \"none\"", "mode = \"restricted\"", 1);
        assert!(parse(&src).is_err());
    }

    #[test]
    fn the_cgroup_table_is_required_with_an_upgrade_hint() {
        let src = MINIMAL.replacen("[cgroup]\nmode = \"off\"\n", "", 1);
        let e = parse(&src).unwrap_err();
        assert!(
            e.contains("missing field `cgroup`") && e.contains("new in sbx v0.3"),
            "{e}"
        );
    }

    fn with_cgroup(body: &str) -> String {
        MINIMAL.replacen("[cgroup]\nmode = \"off\"", &format!("[cgroup]\n{body}"), 1)
    }

    #[test]
    fn cgroup_limits_exist_only_when_delegated() {
        let err = |body: &str| parse(&with_cgroup(body)).unwrap_err();
        assert!(err("mode = \"off\"\npids = 5").contains("only used with mode"));
        assert!(err("mode = \"delegated\"\nmemory_mb = 512").contains("needs cgroup.pids"));
        assert!(err("mode = \"delegated\"\npids = 5").contains("needs cgroup.memory_mb"));
        assert!(err("mode = \"delegated\"\nmemory_mb = 1\npids = 1\nswap_mb = 0").contains("unknown field"));
        assert!(err("mode = \"on\"").contains("unknown variant"));
        let p = parse(&with_cgroup(
            "mode = \"delegated\"\nmemory_mb = 512\npids = \"unlimited\"",
        ))
        .unwrap();
        assert_eq!(
            p.cgroup,
            CgroupCfg::Delegated {
                memory_mb: Limit::Value(512),
                pids: Limit::Unlimited
            }
        );
    }

    #[test]
    fn cgroup_limits_are_checked_like_rlimits() {
        let errs = |body: &str| parse(&with_cgroup(body)).unwrap().validate().unwrap_err();
        let e = errs("mode = \"delegated\"\nmemory_mb = 0\npids = 1");
        assert!(e.iter().any(|e| e.contains("cgroup.memory_mb = 0")), "{e:?}");
        let e = errs(&format!(
            "mode = \"delegated\"\nmemory_mb = {}\npids = 1",
            u64::MAX >> 10
        ));
        assert!(
            e.iter()
                .any(|e| e.contains("cgroup.memory_mb") && e.contains("too large")),
            "{e:?}"
        );
    }

    fn limit() -> impl proptest::strategy::Strategy<Value = Limit> {
        use proptest::prelude::*;
        prop_oneof![Just(Limit::Unlimited), (0..i64::MAX as u64).prop_map(Limit::Value)]
    }

    proptest::proptest! {
        #[test]
        fn cgroup_settings_survive_sbx_policy(memory_mb in limit(), pids in limit(), delegated: bool) {
            let cg = if delegated { CgroupCfg::Delegated { memory_mb, pids } } else { CgroupCfg::Off };
            let mut p = parse(MINIMAL).unwrap();
            p.cgroup = cg;
            let again = parse(&toml::to_string_pretty(&p).unwrap()).unwrap();
            proptest::prop_assert_eq!(again.cgroup, cg);
        }
    }

    #[test]
    fn the_measure_table_is_required_with_an_upgrade_hint() {
        let src = MINIMAL.replacen(
            "[measure]\nmemory_sample_ms = 0\ntmpfs = []\n\n[measure.series]\nmode = \"off\"\n",
            "",
            1,
        );
        let e = parse(&src).unwrap_err();
        assert!(
            e.contains("missing field `measure`")
                && e.contains("[measure] is new in sbx v0.4")
                && e.contains("[measure.series] with mode = \"off\""),
            "{e}"
        );
    }

    #[test]
    fn the_series_table_is_required_with_an_upgrade_hint() {
        let src = MINIMAL.replacen("[measure.series]\nmode = \"off\"\n", "", 1);
        let e = parse(&src).unwrap_err();
        assert!(
            e.contains("missing field `series`") && e.contains("[measure.series] is new in sbx v0.5"),
            "{e}"
        );
    }

    fn with_measure(body: &str) -> String {
        MINIMAL.replacen(
            "[measure]\nmemory_sample_ms = 0\ntmpfs = []",
            &format!("[measure]\n{body}"),
            1,
        )
    }

    #[test]
    fn tmpfs_mounts_are_measured_only_with_sampling_on() {
        let e = parse(&with_measure("memory_sample_ms = 0\ntmpfs = [\"/dev/shm\"]")).unwrap_err();
        assert!(e.contains("only used when measure.memory_sample_ms"), "{e}");
        let e = parse(&with_measure("memory_sample_ms = 20\ntmpfs = []\nevery = 1")).unwrap_err();
        assert!(e.contains("unknown field"), "{e}");
        let p = parse(&with_measure("memory_sample_ms = 20\ntmpfs = []")).unwrap();
        assert_eq!(
            p.measure,
            MeasureCfg::Sampled {
                interval_ms: NonZeroU64::new(20).unwrap(),
                tmpfs: vec![],
                series: SeriesCfg::Off,
            }
        );
        assert_eq!(parse(MINIMAL).unwrap().measure, MeasureCfg::Off);
    }

    #[test]
    fn measured_tmpfs_paths_must_be_distinct_tmpfs_mounts() {
        let t = tmpdir();
        let errs = |body: &str| parse(&with_measure(body)).unwrap().validate().unwrap_err();
        let e = errs(&format!(
            "memory_sample_ms = 20\ntmpfs = [\"rel\", \"/proc\", \"/proc\", \"{}\", \"{}/missing\"]",
            t.0.display(),
            t.0.display()
        ));
        let has = |s: &str| e.iter().any(|e| e.contains(s));
        assert!(has("rel: path must be absolute"), "{e:?}");
        assert!(has("/proc: is not a tmpfs"), "{e:?}");
        assert!(has("lists /proc more than once"), "{e:?}");
        // A directory, not a mount: either on another filesystem or inside a tmpfs.
        assert!(
            e.iter().any(|e| e.contains(&t.0.display().to_string())
                && (e.contains("is not a tmpfs") || e.contains("not a mount point"))),
            "{e:?}"
        );
        assert!(has("missing: No such file"), "{e:?}");
        let e = errs(&format!("memory_sample_ms = {}\ntmpfs = []", MAX_SAMPLE_MS + 1));
        assert!(e.iter().any(|e| e.contains("at most 60000")), "{e:?}");
    }

    fn series() -> impl proptest::strategy::Strategy<Value = SeriesCfg> {
        use proptest::prelude::*;
        let compression = prop_oneof![Just(SeriesCompression::None), Just(SeriesCompression::Gzip)];
        prop_oneof![
            Just(SeriesCfg::Off),
            (1..=u32::MAX, any::<u32>(), compression).prop_map(|(n, max_processes, compression)| SeriesCfg::On {
                max_samples: NonZeroU32::new(n).unwrap(),
                max_processes,
                compression,
            }),
        ]
    }

    fn measure() -> impl proptest::strategy::Strategy<Value = MeasureCfg> {
        use proptest::prelude::*;
        prop_oneof![
            Just(MeasureCfg::Off),
            (
                1..=i64::MAX as u64,
                prop::collection::vec("/[a-z]{1,8}", 0..4),
                series()
            )
                .prop_map(|(ms, tmpfs, series)| MeasureCfg::Sampled {
                    interval_ms: NonZeroU64::new(ms).unwrap(),
                    tmpfs: tmpfs.into_iter().map(PathBuf::from).collect(),
                    series,
                }),
        ]
    }

    proptest::proptest! {
        #[test]
        fn measure_settings_survive_sbx_policy(m in measure()) {
            let mut p = parse(MINIMAL).unwrap();
            p.measure = m.clone();
            let again = parse(&toml::to_string_pretty(&p).unwrap()).unwrap();
            proptest::prop_assert_eq!(again.measure, m);
        }

        #[test]
        fn series_settings_survive_sbx_policy(s in series(), ms in 1..=MAX_SAMPLE_MS) {
            let mut p = parse(MINIMAL).unwrap();
            p.measure = MeasureCfg::Sampled { interval_ms: NonZeroU64::new(ms).unwrap(), tmpfs: vec![], series: s };
            let src = toml::to_string_pretty(&p).unwrap();
            let again = parse(&src).unwrap();
            proptest::prop_assert_eq!(again.measure.series(), s);
            proptest::prop_assert!(src.contains("[measure.series]"), "{}", src);
        }
    }

    fn with_series(ms: u64, tmpfs: &str, body: &str) -> String {
        MINIMAL.replacen(
            "[measure]\nmemory_sample_ms = 0\ntmpfs = []\n\n[measure.series]\nmode = \"off\"",
            &format!("[measure]\nmemory_sample_ms = {ms}\ntmpfs = {tmpfs}\n\n[measure.series]\n{body}"),
            1,
        )
    }

    #[test]
    fn series_settings_exist_only_when_on() {
        let err = |ms: u64, body: &str| parse(&with_series(ms, "[]", body)).unwrap_err();
        assert!(err(20, "mode = \"off\"\nmax_samples = 5").contains("max_samples is only used with mode = \"on\""));
        assert!(err(20, "mode = \"off\"\nmax_processes = 0").contains("max_processes is only used with mode = \"on\""));
        assert!(
            err(20, "mode = \"off\"\ncompression = \"none\"").contains("compression is only used with mode = \"on\"")
        );
        let gz = "\ncompression = \"gzip\"";
        assert!(err(20, &format!("mode = \"on\"\nmax_processes = 8{gz}")).contains("needs measure.series.max_samples"));
        assert!(err(20, &format!("mode = \"on\"\nmax_samples = 5{gz}")).contains("needs measure.series.max_processes"));
        assert!(err(20, "mode = \"on\"\nmax_samples = 5\nmax_processes = 8")
            .contains("needs measure.series.compression (\"none\" or \"gzip\")"));
        assert!(err(20, &format!("mode = \"on\"\nmax_samples = 0\nmax_processes = 8{gz}")).contains("at least 1"));
        assert!(err(20, &format!("mode = \"on\"\nmax_samples = 5\nmax_processes = -1{gz}")).contains("invalid value"));
        assert!(err(
            20,
            &format!("mode = \"on\"\nmax_samples = 5\nmax_processes = 1{gz}\nmax_rows = 1")
        )
        .contains("unknown field"));
        assert!(err(
            20,
            "mode = \"on\"\nmax_samples = 5\nmax_processes = 1\ncompression = \"zstd\""
        )
        .contains("unknown variant `zstd`"));
        assert!(err(20, "mode = \"sampled\"").contains("unknown variant"));
        assert!(
            err(0, &format!("mode = \"on\"\nmax_samples = 5\nmax_processes = 8{gz}"))
                .contains("needs measure.memory_sample_ms above 0")
        );
        for (word, compression) in [("none", SeriesCompression::None), ("gzip", SeriesCompression::Gzip)] {
            let p = parse(&with_series(
                20,
                "[]",
                &format!("mode = \"on\"\nmax_samples = 5\nmax_processes = 0\ncompression = \"{word}\""),
            ))
            .unwrap();
            assert_eq!(
                p.measure.series(),
                SeriesCfg::On {
                    max_samples: NonZeroU32::new(5).unwrap(),
                    max_processes: 0,
                    compression,
                }
            );
            assert_eq!(p.validate().unwrap(), Vec::<String>::new());
        }
        assert_eq!(parse(MINIMAL).unwrap().measure.series(), SeriesCfg::Off);
    }

    #[test]
    fn series_limits_and_the_memory_ceiling() {
        let errs = |tmpfs: &str, samples: u32, procs: u32| {
            let body =
                format!("mode = \"on\"\nmax_samples = {samples}\nmax_processes = {procs}\ncompression = \"none\"");
            parse(&with_series(20, tmpfs, &body)).unwrap().validate()
        };
        let e = errs("[]", MAX_SERIES_SAMPLES + 1, 0).unwrap_err();
        assert!(
            e.iter().any(|e| e.contains("max_samples must be at most 1000000")),
            "{e:?}"
        );
        let e = errs("[]", 1, MAX_SERIES_PROCESSES + 1).unwrap_err();
        assert!(
            e.iter().any(|e| e.contains("max_processes must be at most 4096")),
            "{e:?}"
        );
        assert!(errs("[]", MAX_SERIES_SAMPLES, 0).is_ok());
        assert!(errs("[]", 1, MAX_SERIES_PROCESSES).is_ok());
        // The example in docs/report.md, with one tmpfs mount measured: the path
        // need not exist for the bound.
        let over = |tmpfs: &str, samples: u32, procs: u32| {
            errs(tmpfs, samples, procs).is_err_and(|e| e.iter().any(|e| e.contains("ceiling")))
        };
        assert!(!over("[\"/sbx-no-such-mount\"]", 50_000, 32));
        // Each listed process may be a new one, so the processes dominate.
        let e = errs("[]", MAX_SERIES_SAMPLES, 32).unwrap_err();
        let ceiling: Vec<&String> = e.iter().filter(|e| e.contains("ceiling of 256 MiB")).collect();
        assert_eq!(ceiling.len(), 1, "{e:?}");
        let mib = crate::series::bound(NonZeroU32::new(MAX_SERIES_SAMPLES).unwrap(), 0, 32).div_ceil(1 << 20);
        assert!(ceiling[0].contains(&format!("up to {mib} MiB")), "{e:?}");
        assert!(ceiling[0].contains("lower max_samples or max_processes"), "{e:?}");
        // Each listed mount adds to every row; the paths need not exist for the bound.
        let many: Vec<String> = (0..32).map(|i| format!("\"/sbx-no-such-mount-{i}\"")).collect();
        let many = format!("[{}]", many.join(", "));
        let e = errs(&many, MAX_SERIES_SAMPLES, 0).unwrap_err();
        assert!(e.iter().any(|e| e.contains("ceiling of 256 MiB")), "{e:?}");
        let e = errs(&many, 1000, 0).unwrap_err();
        assert!(!e.iter().any(|e| e.contains("ceiling")), "{e:?}");
    }

    #[test]
    fn keyword_values() {
        let src = MINIMAL.replacen("as_mb = \"unlimited\"", "as_mb = \"infinite\"", 1);
        assert!(parse(&src).unwrap_err().contains("\"unlimited\""));
        let src = MINIMAL.replacen("timeout_secs = \"none\"", "timeout_secs = 0", 1);
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("timeout_secs = 0")));
        let src = MINIMAL.replacen("nproc = 512", "nproc = -1", 1);
        assert!(parse(&src).unwrap_err().contains("negative"));
    }

    #[test]
    fn landlock_abi_requirements() {
        let src = MINIMAL.replacen("abi = 4", "abi = 3", 1);
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("abi >= 4")), "{errs:?}");
        let src = MINIMAL.replacen("scope_signals = false", "scope_signals = true", 1);
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("abi >= 6")), "{errs:?}");
        let src = MINIMAL.replacen("abi = 4", "abi = 10", 1);
        assert!(parse(&src).unwrap().validate().is_err());
        let src = MINIMAL.replacen("abi = 4", "abi = 300", 1);
        assert!(parse(&src).unwrap_err().contains("out of range"));
        let src = MINIMAL.replacen("abi = 4", "abi = \"none\"", 1);
        assert!(parse(&src).unwrap_err().contains("\"off\""));
    }

    /// MINIMAL with landlock.abi = "off": no scopes and no fs rules (an
    /// empty top-level `fs`, since every field is required).
    pub fn without_landlock(src: &str) -> String {
        let src =
            src.replacen("abi = 4", "abi = \"off\"", 1)
                .replacen("[[fs]]\npath = \"/tmp\"\naccess = \"rw\"\n", "", 1);
        format!("fs = []\n{src}")
    }

    #[test]
    fn landlock_off_is_explicit_and_round_trips() {
        let p = parse(&without_landlock(MINIMAL)).unwrap();
        assert_eq!(p.landlock.abi, LandlockAbi::Off);
        let warn = p.validate().unwrap();
        assert!(warn.iter().any(|w| w.contains("permissions only")), "{warn:?}");
        let again = parse(&toml::to_string_pretty(&p).unwrap()).unwrap();
        assert_eq!(again.landlock.abi, LandlockAbi::Off);
        assert!(again.fs.is_empty());
    }

    #[test]
    fn landlock_off_refuses_what_only_landlock_enforces() {
        let src = without_landlock(MINIMAL);
        let errs = |src: &str| parse(src).unwrap().validate().unwrap_err();
        let e = errs(&src.replacen("scope_signals = false", "scope_signals = true", 1));
        assert!(
            e.iter().any(|e| e.contains("scope_abstract_unix need Landlock")),
            "{e:?}"
        );
        let e = errs(&src.replacen("fs = []", "fs = [{ path = \"/tmp\", access = \"r\" }]", 1));
        assert!(e.iter().any(|e| e.contains("fs rules need Landlock")), "{e:?}");

        let mut p = parse(&src).unwrap();
        p.network.mode = NetMode::Egress;
        p.network.bind_tcp = vec![8080];
        p.seccomp.socket_families = vec![SocketFamily::Unix, SocketFamily::Inet];
        let e = p.validate().unwrap_err();
        assert!(e.iter().any(|e| e.contains("bind_tcp needs Landlock")), "{e:?}");
    }

    #[test]
    fn fs_paths_must_exist_and_be_canonical() {
        let t = tmpdir();
        let d = &t.0;
        let link = d.join("link");
        std::os::unix::fs::symlink(d, &link).unwrap();
        let mut p = parse(MINIMAL).unwrap();
        p.fs.push(FsRule {
            path: link.clone(),
            access: "r".into(),
        });
        p.fs.push(FsRule {
            path: d.join("missing"),
            access: "r".into(),
        });
        p.fs.push(FsRule {
            path: d.clone(),
            access: "rr".into(),
        });
        p.fs.push(FsRule {
            path: PathBuf::from("/tmp"),
            access: "r".into(),
        });
        let errs = p.validate().unwrap_err();
        let has = |s: &str| errs.iter().any(|e| e.contains(s));
        assert!(has("not canonical"), "{errs:?}");
        assert!(has("No such file"), "{errs:?}");
        assert!(has("combination of r, w and x"), "{errs:?}");
        assert!(has("more than once"), "{errs:?}");
    }

    #[test]
    fn workdir_must_be_readable_in_the_sandbox() {
        let t = tmpdir();
        let src = MINIMAL.replacen("workdir = \"/tmp\"", &format!("workdir = \"{}\"", t.0.display()), 1);
        let src = src.replacen("path = \"/tmp\"", "path = \"/proc\"", 1);
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("not readable in the sandbox")),
            "{errs:?}"
        );
        let src =
            without_landlock(MINIMAL).replacen("workdir = \"/tmp\"", &format!("workdir = \"{}\"", t.0.display()), 1);
        assert!(
            parse(&src).unwrap().validate().is_ok(),
            "without Landlock only permissions apply"
        );
    }

    #[test]
    fn network_settings_must_match_the_mode() {
        let src = MINIMAL.replacen("bind_tcp = []", "bind_tcp = [8080]", 1);
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("only used with mode")), "{errs:?}");
        let src = MINIMAL.replacen(
            "socket_families = [\"unix\"]",
            "socket_families = [\"unix\", \"inet\"]",
            1,
        );
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("network.mode = \"none\"")), "{errs:?}");
        let src = MINIMAL.replacen(
            "socket_families = [\"unix\"]",
            "socket_families = [\"unix\", \"vsock\"]",
            1,
        );
        assert!(parse(&src).unwrap().validate().is_err());
    }

    fn egress_policy(rules: &str, dns: &str) -> String {
        // /etc/resolv.conf is a symlink on some hosts (systemd-resolved); grant its target.
        let resolv = std::fs::canonicalize(RESOLV_CONF).unwrap();
        MINIMAL
            .replacen("mode = \"none\"", "mode = \"egress\"", 1)
            .replacen("egress = []", &format!("egress = [{rules}]"), 1)
            .replacen(
                "socket_families = [\"unix\"]",
                "socket_families = [\"unix\", \"inet\", \"inet6\"]",
                1,
            )
            .replacen("[seccomp]", &format!("{dns}\n[seccomp]"), 1)
            .replacen(
                "path = \"/tmp\"\naccess = \"rw\"",
                &format!(
                    "path = \"/tmp\"\naccess = \"rw\"\n[[fs]]\npath = \"{}\"\naccess = \"r\"",
                    resolv.display()
                ),
                1,
            )
    }

    const DNS: &str = r#"
[network.dns]
listen = "127.0.0.53:53"
upstream = "169.254.169.254:53"
upstream_transport = "tcp"
resolv_conf = "verify"
timeout_ms = 2000
answer_scopes = ["global"]
"#;

    #[test]
    fn egress_rules() {
        let src = egress_policy(
            r#"{ cidr = "10.0.0.0/8", ports = [5432] }, { domain = "*.example.com", ports = [443] }"#,
            DNS,
        );
        let p = parse(&src).unwrap();
        p.validate().unwrap();
        assert_eq!(p.egress_rules().len(), 2);

        let src = egress_policy(r#"{ domain = "example.com", ports = [443] }"#, "");
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("[network.dns] is required")), "{errs:?}");

        let src = egress_policy(r#"{ cidr = "10.0.0.0/8", ports = [443] }"#, DNS);
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("no network.egress rule names a domain")),
            "{errs:?}"
        );

        let src = egress_policy(r#"{ cidr = "0.0.0.0/0", ports = [80] }"#, "");
        let warn = parse(&src).unwrap().validate().unwrap();
        assert!(warn.iter().any(|w| w.contains("metadata server")), "{warn:?}");

        for bad in [
            r#"{ cidr = "10.0.0.0/8", domain = "a.com", ports = [1] }"#,
            r#"{ ports = [1] }"#,
            r#"{ cidr = "10.0.0.1/8", ports = [1] }"#,
            r#"{ cidr = "10.0.0.0/8", ports = [] }"#,
            r#"{ cidr = "10.0.0.0/8", ports = [0] }"#,
            r#"{ domain = "1.2.3.4", ports = [1] }"#,
        ] {
            let src = egress_policy(bad, "");
            assert!(parse(&src).unwrap().validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn dns_listen_must_be_loopback_port_53() {
        let src = egress_policy(
            r#"{ domain = "example.com", ports = [443] }"#,
            &DNS.replacen("127.0.0.53:53", "0.0.0.0:53", 1),
        );
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("loopback address on port 53")),
            "{errs:?}"
        );
    }

    #[test]
    fn seccomp_names() {
        let src = MINIMAL.replacen("deny = []", "deny = [\"execve\"]", 1);
        let errs = parse(&src).unwrap().validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("must not include execve")), "{errs:?}");
        let src = MINIMAL.replacen("deny = []", "deny = [\"no_such_call\"]", 1);
        assert!(parse(&src).unwrap().validate().is_err());
        let src = MINIMAL.replacen("allow = []", "allow = [\"read\"]", 1);
        assert!(parse(&src).unwrap().validate().is_err());
        let src = MINIMAL.replacen("allow = []", "allow = [\"ptrace\"]", 1);
        let warn = parse(&src).unwrap().validate().unwrap();
        assert!(warn.iter().any(|w| w.contains("ptrace")));
    }

    fn without_listener(src: &str, on_violation: &str) -> String {
        src.replacen("notify = \"listener\"", "notify = \"off\"", 1).replacen(
            "on_violation = \"errno\"",
            &format!("on_violation = \"{on_violation}\""),
            1,
        )
    }

    #[test]
    fn the_notify_key_is_required_with_an_upgrade_hint() {
        let e = parse(&MINIMAL.replacen("notify = \"listener\"\n", "", 1)).unwrap_err();
        assert!(
            e.contains("missing field `notify`")
                && e.contains("new in sbx v0.6")
                && e.contains("notify = \"listener\""),
            "{e}"
        );
        let e = parse(&MINIMAL.replacen("notify = \"listener\"", "notify = \"on\"", 1)).unwrap_err();
        assert!(e.contains("unknown variant"), "{e}");
    }

    #[test]
    fn sendmsg_is_reserved_only_with_the_listener() {
        let deny = |src: &str, names: &str| {
            parse(&src.replacen("deny = []", &format!("deny = [{names}]"), 1))
                .unwrap()
                .validate()
        };
        let errs = deny(MINIMAL, "\"sendmsg\"").unwrap_err();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].contains("must not include sendmsg") && errs[0].contains("listener"),
            "{errs:?}"
        );
        let off = without_listener(MINIMAL, "kill");
        deny(&off, "\"sendmsg\"").unwrap();
        for src in [MINIMAL, off.as_str()] {
            let errs = deny(src, "\"execve\"").unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| e.contains("must not include execve") && e.contains("start the program")),
                "{errs:?}"
            );
        }
    }

    #[test]
    fn seccomp_deny_accepts_the_ipc_calls() {
        let src = MINIMAL.replacen("deny = []", r#"deny = ["msgget", "mq_open", "semget", "shmget"]"#, 1);
        assert_eq!(parse(&src).unwrap().validate().unwrap(), Vec::<String>::new());
        let w = parse(&without_listener(&src, "kill")).unwrap().validate().unwrap();
        assert!(
            w.len() == 1 && w[0].contains("seccomp.notify = \"off\""),
            "only the warning that denials are not seen: {w:?}"
        );
    }

    #[test]
    fn egress_needs_the_listener() {
        let src = egress_policy(r#"{ cidr = "10.0.0.0/8", ports = [5432] }"#, "");
        parse(&src).unwrap().validate().unwrap();
        for v in ["errno", "kill"] {
            let errs = parse(&without_listener(&src, v)).unwrap().validate().unwrap_err();
            assert_eq!(errs.len(), 1, "{errs:?}");
            assert!(errs[0].contains("needs seccomp.notify = \"listener\""), "{errs:?}");
        }
    }

    #[test]
    fn without_the_listener_sbx_warns_that_denials_are_not_seen() {
        let warn = |v| parse(&without_listener(MINIMAL, v)).unwrap().validate().unwrap();
        let w = warn("errno");
        assert!(
            w.len() == 1 && w[0].contains("fails with EPERM") && w[0].contains("neither logged nor counted"),
            "{w:?}"
        );
        let w = warn("kill");
        assert!(
            w.len() == 1 && w[0].contains("SIGSYS") && w[0].contains("denials is null"),
            "{w:?}"
        );
    }

    #[test]
    fn env_values_parse_strictly() {
        assert_eq!(parse_bool("X", "true"), Ok(true));
        assert!(parse_bool("X", "1").is_err());
        assert!(parse_bool("X", "yes").is_err());
        assert!(split_paths("X", "/a::/b").is_err());
        assert_eq!(split_paths("X", "/a:/b").unwrap().len(), 2);
        assert!(parse_net("X", "all").is_err());
        assert_eq!(parse_timeout("X", "none"), Ok(Timeout::None));
        assert!(parse_timeout("X", "-1").is_err());
        assert!(parse_violation("X", "log").is_err());
    }

    #[test]
    fn egress_rule_syntax() {
        let r = parse_egress_rule("api.github.com:443").unwrap();
        assert_eq!(r.domain.as_deref(), Some("api.github.com"));
        assert_eq!(r.ports, vec![443]);
        let r = parse_egress_rule("10.0.0.0/8:80+443").unwrap();
        assert_eq!(r.cidr.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(r.ports, vec![80, 443]);
        let r = parse_egress_rule("[2001:db8::/32]:443").unwrap();
        assert_eq!(r.cidr.as_deref(), Some("2001:db8::/32"));
        assert!(parse_egress_rule("1.2.3.4:443").is_err());
        assert!(parse_egress_rule("example.com").is_err());
        assert!(parse_egress_rule("example.com:http").is_err());
        assert!(parse_egress_rule(":443").is_err());
        assert_eq!(parse_egress_list("X", "a.com:1,10.0.0.0/8:2").unwrap().len(), 2);
    }

    #[test]
    fn overrides_merge_flags_over_env() {
        let env = Overrides {
            timeout: Some(Timeout::Secs(5)),
            ro: vec!["/a".into()],
            ..Default::default()
        };
        let flags = Overrides {
            timeout: Some(Timeout::Secs(9)),
            ro: vec!["/b".into()],
            ..Default::default()
        };
        let m = env.merge(flags);
        assert_eq!(m.timeout, Some(Timeout::Secs(9)));
        assert_eq!(m.ro, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn serializes_back_to_toml() {
        let p = parse(MINIMAL).unwrap();
        let out = toml::to_string_pretty(&p).unwrap();
        let again = parse(&out).unwrap();
        assert_eq!(again.limits.as_mb, Limit::Unlimited);
        assert_eq!(again.process.timeout_secs, Timeout::None);
    }
}
