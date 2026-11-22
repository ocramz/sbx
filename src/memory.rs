//! Memory by kind (`[measure] memory_sample_ms`): what the sandbox holds,
//! sampled while the program runs, for the report's `memory`.
//!
//! `ru_maxrss` counts the file pages of a program's binary and libraries,
//! and misses memory that no process maps: an unmapped memfd, a tmpfs or
//! /dev/shm file, a detached SysV segment. Each sample therefore reads, for
//! every live sandbox process, the resident set by kind (/proc/<pid>/status)
//! and the memfds it holds (/proc/<pid>/fd), and once per sample the
//! sandbox's SysV segments (/proc/sysvipc/shm), the use of the policy's
//! tmpfs mounts, and with a delegated cgroup its memory.stat. The peaks are
//! lower bounds: whatever rises and falls between two samples is missed.
//!
//! With `--series FILE` and `[measure.series]` on, the samples themselves
//! are kept as well ([`crate::series`]).
//!
//! The parsers, [`Peaks`], [`Tracker`] and [`Tally`] are pure; [`Sampler`]
//! does the IO.

use crate::cgroup::{self, Delegation};
use crate::log::{self, os_err};
use crate::policy::MeasureCfg;
use crate::procfs;
use crate::series::{MemorySeries, SeriesSpec, When};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fmt::{self, Display};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub type Pid = libc::pid_t;

const SYSVIPC_SHM: &str = "/proc/sysvipc/shm";
const TMPFS_MAGIC: u32 = 0x0102_1994;

// ---------------------------------------------------------------- pure

/// One process's resident set by kind, from /proc/<pid>/status (KiB).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcMem {
    pub anon_kib: u64,
    pub file_kib: u64,
    pub shmem_kib: u64,
}

impl ProcMem {
    /// None when the fields are missing: a zombie, or a kernel before 4.5.
    pub fn parse_status(status: &[u8]) -> Option<ProcMem> {
        let field = |name: &str| -> Option<u64> {
            procfs::status_text(status, name)?
                .strip_suffix("kB")?
                .trim_end()
                .parse()
                .ok()
        };
        Some(ProcMem {
            anon_kib: field("RssAnon:")?,
            file_kib: field("RssFile:")?,
            shmem_kib: field("RssShmem:")?,
        })
    }
}

/// The sandbox cgroup's memory.stat counters sbx reports (bytes). `shmem`
/// counts memfd, tmpfs and SysV pages charged to the cgroup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CgroupMem {
    pub anon_bytes: u64,
    pub shmem_bytes: u64,
}

impl CgroupMem {
    pub fn parse(memory_stat: &str) -> Result<CgroupMem, String> {
        let get = |k: &str| cgroup::keyed(memory_stat, k).ok_or_else(|| format!("memory.stat has no {k}"));
        Ok(CgroupMem {
            anon_bytes: get("anon")?,
            shmem_bytes: get("shmem")?,
        })
    }

    fn join(self, o: CgroupMem) -> CgroupMem {
        CgroupMem {
            anon_bytes: self.anon_bytes.max(o.anon_bytes),
            shmem_bytes: self.shmem_bytes.max(o.shmem_bytes),
        }
    }
}

/// One line of /proc/sysvipc/shm, the fields sbx uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShmSeg {
    /// The creator's pid.
    pub cpid: Pid,
    /// The owner, which the owner can change with IPC_SET.
    pub uid: u32,
    /// The creator, which nobody can change.
    pub cuid: u32,
    /// Resident bytes, attached or not.
    pub rss_bytes: u64,
}

/// /proc/sysvipc/shm: a header line naming the columns, then one segment per line.
pub fn parse_sysvipc_shm(s: &str) -> Result<Vec<ShmSeg>, String> {
    let mut lines = s.lines();
    let header: Vec<&str> = lines.next().ok_or("it is empty")?.split_whitespace().collect();
    let col = |name: &str| {
        header
            .iter()
            .position(|h| *h == name)
            .ok_or_else(|| format!("no {name} column in {header:?}"))
    };
    let (cpid, uid, cuid, rss) = (col("cpid")?, col("uid")?, col("cuid")?, col("rss")?);
    lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() != header.len() {
                return Err(format!("{} fields under {} columns: {l:?}", f.len(), header.len()));
            }
            let num = |i: usize| {
                f[i].parse::<u64>()
                    .map_err(|_| format!("bad number {:?} in {l:?}", f[i]))
            };
            let small = |i: usize| f[i].parse::<u32>().map_err(|_| format!("bad id {:?} in {l:?}", f[i]));
            Ok(ShmSeg {
                cpid: f[cpid].parse().map_err(|_| format!("bad pid {:?} in {l:?}", f[cpid]))?,
                uid: small(uid)?,
                cuid: small(cuid)?,
                rss_bytes: num(rss)?,
            })
        })
        .collect()
}

/// Resident bytes of the sandbox's SysV segments: owned or created by its
/// uid, or created by one of its live processes.
pub fn sysv_bytes(segs: &[ShmSeg], uid: u32, live: &BTreeSet<Pid>) -> u64 {
    segs.iter()
        .filter(|s| s.uid == uid || s.cuid == uid || live.contains(&s.cpid))
        .map(|s| s.rss_bytes)
        .sum()
}

/// A memfd one of the sandbox's processes holds open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memfd {
    pub dev: u64,
    pub ino: u64,
    /// Allocated bytes (st_blocks).
    pub bytes: u64,
}

/// The bytes of distinct memfds: one shared between descriptors or
/// processes counts once.
pub fn memfd_bytes(fds: &[Memfd]) -> u64 {
    let mut unique: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    for m in fds {
        let b = unique.entry((m.dev, m.ino)).or_insert(0);
        *b = (*b).max(m.bytes);
    }
    unique.values().sum()
}

/// KiB, rounded down, as the report and the series give every figure.
pub fn kib(bytes: u64) -> u64 {
    bytes >> 10
}

/// What one sample read. `None` is a failed read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// Each live sandbox process that could be read.
    pub procs: Vec<ProcMem>,
    pub memfd_bytes: u64,
    pub sysv_bytes: Option<u64>,
    /// Every measured tmpfs mount: the bytes used above its level at start.
    pub tmpfs_bytes: BTreeMap<PathBuf, Option<u64>>,
    /// With a delegated cgroup (`None` without one, too).
    pub cgroup: Option<CgroupMem>,
}

/// The largest value of every figure over the samples so far.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peaks {
    /// The largest single process, per kind (as `max_rss_kib` is).
    pub max_anon_kib: u64,
    pub max_file_kib: u64,
    pub max_shmem_kib: u64,
    /// The largest sum of RssAnon over the processes of one sample.
    pub tree_anon_kib: u64,
    pub memfd_bytes: u64,
    pub sysv_bytes: u64,
    pub tmpfs_bytes: BTreeMap<PathBuf, u64>,
    pub cgroup: Option<CgroupMem>,
}

impl Peaks {
    /// The figures of a single sample; a failed read adds nothing.
    pub fn of(s: &Sample) -> Peaks {
        let max = |f: fn(&ProcMem) -> u64| s.procs.iter().map(f).max().unwrap_or(0);
        Peaks {
            max_anon_kib: max(|m| m.anon_kib),
            max_file_kib: max(|m| m.file_kib),
            max_shmem_kib: max(|m| m.shmem_kib),
            tree_anon_kib: s.procs.iter().map(|m| m.anon_kib).sum(),
            memfd_bytes: s.memfd_bytes,
            sysv_bytes: s.sysv_bytes.unwrap_or(0),
            tmpfs_bytes: s
                .tmpfs_bytes
                .iter()
                .filter_map(|(path, b)| b.map(|b| (path.clone(), b)))
                .collect(),
            cgroup: s.cgroup,
        }
    }

    /// Pointwise maximum.
    pub fn join(self, o: Peaks) -> Peaks {
        let mut tmpfs_bytes = self.tmpfs_bytes;
        for (path, v) in o.tmpfs_bytes {
            let b = tmpfs_bytes.entry(path).or_insert(0);
            *b = (*b).max(v);
        }
        Peaks {
            max_anon_kib: self.max_anon_kib.max(o.max_anon_kib),
            max_file_kib: self.max_file_kib.max(o.max_file_kib),
            max_shmem_kib: self.max_shmem_kib.max(o.max_shmem_kib),
            tree_anon_kib: self.tree_anon_kib.max(o.tree_anon_kib),
            memfd_bytes: self.memfd_bytes.max(o.memfd_bytes),
            sysv_bytes: self.sysv_bytes.max(o.sysv_bytes),
            tmpfs_bytes,
            cgroup: match (self.cgroup, o.cgroup) {
                (Some(a), Some(b)) => Some(a.join(b)),
                (a, b) => a.or(b),
            },
        }
    }

    pub fn fold(self, s: &Sample) -> Peaks {
        self.join(Peaks::of(s))
    }
}

/// Which processes sbx reaped without any sample having read them.
///
/// `sampled` holds the pids a sample read that have stayed in /proc since
/// (zombies included), so a recycled pid starts afresh.
#[derive(Debug, Default)]
pub struct Tracker {
    sampled: BTreeSet<Pid>,
    unsampled: u32,
}

impl Tracker {
    /// After a sample: `present` is every pid in /proc, `measured` (a
    /// subset) the sandbox processes the sample read.
    pub fn observe(&mut self, present: &BTreeSet<Pid>, measured: &BTreeSet<Pid>) {
        self.sampled.retain(|p| present.contains(p));
        self.sampled.extend(measured);
    }

    /// sbx reaped `pid`.
    pub fn reaped(&mut self, pid: Pid) {
        if !self.sampled.remove(&pid) {
            self.unsampled = self.unsampled.saturating_add(1);
        }
    }

    pub fn unsampled(&self) -> u32 {
        self.unsampled
    }
}

/// The report's `memory`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryReport {
    pub interval_ms: u64,
    pub samples: u64,
    pub max_anon_kib: u64,
    pub max_file_kib: u64,
    pub max_shmem_kib: u64,
    pub tree_peak_anon_kib: u64,
    pub memfd_peak_kib: u64,
    pub sysv_shm_peak_kib: u64,
    pub tmpfs_peak_kib: BTreeMap<String, u64>,
    pub cgroup: Option<CgroupPeaks>,
    pub unsampled_processes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CgroupPeaks {
    pub peak_anon_kib: u64,
    pub peak_shmem_kib: u64,
}

impl MemoryReport {
    pub fn new(interval_ms: u64, samples: u64, p: &Peaks, unsampled: u32) -> MemoryReport {
        MemoryReport {
            interval_ms,
            samples,
            max_anon_kib: p.max_anon_kib,
            max_file_kib: p.max_file_kib,
            max_shmem_kib: p.max_shmem_kib,
            tree_peak_anon_kib: p.tree_anon_kib,
            memfd_peak_kib: kib(p.memfd_bytes),
            sysv_shm_peak_kib: kib(p.sysv_bytes),
            tmpfs_peak_kib: p
                .tmpfs_bytes
                .iter()
                .map(|(path, b)| (path.display().to_string(), kib(*b)))
                .collect(),
            cgroup: p.cgroup.map(|c| CgroupPeaks {
                peak_anon_kib: kib(c.anon_bytes),
                peak_shmem_kib: kib(c.shmem_bytes),
            }),
            unsampled_processes: unsampled,
        }
    }
}

/// What the samples add up to: the peaks, the processes no sample saw,
/// and, with a series, the samples themselves.
#[derive(Debug)]
pub struct Tally {
    interval_ms: u64,
    peaks: Peaks,
    tracker: Tracker,
    samples: u64,
    series: Option<MemorySeries>,
}

impl Tally {
    /// `tmpfs`: the measured mounts, each reported even if no read succeeds.
    pub fn new(interval_ms: u64, tmpfs: &[PathBuf], series: Option<SeriesSpec>) -> Tally {
        Tally {
            interval_ms,
            peaks: Peaks {
                tmpfs_bytes: tmpfs.iter().map(|p| (p.clone(), 0)).collect(),
                ..Peaks::default()
            },
            tracker: Tracker::default(),
            samples: 0,
            series: series.map(MemorySeries::new),
        }
    }

    /// A sample taken `at` after the program started. `present`: every pid
    /// in /proc; `measured`: the sandbox processes the sample read.
    pub fn record(&mut self, at: Duration, when: When, s: &Sample, present: &BTreeSet<Pid>, measured: &BTreeSet<Pid>) {
        self.peaks = std::mem::take(&mut self.peaks).fold(s);
        self.tracker.observe(present, measured);
        self.samples += 1;
        if let Some(series) = &mut self.series {
            series.push(u64::try_from(at.as_micros()).unwrap_or(u64::MAX), s, when);
        }
    }

    /// sbx reaped `pid`.
    pub fn reaped(&mut self, pid: Pid) {
        self.tracker.reaped(pid);
    }

    pub fn finish(self) -> (MemoryReport, Option<MemorySeries>) {
        let report = MemoryReport::new(self.interval_ms, self.samples, &self.peaks, self.tracker.unsampled());
        (report, self.series)
    }
}

// ---------------------------------------------------------------- IO

/// Why a read of the sandbox's /proc failed.
#[derive(Debug)]
pub enum ReadError {
    /// The process (or descriptor) went away meanwhile.
    Gone,
    Failed(String),
}

impl Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Gone => write!(f, "the process exited"),
            ReadError::Failed(e) => write!(f, "{e}"),
        }
    }
}

fn read_error(what: impl Display, e: std::io::Error) -> ReadError {
    match e.raw_os_error() {
        Some(libc::ENOENT | libc::ESRCH) => ReadError::Gone,
        _ => ReadError::Failed(format!("{what}: {e}")),
    }
}

/// The resident set of `pid` by kind.
pub fn proc_mem(pid: Pid) -> Result<ProcMem, ReadError> {
    let path = format!("/proc/{pid}/status");
    // Bytes: the process name in it need not be UTF-8.
    let s = std::fs::read(&path).map_err(|e| read_error(&path, e))?;
    match ProcMem::parse_status(&s) {
        Some(m) => Ok(m),
        // Exited meanwhile.
        None if procfs::status_text(&s, "State:").is_some_and(|v| v.starts_with(['Z', 'X'])) => Err(ReadError::Gone),
        None => Err(ReadError::Failed(format!(
            "{path} has no RssAnon, RssFile and RssShmem (needs Linux 4.5+)"
        ))),
    }
}

/// The memfds `pid` holds open. Listing another uid's descriptors needs
/// CAP_SYS_PTRACE (see `capabilities`).
pub fn memfds(pid: Pid) -> Result<Vec<Memfd>, ReadError> {
    let dir = format!("/proc/{pid}/fd");
    let mut out = vec![];
    for entry in std::fs::read_dir(&dir).map_err(|e| read_error(&dir, e))? {
        let path = entry.map_err(|e| read_error(&dir, e))?.path();
        // A descriptor closed meanwhile is skipped.
        let target = match std::fs::read_link(&path) {
            Ok(t) => t,
            Err(e) => match read_error(path.display(), e) {
                ReadError::Gone => continue,
                failed => return Err(failed),
            },
        };
        if !target.as_os_str().as_bytes().starts_with(b"/memfd:") {
            continue;
        }
        // Through the link: the memfd's own inode.
        match std::fs::metadata(&path) {
            Ok(m) => out.push(Memfd {
                dev: m.dev(),
                ino: m.ino(),
                bytes: m.blocks().saturating_mul(512),
            }),
            Err(e) => match read_error(path.display(), e) {
                ReadError::Gone => continue,
                failed => return Err(failed),
            },
        }
    }
    Ok(out)
}

/// Every SysV shared memory segment in sbx's IPC namespace.
pub fn sysv_segments() -> Result<Vec<ShmSeg>, String> {
    let s = std::fs::read_to_string(SYSVIPC_SHM).map_err(|e| format!("read {SYSVIPC_SHM}: {e}"))?;
    parse_sysvipc_shm(&s).map_err(|e| format!("{SYSVIPC_SHM}: {e}"))
}

fn statfs(path: &Path) -> Result<libc::statfs, String> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| format!("{} contains a NUL byte", path.display()))?;
    // SAFETY: zeroed statfs is valid output storage.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated and st is valid.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(os_err(format!("statfs({})", path.display())));
    }
    Ok(st)
}

/// statfs's f_type is a different integer type in each libc; every one
/// holds a u32 magic.
fn is_magic<T: From<u32> + PartialEq>(f_type: T, magic: u32) -> bool {
    f_type == T::from(magic)
}

/// The device of the tmpfs mounted at `path`; an error unless `path` is a
/// tmpfs mount point.
pub fn tmpfs_mount(path: &Path) -> Result<u64, String> {
    let st = statfs(path)?;
    if !is_magic(st.f_type, TMPFS_MAGIC) {
        return Err(format!(
            "is not a tmpfs (f_type {:#x}); name a tmpfs mount point",
            st.f_type
        ));
    }
    let dev = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.dev())
            .map_err(|e| format!("{}: {e}", p.display()))
    };
    let own = dev(path)?;
    if let Some(parent) = path.parent() {
        if dev(parent)? == own {
            return Err("is not a mount point but a directory in a tmpfs; name the mount point itself".into());
        }
    }
    Ok(own)
}

/// Bytes in use on the filesystem at `path`.
fn fs_used(path: &Path) -> Result<u64, String> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| format!("{} contains a NUL byte", path.display()))?;
    // SAFETY: zeroed statvfs is valid output storage.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated and st is valid.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(os_err(format!("statvfs({})", path.display())));
    }
    Ok(st.f_blocks.saturating_sub(st.f_bfree).saturating_mul(st.f_frsize))
}

/// What a failed read was reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Status,
    Fds,
    Sysv,
    Tmpfs,
    Cgroup,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Status => "/proc/<pid>/status",
            Kind::Fds => "/proc/<pid>/fd",
            Kind::Sysv => SYSVIPC_SHM,
            Kind::Tmpfs => "measure.tmpfs",
            Kind::Cgroup => "the sandbox cgroup's memory.stat",
        }
    }
}

/// Failed reads per kind; the first of each kind is logged.
#[derive(Debug, Default)]
struct Failures(BTreeMap<Kind, u64>);

impl Failures {
    fn record(&mut self, kind: Kind, e: ReadError) {
        let ReadError::Failed(msg) = e else {
            return;
        };
        let n = self.0.entry(kind).or_insert(0);
        *n += 1;
        if *n == 1 {
            log::error(format!(
                "memory sampling: {msg}; the report's memory figures may be low"
            ));
        }
    }
}

/// Samples the sandbox's memory every `interval` (see the module docs).
pub struct Sampler {
    uid: u32,
    /// Each measured tmpfs mount and its use when sbx started.
    tmpfs: Vec<(PathBuf, u64)>,
    failures: Failures,
    tally: Tally,
}

impl Sampler {
    /// None when sampling is off. Reads the tmpfs mounts' baselines, so it
    /// runs before the program starts. `series`: keep the samples too.
    pub fn new(cfg: &MeasureCfg, uid: u32, series: Option<SeriesSpec>) -> Result<Option<Sampler>, String> {
        let MeasureCfg::Sampled { interval_ms, tmpfs, .. } = cfg else {
            return Ok(None);
        };
        let tmpfs: Vec<(PathBuf, u64)> = tmpfs
            .iter()
            .map(|p| {
                fs_used(p)
                    .map(|used| (p.clone(), used))
                    .map_err(|e| format!("measure.tmpfs {}: {e}", p.display()))
            })
            .collect::<Result<_, _>>()?;
        let paths: Vec<PathBuf> = tmpfs.iter().map(|(p, _)| p.clone()).collect();
        Ok(Some(Sampler {
            uid,
            tmpfs,
            failures: Failures::default(),
            tally: Tally::new(interval_ms.get(), &paths, series),
        }))
    }

    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.tally.interval_ms)
    }

    /// Read everything once, `at` after the program started. `live`: the
    /// sandbox's live processes; `present`: every pid in /proc, zombies
    /// included.
    pub fn sample(
        &mut self,
        at: Duration,
        when: When,
        live: &BTreeSet<Pid>,
        present: &BTreeSet<Pid>,
        cg: Option<&Delegation>,
    ) {
        let mut s = Sample::default();
        let mut measured = BTreeSet::new();
        let mut fds = vec![];
        for &pid in live {
            match proc_mem(pid) {
                Ok(m) => {
                    s.procs.push(m);
                    measured.insert(pid);
                }
                Err(e) => {
                    self.failures.record(Kind::Status, e);
                    continue;
                }
            }
            match memfds(pid) {
                Ok(v) => fds.extend(v),
                Err(e) => self.failures.record(Kind::Fds, e),
            }
        }
        s.memfd_bytes = memfd_bytes(&fds);
        s.sysv_bytes = match sysv_segments() {
            Ok(segs) => Some(sysv_bytes(&segs, self.uid, live)),
            Err(e) => {
                self.failures.record(Kind::Sysv, ReadError::Failed(e));
                None
            }
        };
        for (path, base) in &self.tmpfs {
            let used = match fs_used(path) {
                Ok(used) => Some(used.saturating_sub(*base)),
                Err(e) => {
                    self.failures.record(Kind::Tmpfs, ReadError::Failed(e));
                    None
                }
            };
            s.tmpfs_bytes.insert(path.clone(), used);
        }
        if let Some(c) = cg {
            match c.memory_stat().and_then(|m| CgroupMem::parse(&m)) {
                Ok(m) => s.cgroup = Some(m),
                Err(e) => self.failures.record(Kind::Cgroup, ReadError::Failed(e)),
            }
        }
        self.tally.record(at, when, &s, present, &measured);
    }

    /// sbx reaped `pid`.
    pub fn reaped(&mut self, pid: Pid) {
        self.tally.reaped(pid);
    }

    pub fn finish(self) -> (MemoryReport, Option<MemorySeries>) {
        for (kind, n) in &self.failures.0 {
            if *n > 1 {
                log::error(format!("memory sampling: {n} reads of {} failed", kind.as_str()));
            }
        }
        let (report, series) = self.tally.finish();
        if let Some(s) = &series {
            log::info(format!(
                "memory series: {} rows, {} samples dropped, {} KiB in memory",
                s.rows().len(),
                s.dropped(),
                s.footprint().div_ceil(1024)
            ));
        }
        (report, series)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use proptest::prelude::*;

    fn render_status(m: &ProcMem, name: &[u8]) -> Vec<u8> {
        let kb = |v: u64| format!("{v:>8} kB");
        procfs::render::status(
            name,
            &[
                ("Umask:", "0022".into()),
                ("State:", "S (sleeping)".into()),
                ("Pid:", "42".into()),
                ("VmPeak:", "  123456 kB".into()),
                ("VmRSS:", kb(m.anon_kib + m.file_kib + m.shmem_kib)),
                ("RssAnon:", kb(m.anon_kib)),
                ("RssFile:", kb(m.file_kib)),
                ("RssShmem:", kb(m.shmem_kib)),
                ("VmData:", "    1234 kB".into()),
                ("Threads:", "1".into()),
            ],
        )
    }

    fn proc_mem() -> impl Strategy<Value = ProcMem> {
        (0..1u64 << 30, 0..1u64 << 30, 0..1u64 << 30).prop_map(|(anon_kib, file_kib, shmem_kib)| ProcMem {
            anon_kib,
            file_kib,
            shmem_kib,
        })
    }

    /// The kernel's format (ipc/shm.c, sysvipc_shm_proc_show).
    fn render_sysvipc(rows: &[(i32, ShmSeg, u64)]) -> String {
        let mut out =
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      \
                       atime      dtime      ctime                   rss                  swap\n"
                .to_string();
        for (key, s, size) in rows {
            out += &format!(
                "{key:>10} {:>10} {:>4o} {size:>21} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>10} {:>10} {:>10} \
                 {:>21} {:>21}\n",
                7, 0o600, s.cpid, 1, 0, s.uid, 0, s.cuid, 0, 0, 0, 1_700_000_000u64, s.rss_bytes, 0
            );
        }
        out
    }

    fn seg() -> impl Strategy<Value = ShmSeg> {
        (1..Pid::MAX, any::<u32>(), any::<u32>(), 0..1u64 << 48).prop_map(|(cpid, uid, cuid, rss_bytes)| ShmSeg {
            cpid,
            uid,
            cuid,
            rss_bytes,
        })
    }

    /// The tmpfs mounts test samples measure, sorted.
    pub const TMPFS: [&str; 3] = ["/a", "/b", "/c"];

    /// A sample as [`Sampler`] takes it: a figure or a failed read for each
    /// of the first `n_tmpfs` of [`TMPFS`], and for memory.stat if
    /// `cgroup`; `None` there otherwise.
    pub fn sample_of(n_tmpfs: usize, cgroup: bool) -> impl Strategy<Value = Sample> {
        let tmpfs = prop::collection::vec(prop::option::of(0..1u64 << 48), n_tmpfs)
            .prop_map(|v| TMPFS.iter().map(PathBuf::from).zip(v).collect());
        let mem = (0..1u64 << 48, 0..1u64 << 48).prop_map(|(anon_bytes, shmem_bytes)| CgroupMem {
            anon_bytes,
            shmem_bytes,
        });
        let cgroup = if cgroup {
            prop::option::of(mem).boxed()
        } else {
            Just(None).boxed()
        };
        (
            prop::collection::vec(proc_mem(), 0..20),
            0..1u64 << 48,
            prop::option::of(0..1u64 << 48),
            tmpfs,
            cgroup,
        )
            .prop_map(|(procs, memfd_bytes, sysv_bytes, tmpfs_bytes, cgroup)| Sample {
                procs,
                memfd_bytes,
                sysv_bytes,
                tmpfs_bytes,
                cgroup,
            })
    }

    fn sample() -> impl Strategy<Value = Sample> {
        (0..=TMPFS.len()).prop_flat_map(|n| sample_of(n, true))
    }

    /// `a` is nowhere above `b`.
    fn le(a: &Peaks, b: &Peaks) -> bool {
        let cg = match (a.cgroup, b.cgroup) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(x), Some(y)) => x.anon_bytes <= y.anon_bytes && x.shmem_bytes <= y.shmem_bytes,
        };
        a.max_anon_kib <= b.max_anon_kib
            && a.max_file_kib <= b.max_file_kib
            && a.max_shmem_kib <= b.max_shmem_kib
            && a.tree_anon_kib <= b.tree_anon_kib
            && a.memfd_bytes <= b.memfd_bytes
            && a.sysv_bytes <= b.sysv_bytes
            && a.tmpfs_bytes
                .iter()
                .all(|(k, v)| b.tmpfs_bytes.get(k).is_some_and(|w| v <= w))
            && cg
    }

    #[derive(Clone, Debug)]
    enum Ev {
        Sample {
            present: BTreeSet<Pid>,
            measured: BTreeSet<Pid>,
        },
        Reap(Pid),
    }

    fn events() -> impl Strategy<Value = Vec<Ev>> {
        let ev = prop_oneof![
            prop::collection::btree_map(1..6 as Pid, any::<bool>(), 0..6).prop_map(|m| Ev::Sample {
                present: m.keys().copied().collect(),
                measured: m.iter().filter(|(_, &read)| read).map(|(&p, _)| p).collect(),
            }),
            (1..6 as Pid).prop_map(Ev::Reap),
        ];
        prop::collection::vec(ev, 0..40)
    }

    /// A reaped pid was sampled if, since it was last reaped, a sample read
    /// it and every later sample still found it in /proc.
    fn unsampled_model(evs: &[Ev]) -> u32 {
        let mut n = 0;
        for (t, e) in evs.iter().enumerate() {
            let Ev::Reap(pid) = e else { continue };
            let from = evs[..t]
                .iter()
                .rposition(|e| matches!(e, Ev::Reap(p) if p == pid))
                .map_or(0, |i| i + 1);
            let window = &evs[from..t];
            let read = window
                .iter()
                .rposition(|e| matches!(e, Ev::Sample { measured, .. } if measured.contains(pid)));
            let sampled = read.is_some_and(|r| {
                window[r + 1..].iter().all(|e| match e {
                    Ev::Sample { present, .. } => present.contains(pid),
                    Ev::Reap(_) => true,
                })
            });
            n += u32::from(!sampled);
        }
        n
    }

    proptest! {
        /// The sandbox picks the name: any bytes but NUL, UTF-8 or not.
        #[test]
        fn status_parsing_survives_any_process_name(m in proc_mem(), name in prop::collection::vec(1..=255u8, 0..16)) {
            prop_assert_eq!(ProcMem::parse_status(&render_status(&m, &name)), Some(m));
        }

        #[test]
        fn memory_stat_parsing_inverts_rendering(
            c in (any::<u64>(), any::<u64>()),
            others in prop::collection::btree_map(
                prop::sample::select(vec!["anon_thp", "file", "file_mapped", "shmem_thp", "active_anon", "kernel"]),
                any::<u64>(),
                0..6,
            ),
        ) {
            let want = CgroupMem { anon_bytes: c.0, shmem_bytes: c.1 };
            let mut lines: Vec<String> = others.iter().map(|(k, v)| format!("{k} {v}")).collect();
            lines.insert(lines.len() / 2, format!("anon {}", c.0));
            lines.push(format!("shmem {}", c.1));
            prop_assert_eq!(CgroupMem::parse(&(lines.join("\n") + "\n")), Ok(want));
        }

        #[test]
        fn sysvipc_parsing_inverts_rendering(
            rows in prop::collection::vec((any::<i32>(), seg(), any::<u64>()), 0..10),
        ) {
            let segs: Vec<ShmSeg> = rows.iter().map(|r| r.1).collect();
            prop_assert_eq!(parse_sysvipc_shm(&render_sysvipc(&rows)), Ok(segs));
        }

        #[test]
        fn sysv_counts_exactly_the_sandboxs_segments(
            ours in prop::collection::vec((seg(), 0..3u8), 0..8),
            theirs in prop::collection::vec(seg(), 0..8),
        ) {
            let (uid, pid) = (65534, 4242);
            let live = BTreeSet::from([pid]);
            // Ours by owner, by creator (whatever IPC_SET made the owner), or by creating process.
            let ours: Vec<ShmSeg> = ours.into_iter().map(|(s, how)| match how {
                0 => ShmSeg { uid, ..s },
                1 => ShmSeg { cuid: uid, ..s },
                _ => ShmSeg { cpid: pid, ..s },
            }).collect();
            let theirs: Vec<ShmSeg> = theirs.into_iter().map(|s| ShmSeg {
                uid: s.uid.max(uid + 1),
                cuid: s.cuid.max(uid + 1),
                cpid: if s.cpid == pid { pid + 1 } else { s.cpid },
                ..s
            }).collect();
            let mut all = [ours.clone(), theirs].concat();
            all.reverse();
            prop_assert_eq!(sysv_bytes(&all, uid, &live), ours.iter().map(|s| s.rss_bytes).sum::<u64>());
        }

        #[test]
        fn memfds_count_once_each(
            files in prop::collection::btree_map((0..4u64, any::<u64>()), 0..1u64 << 40, 0..10),
            copies in prop::collection::vec(1..4usize, 10),
            seed in any::<u64>(),
        ) {
            let mut fds: Vec<Memfd> = files
                .iter()
                .zip(copies)
                .flat_map(|((&(dev, ino), &bytes), n)| std::iter::repeat_n(Memfd { dev, ino, bytes }, n))
                .collect();
            // A deterministic shuffle.
            fds.sort_by_key(|m| (m.ino ^ seed).rotate_left((m.dev % 64) as u32));
            prop_assert_eq!(memfd_bytes(&fds), files.values().sum::<u64>());
        }

        #[test]
        fn a_sample_yields_its_largest_process_and_its_tree_sum(s in sample()) {
            let p = Peaks::of(&s);
            prop_assert_eq!(p.max_anon_kib, s.procs.iter().map(|m| m.anon_kib).max().unwrap_or(0));
            prop_assert_eq!(p.max_file_kib, s.procs.iter().map(|m| m.file_kib).max().unwrap_or(0));
            prop_assert_eq!(p.max_shmem_kib, s.procs.iter().map(|m| m.shmem_kib).max().unwrap_or(0));
            prop_assert_eq!(p.tree_anon_kib, s.procs.iter().map(|m| m.anon_kib).sum::<u64>());
            prop_assert!(s.procs.iter().all(|m| m.anon_kib <= p.tree_anon_kib));
            let read: BTreeMap<PathBuf, u64> =
                s.tmpfs_bytes.iter().filter_map(|(k, v)| v.map(|v| (k.clone(), v))).collect();
            prop_assert_eq!((p.memfd_bytes, p.sysv_bytes, &p.tmpfs_bytes, p.cgroup),
                            (s.memfd_bytes, s.sysv_bytes.unwrap_or(0), &read, s.cgroup));
        }

        #[test]
        fn peaks_fold_is_monotone_idempotent_and_order_free(
            samples in prop::collection::vec(sample(), 0..6),
            extra in sample(),
        ) {
            let p = samples.iter().fold(Peaks::default(), |p, s| p.fold(s));
            let q = p.clone().fold(&extra);
            prop_assert!(le(&p, &q), "fold lowered a peak: {:?} -> {:?}", p, q);
            prop_assert!(le(&Peaks::of(&extra), &q));
            prop_assert_eq!(q.clone().fold(&extra), q.clone());
            let backwards = samples.iter().rev().fold(Peaks::default().fold(&extra), |p, s| p.fold(s));
            prop_assert_eq!(backwards, q);
        }

        #[test]
        fn unsampled_processes_follow_the_model(evs in events()) {
            let mut t = Tracker::default();
            for e in &evs {
                match e {
                    Ev::Sample { present, measured } => t.observe(present, measured),
                    Ev::Reap(pid) => t.reaped(*pid),
                }
            }
            prop_assert_eq!(t.unsampled(), unsampled_model(&evs));
        }
    }

    #[test]
    fn zombies_and_garbage_are_not_measured() {
        let zombie = b"Name:\tsh\nState:\tZ (zombie)\nPid:\t9\nThreads:\t1\n";
        assert_eq!(ProcMem::parse_status(zombie), None);
        assert!(CgroupMem::parse("anon_thp 0\nshmem_thp 0\n").is_err());
        assert!(parse_sysvipc_shm("").is_err());
        assert!(parse_sysvipc_shm("key shmid perms size\n").is_err());
        let header = render_sysvipc(&[]);
        assert_eq!(parse_sysvipc_shm(&header), Ok(vec![]));
        assert!(parse_sysvipc_shm(&format!("{header}1 7 600 5 1 1 0 2 0 3 0 0 0 0 x 0\n")).is_err());
        assert!(parse_sysvipc_shm(&format!("{header}1 7 600 5 1 1 0 2 0 3 0 0 0 0 4\n")).is_err());
    }

    #[test]
    fn the_report_is_in_kib() {
        let p = Peaks {
            max_anon_kib: 3,
            memfd_bytes: 48 << 20,
            sysv_bytes: 4095,
            tmpfs_bytes: BTreeMap::from([(PathBuf::from("/dev/shm"), 8 << 20)]),
            cgroup: Some(CgroupMem {
                anon_bytes: 1 << 20,
                shmem_bytes: 2048,
            }),
            ..Peaks::default()
        };
        let r = serde_json::to_value(MemoryReport::new(20, 7, &p, 1)).unwrap();
        assert_eq!(r["memfd_peak_kib"], 49152);
        assert_eq!(r["sysv_shm_peak_kib"], 3);
        assert_eq!(r["tmpfs_peak_kib"]["/dev/shm"], 8192);
        assert_eq!(r["cgroup"]["peak_anon_kib"], 1024);
        assert_eq!(r["cgroup"]["peak_shmem_kib"], 2);
        assert_eq!(r["max_anon_kib"], 3);
        assert_eq!(r["unsampled_processes"], 1);
        assert_eq!(r.as_object().unwrap().len(), 11, "{r}");
    }
}
