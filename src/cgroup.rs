//! cgroup v2 limits for the sandbox (`cgroup.mode = "delegated"`).
//!
//! sbx's own cgroup C (from /proc/self/cgroup) must be delegated to it: a
//! writable cgroup2 mount at /sys/fs/cgroup, the memory and pids controllers
//! available in C, and no other process in C. cgroup v2 keeps processes out
//! of cgroups whose controllers are enabled for their children, so sbx
//! first moves itself into C/sbx-supervisor, then enables memory and pids
//! for C's children and creates C/sbx-sandbox with the policy's limits. The
//! child joins C/sbx-sandbox before it drops its privileges, so the program
//! and everything it starts are charged there and an OOM kill hits them, not
//! the supervisor. [`Delegation::finish`] kills whatever is left, reads the
//! counters and puts C back as it was.
//!
//!   C                 cgroup.subtree_control: +memory +pids (while sbx runs)
//!   ├─ sbx-supervisor sbx
//!   └─ sbx-sandbox    the program; memory.max, memory.swap.max = 0,
//!                     memory.oom.group = 1, pids.max

use crate::log::{self, os_err};
use crate::policy::{CgroupCfg, Limit};
use serde::Serialize;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MOUNT: &str = "/sys/fs/cgroup";
const SUPERVISOR: &str = "sbx-supervisor";
const SANDBOX: &str = "sbx-sandbox";
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
/// Files sbx reads or writes in the sandbox cgroup besides the limits.
const NEEDED: [&str; 6] = [
    "cgroup.kill",
    "cgroup.events",
    "memory.events",
    "memory.peak",
    "pids.events",
    "cpu.stat",
];

/// What the sandbox cgroup recorded, for the report.
#[derive(Debug, Clone, Serialize)]
pub struct CgroupStats {
    pub memory_mb: Limit,
    pub pids: Limit,
    /// Peak memory of the whole sandbox, page cache and tmpfs files included.
    pub memory_peak_kib: u64,
    /// Processes the kernel's OOM killer killed (memory.events oom_kill).
    pub oom_kills: u64,
    /// Times a fork or clone failed on pids.max (pids.events max).
    pub pids_max_hits: u64,
    pub user_ms: u64,
    pub sys_ms: u64,
}

/// The cgroup path sbx is in, from /proc/self/cgroup: exactly one cgroup v2
/// entry, inside sbx's cgroup namespace.
pub fn own_cgroup(proc_self_cgroup: &str) -> Result<PathBuf, String> {
    let lines: Vec<&str> = proc_self_cgroup.lines().filter(|l| !l.is_empty()).collect();
    let [line] = lines.as_slice() else {
        return Err(format!(
            "/proc/self/cgroup lists {} hierarchies; sbx needs a pure cgroup v2 setup (one \"0::/...\" line)",
            lines.len()
        ));
    };
    let path = line
        .strip_prefix("0::")
        .ok_or_else(|| format!("/proc/self/cgroup is {line:?}; sbx needs cgroup v2 (\"0::/...\")"))?;
    if !path.starts_with('/') || path.split('/').any(|c| c == "..") {
        return Err(format!(
            "sbx's cgroup {path} lies outside its cgroup namespace; run sbx in a cgroup namespace of its own"
        ));
    }
    Ok(PathBuf::from(path.trim_start_matches('/')))
}

/// What a limit file is set to.
pub fn limit_value(l: Limit, shift: u32) -> String {
    match l {
        Limit::Value(n) => (n << shift).to_string(),
        Limit::Unlimited => "max".into(),
    }
}

/// The value of `key` in a flat-keyed cgroup file ("key value" lines).
pub fn keyed(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|l| {
        let (k, v) = l.split_once(' ')?;
        if k == key {
            v.trim().parse().ok()
        } else {
            None
        }
    })
}

/// A memory.max value: None for "max".
fn parse_max(s: &str) -> Result<Option<u64>, String> {
    match s.trim() {
        "max" => Ok(None),
        v => v.parse().map(Some).map_err(|_| format!("unexpected value {v:?}")),
    }
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn write(path: &Path, value: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|mut f| f.write_all(value.as_bytes()))
        .map_err(|e| format!("write {value:?} to {}: {e}", path.display()))
}

/// The steps setup took, undone in reverse order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    MadeSupervisor,
    MovedSelf,
    EnabledControllers,
    MadeSandbox,
}

/// The changes made to sbx's cgroup so far; dropping it undoes them.
struct Changes {
    base: PathBuf,
    done: Vec<Step>,
}

impl Changes {
    fn sandbox(&self) -> PathBuf {
        self.base.join(SANDBOX)
    }

    fn mkdir(&self, name: &str) -> Result<(), String> {
        let p = self.base.join(name);
        std::fs::create_dir(&p).map_err(|e| match e.raw_os_error() {
            Some(libc::EROFS) => format!(
                "mkdir {}: {e}: {MOUNT} is mounted read-only, so no cgroup is delegated to sbx (podman: \
                 --systemd=always; Docker and Kubernetes give a writable cgroupfs only to privileged containers; \
                 see the README, \"cgroup limits\")",
                p.display()
            ),
            _ => format!("mkdir {}: {e}", p.display()),
        })
    }

    fn undo(&mut self) -> Vec<String> {
        let mut errs = vec![];
        while let Some(step) = self.done.pop() {
            let r = match step {
                Step::MadeSandbox => rmdir(&self.sandbox()),
                Step::EnabledControllers => write(&self.base.join("cgroup.subtree_control"), "-memory -pids"),
                Step::MovedSelf => write(&self.base.join("cgroup.procs"), &std::process::id().to_string()),
                Step::MadeSupervisor => rmdir(&self.base.join(SUPERVISOR)),
            };
            if let Err(e) = r {
                errs.push(format!("restoring sbx's cgroup {}: {e}", self.base.display()));
            }
        }
        errs
    }
}

/// A backstop for early returns: put the cgroup back, logging failures.
impl Drop for Changes {
    fn drop(&mut self) {
        for e in self.undo() {
            log::error(e);
        }
    }
}

pub struct Delegation {
    changes: Changes,
    memory_mb: Limit,
    pids: Limit,
    /// sbx-sandbox/cgroup.procs, which the child writes to join.
    procs: OwnedFd,
}

impl Delegation {
    /// Create the sandbox cgroup. Runs before fork, while sbx is
    /// single-threaded and the signals that would stop it are blocked.
    pub fn setup(cfg: CgroupCfg) -> Result<Option<Delegation>, String> {
        let CgroupCfg::Delegated { memory_mb, pids } = cfg else {
            return Ok(None);
        };
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(
                "cgroup.mode = \"delegated\" needs sbx to start as root: the program would otherwise share the \
                 uid that owns the sandbox cgroup and could raise its own limits"
                    .into(),
            );
        }
        check_mount()?;
        let base = Path::new(MOUNT).join(own_cgroup(&read(Path::new("/proc/self/cgroup"))?)?);
        let b = base.display();
        let me = std::process::id();
        let procs = read(&base.join("cgroup.procs"))?;
        let others: Vec<String> = procs
            .lines()
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .filter(|&p| p != me)
            .map(|p| format!("{} (pid {p})", crate::notify::comm_of(p as i32)))
            .collect();
        if !others.is_empty() {
            return Err(format!(
                "sbx's cgroup {b} also contains {}; sbx needs a cgroup of its own (start it in a cgroup with \
                 nothing else in it, see the README, \"cgroup limits\")",
                others.join(", ")
            ));
        }
        match std::fs::read_to_string(base.join("cgroup.type")) {
            Ok(t) if t.trim() != "domain" => {
                return Err(format!("{b} is a {} cgroup; sbx needs a domain cgroup", t.trim()))
            }
            // The root cgroup has no cgroup.type.
            Ok(_) | Err(_) => {}
        }
        let controllers = read(&base.join("cgroup.controllers"))?;
        let have: Vec<&str> = controllers.split_whitespace().collect();
        if !have.contains(&"memory") || !have.contains(&"pids") {
            return Err(format!(
                "{b} offers the controllers [{}], not memory and pids: the parent cgroup must enable them for it",
                have.join(" ")
            ));
        }
        for name in [SUPERVISOR, SANDBOX] {
            if base.join(name).exists() {
                return Err(format!(
                    "{} exists, probably left by an sbx that was killed; remove it with rmdir",
                    base.join(name).display()
                ));
            }
        }
        if let Limit::Value(mb) = memory_mb {
            let own = read(&base.join("memory.max"))?;
            if let Some(max) = parse_max(&own).map_err(|e| format!("{b}/memory.max: {e}"))? {
                if mb << 20 >= max {
                    return Err(format!(
                        "cgroup.memory_mb = {mb} is not below the container's own limit ({} MiB in \
                         {b}/memory.max): the container's OOM killer would act first and may kill sbx",
                        max >> 20
                    ));
                }
            }
        }

        let mut c = Changes { base, done: vec![] };
        c.mkdir(SUPERVISOR)?;
        c.done.push(Step::MadeSupervisor);
        write(&c.base.join(SUPERVISOR).join("cgroup.procs"), &me.to_string())?;
        c.done.push(Step::MovedSelf);
        write(&c.base.join("cgroup.subtree_control"), "+memory +pids")?;
        c.done.push(Step::EnabledControllers);
        c.mkdir(SANDBOX)?;
        c.done.push(Step::MadeSandbox);
        configure_sandbox(&c.sandbox(), memory_mb, pids)?;
        let path = c.sandbox().join("cgroup.procs");
        let procs = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        Ok(Some(Delegation {
            changes: c,
            memory_mb,
            pids,
            procs: OwnedFd::from(procs),
        }))
    }

    fn sandbox(&self) -> PathBuf {
        self.changes.sandbox()
    }

    /// For the child: join the sandbox cgroup. Allocation-free.
    pub fn procs_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    /// SIGKILL everything in the sandbox cgroup, including processes that
    /// left sbx's process group.
    pub fn kill(&self) -> Result<(), String> {
        write(&self.sandbox().join("cgroup.kill"), "1")
    }

    /// Processes (not threads, not zombies) in the sandbox cgroup.
    pub fn live_processes(&self) -> Result<u32, String> {
        Ok(read(&self.sandbox().join("cgroup.procs"))?.lines().count() as u32)
    }

    pub fn oom_kills(&self) -> u64 {
        read(&self.sandbox().join("memory.events"))
            .ok()
            .and_then(|e| keyed(&e, "oom_kill"))
            .unwrap_or(0)
    }

    /// Kill what is left, read the counters, and put sbx's cgroup back as
    /// it was. Errors are returned, and the counters still when possible.
    pub fn finish(mut self) -> (Option<CgroupStats>, Vec<String>) {
        let mut errs = vec![];
        if let Err(e) = self.kill() {
            errs.push(e);
        }
        let events = self.sandbox().join("cgroup.events");
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match read(&events) {
                Ok(e) if keyed(&e, "populated") == Some(0) => break,
                Ok(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
                Ok(_) => {
                    errs.push(format!(
                        "{} still has processes 5s after cgroup.kill",
                        self.sandbox().display()
                    ));
                    break;
                }
                Err(e) => {
                    errs.push(e);
                    break;
                }
            }
        }
        let stats = self.stats().map_err(|e| errs.push(e)).ok();
        errs.extend(self.changes.undo());
        (stats, errs)
    }

    fn stats(&self) -> Result<CgroupStats, String> {
        let s = self.sandbox();
        let get = |file: &str, key: &str| -> Result<u64, String> {
            keyed(&read(&s.join(file))?, key).ok_or_else(|| format!("{}/{file} has no {key}", s.display()))
        };
        let peak = read(&s.join("memory.peak"))?;
        Ok(CgroupStats {
            memory_mb: self.memory_mb,
            pids: self.pids,
            memory_peak_kib: peak
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{}/memory.peak: unexpected value {:?}", s.display(), peak.trim()))?
                >> 10,
            oom_kills: get("memory.events", "oom_kill")?,
            pids_max_hits: get("pids.events", "max")?,
            user_ms: get("cpu.stat", "user_usec")? / 1000,
            sys_ms: get("cpu.stat", "system_usec")? / 1000,
        })
    }
}

/// For `sbx probe`: set the cgroup up and tear it down again.
pub fn trial(cfg: CgroupCfg) -> Result<String, String> {
    let Some(d) = Delegation::setup(cfg)? else {
        return Ok("off".into());
    };
    let base = d.changes.base.display().to_string();
    let (_, errs) = d.finish();
    if !errs.is_empty() {
        return Err(errs.join("; "));
    }
    Ok(format!(
        "{base} is delegated to sbx; a trial sandbox cgroup was created and removed"
    ))
}

/// The child's first step: move itself into the sandbox cgroup.
pub fn join(procs_fd: RawFd) -> Result<(), String> {
    // SAFETY: writing a static buffer to our fd.
    if unsafe { libc::write(procs_fd, b"0".as_ptr().cast(), 1) } != 1 {
        return Err(os_err("joining the sandbox cgroup (write to cgroup.procs)"));
    }
    Ok(())
}

fn configure_sandbox(s: &Path, memory_mb: Limit, pids: Limit) -> Result<(), String> {
    let mut settings = vec![
        ("memory.max", limit_value(memory_mb, 20)),
        ("memory.oom.group", "1".to_string()),
        ("pids.max", limit_value(pids, 0)),
    ];
    if s.join("memory.swap.max").exists() {
        settings.push(("memory.swap.max", "0".into()));
    } else if swap_active()? {
        return Err(format!(
            "{} has no memory.swap.max (no swap accounting), but swap is active: the sandbox could swap \
             past cgroup.memory_mb",
            s.display()
        ));
    }
    for (file, value) in settings {
        let path = s.join(file);
        write(&path, &value)?;
        let got = read(&path)?;
        if got.trim() != value {
            return Err(format!(
                "{} reads {:?} after sbx wrote {value:?}",
                path.display(),
                got.trim()
            ));
        }
    }
    for file in NEEDED {
        if !s.join(file).exists() {
            return Err(format!(
                "{} has no {file}; sbx needs Linux 5.19+ (memory.peak, cgroup.kill)",
                s.display()
            ));
        }
    }
    Ok(())
}

fn rmdir(p: &Path) -> Result<(), String> {
    let c = CString::new(p.as_os_str().as_bytes()).map_err(|_| format!("{}: NUL byte", p.display()))?;
    // SAFETY: rmdir of a NUL-terminated path.
    if unsafe { libc::rmdir(c.as_ptr()) } != 0 {
        return Err(os_err(format!("rmdir {}", p.display())));
    }
    Ok(())
}

fn check_mount() -> Result<(), String> {
    let c = CString::new(MOUNT).map_err(|_| "BUG: NUL in the cgroup mount path".to_string())?;
    // SAFETY: zeroed statfs is valid output storage.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated and st is valid.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(os_err(format!("statfs({MOUNT})")));
    }
    if st.f_type as i64 != CGROUP2_SUPER_MAGIC {
        return Err(format!(
            "{MOUNT} is not a cgroup v2 mount (f_type {:#x}); cgroup v1 and hybrid setups are not supported",
            st.f_type
        ));
    }
    Ok(())
}

fn swap_active() -> Result<bool, String> {
    // A header line, then one line per active swap area.
    Ok(read(Path::new("/proc/swaps"))?
        .lines()
        .skip(1)
        .any(|l| !l.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn own_cgroup_needs_one_v2_line_inside_the_namespace() {
        assert_eq!(own_cgroup("0::/\n").unwrap(), PathBuf::from(""));
        assert_eq!(own_cgroup("0::/a/b\n").unwrap(), PathBuf::from("a/b"));
        assert!(own_cgroup("0::/../x\n").unwrap_err().contains("outside"));
        assert!(own_cgroup("12:pids:/x\n0::/x\n").unwrap_err().contains("2 hierarchies"));
        assert!(own_cgroup("1:name=systemd:/x\n").unwrap_err().contains("cgroup v2"));
        assert!(own_cgroup("").is_err());
    }

    proptest! {
        #[test]
        fn limits_are_written_in_bytes_or_as_max(n in 1u64..(1 << 40), shift in prop_oneof![Just(0u32), Just(20)]) {
            prop_assert_eq!(limit_value(Limit::Value(n), shift).parse::<u64>().unwrap(), n << shift);
            prop_assert_eq!(limit_value(Limit::Unlimited, shift), "max");
        }

        #[test]
        fn keyed_finds_exactly_its_key(
            entries in prop::collection::btree_map("[a-z_]{1,12}", any::<u64>(), 0..8),
            missing in "[A-Z]{1,4}",
        ) {
            let contents: String = entries.iter().map(|(k, v)| format!("{k} {v}\n")).collect();
            for (k, v) in &entries {
                prop_assert_eq!(keyed(&contents, k), Some(*v));
            }
            prop_assert_eq!(keyed(&contents, &missing), None);
        }
    }

    #[test]
    fn memory_max_reads_max_as_unlimited() {
        assert_eq!(parse_max("max\n"), Ok(None));
        assert_eq!(parse_max("1073741824\n"), Ok(Some(1 << 30)));
        assert!(parse_max("lots").is_err());
    }
}
