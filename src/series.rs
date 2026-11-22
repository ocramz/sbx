//! The memory time series (`[measure.series]`, `--series FILE`): each memory
//! sample as read, in order, written as columns. At most `max_samples`
//! samples taken while the program runs are kept, and the one taken right
//! after its process was reaped always is; the others are only counted.
//!
//! Pure: [`crate::memory::Tally`] feeds it, `main` writes it.

use crate::memory::{kib, Peaks, Sample};
use crate::policy::{MeasureCfg, SeriesCfg};
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use std::mem::size_of;
use std::num::NonZeroU32;
use std::path::PathBuf;

/// Whether each sample reads a delegated cgroup's memory.stat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupColumns {
    /// No delegated cgroup: the cgroup columns are `null` as a whole.
    Absent,
    Present,
}

/// When a sample was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// While the program runs: kept while fewer than `max_samples` are.
    Running,
    /// Right after the program's process was reaped: always kept.
    Final,
}

/// What a series records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeriesSpec {
    pub interval_ms: u64,
    pub max_samples: NonZeroU32,
    /// The measured tmpfs mounts, sorted as the report keys them; entry i of
    /// a row's `tmpfs_kib` is mount i.
    pub tmpfs: Vec<PathBuf>,
    pub cgroup: CgroupColumns,
}

impl SeriesSpec {
    /// None unless sampling and the series are both on.
    pub fn new(cfg: &MeasureCfg, cgroup: CgroupColumns) -> Option<SeriesSpec> {
        let MeasureCfg::Sampled {
            interval_ms,
            tmpfs,
            series: SeriesCfg::On { max_samples },
        } = cfg
        else {
            return None;
        };
        let mut tmpfs = tmpfs.clone();
        tmpfs.sort();
        Some(SeriesSpec {
            interval_ms: interval_ms.get(),
            max_samples: *max_samples,
            tmpfs,
            cgroup,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CgroupKib {
    pub anon_kib: u64,
    pub shmem_kib: u64,
}

/// One sample, in KiB like the report. `None` is a failed read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Since the program started, the origin of the report's `wall_ms`.
    pub t_us: u64,
    /// The sandbox processes the sample read.
    pub live_processes: u32,
    pub max_anon_kib: u64,
    pub max_file_kib: u64,
    pub max_shmem_kib: u64,
    pub tree_anon_kib: u64,
    pub memfd_kib: u64,
    pub sysv_shm_kib: Option<u64>,
    /// One entry per [`SeriesSpec::tmpfs`] mount.
    pub tmpfs_kib: Box<[Option<u64>]>,
    /// Always `None` under [`CgroupColumns::Absent`].
    pub cgroup: Option<CgroupKib>,
}

impl Row {
    pub fn of(spec: &SeriesSpec, t_us: u64, s: &Sample) -> Row {
        // The same figures the report's peaks are taken over.
        let p = Peaks::of(s);
        Row {
            t_us,
            live_processes: u32::try_from(s.procs.len()).unwrap_or(u32::MAX),
            max_anon_kib: p.max_anon_kib,
            max_file_kib: p.max_file_kib,
            max_shmem_kib: p.max_shmem_kib,
            tree_anon_kib: p.tree_anon_kib,
            memfd_kib: kib(s.memfd_bytes),
            sysv_shm_kib: s.sysv_bytes.map(kib),
            tmpfs_kib: spec
                .tmpfs
                .iter()
                .map(|m| s.tmpfs_bytes.get(m).copied().flatten().map(kib))
                .collect(),
            cgroup: match spec.cgroup {
                CgroupColumns::Absent => None,
                CgroupColumns::Present => s.cgroup.map(|c| CgroupKib {
                    anon_kib: kib(c.anon_bytes),
                    shmem_kib: kib(c.shmem_bytes),
                }),
            },
        }
    }
}

/// The samples of one run, as [`SeriesSpec`] says to keep them.
#[derive(Debug)]
pub struct MemorySeries {
    spec: SeriesSpec,
    rows: Vec<Row>,
    /// Every sample taken: `rows.len() + dropped`.
    samples: u64,
    /// Running samples taken once `max_samples` were kept.
    dropped: u64,
}

/// Rows reserved at the first sample.
const FIRST_ROWS: usize = 64;

/// What the allocator adds to each allocation, rounded up.
const ALLOC_OVERHEAD: u64 = 16;

/// The heap bytes of one row's tmpfs entries.
fn tmpfs_cost(n_tmpfs: usize) -> u64 {
    match n_tmpfs {
        0 => 0,
        n => (n as u64)
            .saturating_mul(size_of::<Option<u64>>() as u64)
            .saturating_add(ALLOC_OVERHEAD),
    }
}

/// The most heap memory a series of this spec can take: `max_samples`
/// running rows and the final one, as [`MemorySeries::footprint`] counts.
pub fn bound(max_samples: NonZeroU32, n_tmpfs: usize) -> u64 {
    let rows = u64::from(max_samples.get()) + 1;
    rows.saturating_mul((size_of::<Row>() as u64).saturating_add(tmpfs_cost(n_tmpfs)))
}

impl MemorySeries {
    pub fn new(spec: SeriesSpec) -> MemorySeries {
        MemorySeries {
            spec,
            rows: Vec::new(),
            samples: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, t_us: u64, s: &Sample, when: When) {
        self.samples += 1;
        let keep = match when {
            When::Running => self.rows.len() < self.spec.max_samples.get() as usize,
            When::Final => true,
        };
        if !keep {
            self.dropped += 1;
            return;
        }
        if self.rows.len() == self.rows.capacity() {
            // Doubling, but never beyond the rows the spec allows.
            let room = (self.spec.max_samples.get() as usize + 1).saturating_sub(self.rows.len());
            self.rows
                .reserve_exact(self.rows.capacity().max(FIRST_ROWS).min(room).max(1));
        }
        self.rows.push(Row::of(&self.spec, t_us, s));
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The heap bytes the series holds, modelled as [`bound`] models them.
    pub fn footprint(&self) -> u64 {
        let rows = (self.rows.capacity() as u64).saturating_mul(size_of::<Row>() as u64);
        self.rows
            .iter()
            .fold(rows, |b, r| b.saturating_add(tmpfs_cost(r.tmpfs_kib.len())))
    }
}

/// `{"interval_ms", "max_samples", "samples", "dropped", "rows"}`, with
/// `rows` one array per column, streamed from the rows.
impl Serialize for MemorySeries {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut m = ser.serialize_struct("MemorySeries", 5)?;
        m.serialize_field("interval_ms", &self.spec.interval_ms)?;
        m.serialize_field("max_samples", &self.spec.max_samples)?;
        m.serialize_field("samples", &self.samples)?;
        m.serialize_field("dropped", &self.dropped)?;
        m.serialize_field("rows", &Columns(self))?;
        m.end()
    }
}

struct Columns<'a>(&'a MemorySeries);

impl Serialize for Columns<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let rows = &self.0.rows[..];
        let present = self.0.spec.cgroup == CgroupColumns::Present;
        let mut m = ser.serialize_struct("Rows", 11)?;
        m.serialize_field("t_us", &col(rows, |r| r.t_us))?;
        m.serialize_field("live_processes", &col(rows, |r| r.live_processes))?;
        m.serialize_field("max_anon_kib", &col(rows, |r| r.max_anon_kib))?;
        m.serialize_field("max_file_kib", &col(rows, |r| r.max_file_kib))?;
        m.serialize_field("max_shmem_kib", &col(rows, |r| r.max_shmem_kib))?;
        m.serialize_field("tree_anon_kib", &col(rows, |r| r.tree_anon_kib))?;
        m.serialize_field("memfd_kib", &col(rows, |r| r.memfd_kib))?;
        m.serialize_field("sysv_shm_kib", &col(rows, |r| r.sysv_shm_kib))?;
        m.serialize_field("tmpfs_kib", &Tmpfs(self.0))?;
        m.serialize_field(
            "cgroup_anon_kib",
            &present.then(|| col(rows, |r| r.cgroup.map(|c| c.anon_kib))),
        )?;
        m.serialize_field(
            "cgroup_shmem_kib",
            &present.then(|| col(rows, |r| r.cgroup.map(|c| c.shmem_kib))),
        )?;
        m.end()
    }
}

/// One figure of every row.
struct Column<'a, T> {
    rows: &'a [Row],
    f: fn(&Row) -> T,
}

fn col<T>(rows: &[Row], f: fn(&Row) -> T) -> Column<'_, T> {
    Column { rows, f }
}

impl<T: Serialize> Serialize for Column<'_, T> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_seq(self.rows.iter().map(self.f))
    }
}

/// `{"<mount>": [...]}` per measured tmpfs mount.
struct Tmpfs<'a>(&'a MemorySeries);

impl Serialize for Tmpfs<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let rows = &self.0.rows[..];
        ser.collect_map(
            self.0
                .spec
                .tmpfs
                .iter()
                .enumerate()
                .map(|(i, path)| (path.display().to_string(), TmpfsColumn { rows, i })),
        )
    }
}

struct TmpfsColumn<'a> {
    rows: &'a [Row],
    i: usize,
}

impl Serialize for TmpfsColumn<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_seq(self.rows.iter().map(|r| r.tmpfs_kib.get(self.i).copied().flatten()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::tests::{sample_of, TMPFS};
    use crate::memory::Tally;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::time::Duration;

    const STEP_US: u64 = 20_000;

    fn spec(max_samples: u32, n_tmpfs: usize, cgroup: bool) -> SeriesSpec {
        SeriesSpec {
            interval_ms: STEP_US / 1000,
            max_samples: NonZeroU32::new(max_samples).unwrap(),
            tmpfs: TMPFS[..n_tmpfs].iter().map(PathBuf::from).collect(),
            cgroup: if cgroup {
                CgroupColumns::Present
            } else {
                CgroupColumns::Absent
            },
        }
    }

    /// A spec, the samples taken while the program ran, and the final one.
    fn run() -> impl Strategy<Value = (SeriesSpec, Vec<Sample>, Sample)> {
        (1..12u32, 0..=TMPFS.len(), any::<bool>()).prop_flat_map(|(max, n, cg)| {
            (
                Just(spec(max, n, cg)),
                prop::collection::vec(sample_of(n, cg), 0..30),
                sample_of(n, cg),
            )
        })
    }

    fn record(spec: &SeriesSpec, running: &[Sample], last: &Sample) -> MemorySeries {
        let mut s = MemorySeries::new(spec.clone());
        for (i, x) in running.iter().enumerate() {
            s.push(i as u64 * STEP_US, x, When::Running);
        }
        s.push(running.len() as u64 * STEP_US, last, When::Final);
        s
    }

    /// The samples a series of `spec` keeps.
    fn kept<'a>(spec: &SeriesSpec, running: &'a [Sample], last: &'a Sample) -> Vec<&'a Sample> {
        let n = running.len().min(spec.max_samples.get() as usize);
        running[..n].iter().chain([last]).collect()
    }

    proptest! {
        #[test]
        fn kept_rows_are_the_first_samples_and_the_final_one((spec, running, last) in run()) {
            let s = record(&spec, &running, &last);
            let kept = running.len().min(spec.max_samples.get() as usize);
            let mut want: Vec<Row> = running[..kept]
                .iter()
                .enumerate()
                .map(|(i, x)| Row::of(&spec, i as u64 * STEP_US, x))
                .collect();
            want.push(Row::of(&spec, running.len() as u64 * STEP_US, &last));
            prop_assert_eq!(s.rows(), &want[..]);
            prop_assert_eq!(s.samples, running.len() as u64 + 1);
            prop_assert_eq!(s.dropped(), (running.len() - kept) as u64);
            prop_assert_eq!(s.samples, s.rows().len() as u64 + s.dropped());
        }

        #[test]
        fn the_series_agrees_with_the_report((spec, running, last) in run()) {
            let mut t = Tally::new(spec.interval_ms, &spec.tmpfs, Some(spec.clone()));
            let none = BTreeSet::new();
            for (i, x) in running.iter().enumerate() {
                t.record(Duration::from_micros(i as u64 * STEP_US), When::Running, x, &none, &none);
            }
            t.record(Duration::from_micros(running.len() as u64 * STEP_US), When::Final, &last, &none, &none);
            let (r, s) = t.finish();
            let s = s.unwrap();
            prop_assert_eq!(r.samples, s.samples);
            let rows = s.rows();
            let max = |f: fn(&Row) -> Option<u64>| rows.iter().filter_map(f).max().unwrap_or(0);
            let mut pairs = vec![
                ("max_anon_kib", max(|r| Some(r.max_anon_kib)), r.max_anon_kib),
                ("max_file_kib", max(|r| Some(r.max_file_kib)), r.max_file_kib),
                ("max_shmem_kib", max(|r| Some(r.max_shmem_kib)), r.max_shmem_kib),
                ("tree_anon_kib", max(|r| Some(r.tree_anon_kib)), r.tree_peak_anon_kib),
                ("memfd_kib", max(|r| Some(r.memfd_kib)), r.memfd_peak_kib),
                ("sysv_shm_kib", max(|r| r.sysv_shm_kib), r.sysv_shm_peak_kib),
                ("cgroup_anon_kib", max(|r| r.cgroup.map(|c| c.anon_kib)), r.cgroup.map_or(0, |c| c.peak_anon_kib)),
                ("cgroup_shmem_kib", max(|r| r.cgroup.map(|c| c.shmem_kib)), r.cgroup.map_or(0, |c| c.peak_shmem_kib)),
            ];
            for (i, path) in spec.tmpfs.iter().enumerate() {
                let col = rows.iter().filter_map(|r| r.tmpfs_kib[i]).max().unwrap_or(0);
                pairs.push(("tmpfs_kib", col, r.tmpfs_peak_kib[&path.display().to_string()]));
            }
            prop_assert_eq!(r.tmpfs_peak_kib.len(), spec.tmpfs.len());
            for (name, col, report) in pairs {
                prop_assert!(col <= report, "{}: {} above the report's {}", name, col, report);
                if s.dropped() == 0 {
                    prop_assert_eq!(col, report, "{}", name);
                }
            }
            if s.dropped() == 0 {
                prop_assert_eq!(r.cgroup.is_some(), rows.iter().any(|r| r.cgroup.is_some()));
            }
        }

        #[test]
        fn every_column_has_one_entry_per_row_and_null_exactly_where_reads_failed((spec, running, last) in run()) {
            let s = record(&spec, &running, &last);
            let mut out = vec![];
            crate::report::series_json(&mut out, "v0.5", &s).unwrap();
            prop_assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1, "one line");
            prop_assert_eq!(out.last(), Some(&b'\n'));
            let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
            prop_assert_eq!(v.as_object().unwrap().len(), 2);
            prop_assert_eq!(&v["sbx_version"], "v0.5");
            let m = &v["memory"];
            prop_assert_eq!(m.as_object().unwrap().len(), 5);
            prop_assert_eq!(&m["interval_ms"], spec.interval_ms);
            prop_assert_eq!(&m["max_samples"], spec.max_samples.get());
            prop_assert_eq!(&m["samples"], running.len() as u64 + 1);
            prop_assert_eq!(&m["dropped"], s.dropped());

            let kept = kept(&spec, &running, &last);
            let rows = m["rows"].as_object().unwrap();
            let names: BTreeSet<&str> = rows.keys().map(String::as_str).collect();
            prop_assert_eq!(names, BTreeSet::from([
                "t_us", "live_processes", "max_anon_kib", "max_file_kib", "max_shmem_kib", "tree_anon_kib",
                "memfd_kib", "sysv_shm_kib", "tmpfs_kib", "cgroup_anon_kib", "cgroup_shmem_kib",
            ]));
            let column = |v: &serde_json::Value| -> Vec<Option<u64>> {
                v.as_array().unwrap().iter().map(|x| if x.is_null() { None } else { Some(x.as_u64().unwrap()) }).collect()
            };
            let all = |f: &dyn Fn(&Sample) -> u64| -> Vec<Option<u64>> { kept.iter().map(|s| Some(f(s))).collect() };
            let t_us: Vec<Option<u64>> = (0..kept.len() - 1)
                .map(|i| Some(i as u64 * STEP_US))
                .chain([Some(running.len() as u64 * STEP_US)])
                .collect();
            prop_assert_eq!(column(&rows["t_us"]), t_us);
            prop_assert_eq!(column(&rows["live_processes"]), all(&|s| s.procs.len() as u64));
            prop_assert_eq!(
                column(&rows["max_anon_kib"]),
                all(&|s| s.procs.iter().map(|p| p.anon_kib).max().unwrap_or(0))
            );
            prop_assert_eq!(
                column(&rows["max_file_kib"]),
                all(&|s| s.procs.iter().map(|p| p.file_kib).max().unwrap_or(0))
            );
            prop_assert_eq!(
                column(&rows["max_shmem_kib"]),
                all(&|s| s.procs.iter().map(|p| p.shmem_kib).max().unwrap_or(0))
            );
            prop_assert_eq!(column(&rows["tree_anon_kib"]), all(&|s| s.procs.iter().map(|p| p.anon_kib).sum()));
            prop_assert_eq!(column(&rows["memfd_kib"]), all(&|s| kib(s.memfd_bytes)));
            let sysv: Vec<Option<u64>> = kept.iter().map(|s| s.sysv_bytes.map(kib)).collect();
            prop_assert_eq!(column(&rows["sysv_shm_kib"]), sysv);

            let tmpfs = rows["tmpfs_kib"].as_object().unwrap();
            let mounts: Vec<&str> = tmpfs.keys().map(String::as_str).collect();
            prop_assert_eq!(mounts, &TMPFS[..spec.tmpfs.len()]);
            for (path, col) in tmpfs {
                let want: Vec<Option<u64>> = kept
                    .iter()
                    .map(|s| s.tmpfs_bytes[&PathBuf::from(path)].map(kib))
                    .collect();
                prop_assert_eq!(column(col), want, "{}", path);
            }

            match spec.cgroup {
                CgroupColumns::Absent => {
                    prop_assert!(rows["cgroup_anon_kib"].is_null() && rows["cgroup_shmem_kib"].is_null());
                }
                CgroupColumns::Present => {
                    let anon: Vec<Option<u64>> = kept.iter().map(|s| s.cgroup.map(|c| kib(c.anon_bytes))).collect();
                    let shmem: Vec<Option<u64>> = kept.iter().map(|s| s.cgroup.map(|c| kib(c.shmem_bytes))).collect();
                    prop_assert_eq!(column(&rows["cgroup_anon_kib"]), anon);
                    prop_assert_eq!(column(&rows["cgroup_shmem_kib"]), shmem);
                }
            }
        }

        #[test]
        fn the_bound_covers_every_series_the_spec_allows(
            max in 1..200u32,
            n in 0..=TMPFS.len(),
            pushes in 0..500usize,
        ) {
            let spec = spec(max, n, true);
            let mut s = MemorySeries::new(spec.clone());
            for i in 0..pushes {
                s.push(i as u64, &Sample::default(), When::Running);
            }
            s.push(pushes as u64, &Sample::default(), When::Final);
            prop_assert!(s.rows.capacity() <= max as usize + 1, "capacity {}", s.rows.capacity());
            prop_assert!(
                s.footprint() <= bound(spec.max_samples, n),
                "{} above the bound {}", s.footprint(), bound(spec.max_samples, n)
            );
        }
    }
}
