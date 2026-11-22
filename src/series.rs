//! The memory time series (`[measure.series]`, `--series FILE`): each memory
//! sample as read, in order, written as columns. At most `max_samples`
//! samples taken while the program runs are kept, and the one taken right
//! after its process was reaped always is; the others are only counted.
//!
//! Each row also lists the sample's `max_processes` largest processes, by
//! resident set, and sums the rest into `others`, so the listed figures and
//! `others` add up to the sample's. A process is its pid and start time; the
//! process table holds each listed process once, with its latest name.
//!
//! Every figure is held as a varint of its delta from the row before
//! ([`codec`]), and decoded only while the file is written.
//!
//! Pure: [`crate::memory::Tally`] feeds it, `main` writes it.

mod codec;

use crate::log;
use crate::memory::{kib, Peaks, ProcKey, ProcMem, ProcRead, Sample};
use crate::policy::{MeasureCfg, SeriesCfg, SeriesCompression};
use crate::procfs::Comm;
use codec::{room_for, Column, OptColumn, RankColumn, Room};
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use std::cmp::{Ordering, Reverse};
use std::collections::btree_map::{self, BTreeMap};
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

/// How many of each sample's processes a row lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessColumns {
    /// `max_processes = 0`: `processes`, `process_rows` and the `others_*`
    /// columns are `null`.
    Absent,
    /// The largest ones, and the others summed.
    Top(NonZeroU32),
}

impl ProcessColumns {
    pub fn new(max_processes: u32) -> ProcessColumns {
        NonZeroU32::new(max_processes).map_or(ProcessColumns::Absent, ProcessColumns::Top)
    }

    /// The most processes a row lists.
    pub fn max(self) -> u32 {
        match self {
            ProcessColumns::Absent => 0,
            ProcessColumns::Top(n) => n.get(),
        }
    }
}

/// When a sample was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// While the program runs: kept while fewer than `max_samples` are.
    Running,
    /// Right after the program's process was reaped: always kept.
    Final,
}

/// What a series records, and how its file is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeriesSpec {
    pub interval_ms: u64,
    pub max_samples: NonZeroU32,
    /// The measured tmpfs mounts, sorted as the report keys them; entry i of
    /// a row's `tmpfs_kib` is mount i.
    pub tmpfs: Vec<PathBuf>,
    pub cgroup: CgroupColumns,
    pub processes: ProcessColumns,
    /// The file only: the series in memory is the same either way.
    pub compression: SeriesCompression,
}

impl SeriesSpec {
    /// None unless sampling and the series are both on.
    pub fn new(cfg: &MeasureCfg, cgroup: CgroupColumns) -> Option<SeriesSpec> {
        let MeasureCfg::Sampled {
            interval_ms,
            tmpfs,
            series:
                SeriesCfg::On {
                    max_samples,
                    max_processes,
                    compression,
                },
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
            processes: ProcessColumns::new(*max_processes),
            compression: *compression,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CgroupKib {
    pub anon_kib: u64,
    pub shmem_kib: u64,
}

/// The processes of a sample that its row does not list, summed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Others {
    pub processes: u32,
    pub mem: ProcMem,
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
    /// Every process under [`ProcessColumns::Absent`], which writes none.
    pub others: Others,
}

/// Rank order: the larger resident set first, then the smaller (pid, start).
fn by_rank(a: &ProcRead, b: &ProcRead) -> Ordering {
    (Reverse(a.mem.rss_kib()), a.key).cmp(&(Reverse(b.mem.rss_kib()), b.key))
}

/// The first `n` of a sample's processes in rank order, and the rest summed.
pub fn rank(procs: &[ProcRead], n: usize) -> (Vec<&ProcRead>, Others) {
    let mut top: Vec<&ProcRead> = procs.iter().collect();
    if n < top.len() {
        // The n first in rank order to the front, in any order.
        top.select_nth_unstable_by(n, |a, b| by_rank(a, b));
    }
    let rest = top.split_off(n.min(top.len()));
    top.sort_unstable_by(|a, b| by_rank(a, b));
    let others = rest.iter().fold(Others::default(), |o, p| Others {
        processes: o.processes.saturating_add(1),
        mem: ProcMem {
            anon_kib: o.mem.anon_kib.saturating_add(p.mem.anon_kib),
            file_kib: o.mem.file_kib.saturating_add(p.mem.file_kib),
            shmem_kib: o.mem.shmem_kib.saturating_add(p.mem.shmem_kib),
        },
    });
    (top, others)
}

impl Row {
    /// The row, and the processes it lists in rank order: the first
    /// `min(max_processes, live_processes)`.
    pub fn of<'s>(spec: &SeriesSpec, t_us: u64, s: &'s Sample) -> (Row, Vec<&'s ProcRead>) {
        // The same figures the report's peaks are taken over.
        let p = Peaks::of(s);
        let (top, others) = rank(&s.procs, spec.processes.max() as usize);
        let row = Row {
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
            others,
        };
        (row, top)
    }
}

/// A process's index in the process table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot(pub u32);

/// One listed process of one row, as the tests decode it.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRow {
    /// Its index in the rows.
    pub row: u32,
    pub process: Slot,
    pub mem: ProcMem,
}

/// Every listed process once, in the order first listed: slots are dense,
/// since nothing is ever removed.
#[derive(Debug, Default)]
struct ProcessTable {
    slots: BTreeMap<ProcKey, Slot>,
    /// Slot i: the process and the name it had when last listed.
    procs: Vec<(ProcKey, Comm)>,
}

impl ProcessTable {
    /// `p`'s slot, new if it was never listed; `cap`: the most slots.
    fn slot(&mut self, p: &ProcRead, cap: usize) -> Slot {
        match self.slots.entry(p.key) {
            btree_map::Entry::Occupied(e) => {
                let slot = *e.get();
                self.procs[slot.0 as usize].1 = p.name;
                slot
            }
            btree_map::Entry::Vacant(e) => {
                let slot = Slot(u32::try_from(self.procs.len()).unwrap_or(u32::MAX));
                room_for(&mut self.procs, 1, cap);
                self.procs.push((p.key, p.name));
                *e.insert(slot)
            }
        }
    }
}

/// One column per figure of [`Row`], each value the delta from the row
/// before.
#[derive(Debug)]
struct RowColumns {
    t_us: Column<u64>,
    live_processes: Column<u32>,
    max_anon_kib: Column<u64>,
    max_file_kib: Column<u64>,
    max_shmem_kib: Column<u64>,
    tree_anon_kib: Column<u64>,
    memfd_kib: Column<u64>,
    sysv_shm_kib: OptColumn,
    /// One per [`SeriesSpec::tmpfs`] mount.
    tmpfs_kib: Box<[OptColumn]>,
    cgroup: CgroupStore,
    /// Kept under [`ProcessColumns::Absent`] too, where they sum every
    /// process, so that each [`Row`] comes back whole.
    others_processes: Column<u32>,
    others_anon_kib: Column<u64>,
    others_file_kib: Column<u64>,
    others_shmem_kib: Column<u64>,
}

#[derive(Debug)]
enum CgroupStore {
    /// [`CgroupColumns::Absent`]: every row's is `None`.
    Absent,
    /// `shmem` holds a value only for the rows whose read of memory.stat
    /// succeeded, the rows where `anon` is not `null`.
    Present { anon: OptColumn, shmem: Column<u64> },
}

impl RowColumns {
    /// Columns for at most `rows` rows.
    fn new(spec: &SeriesSpec, rows: usize) -> RowColumns {
        RowColumns {
            t_us: Column::new(rows),
            live_processes: Column::new(rows),
            max_anon_kib: Column::new(rows),
            max_file_kib: Column::new(rows),
            max_shmem_kib: Column::new(rows),
            tree_anon_kib: Column::new(rows),
            memfd_kib: Column::new(rows),
            sysv_shm_kib: OptColumn::new(rows),
            tmpfs_kib: spec.tmpfs.iter().map(|_| OptColumn::new(rows)).collect(),
            cgroup: match spec.cgroup {
                CgroupColumns::Absent => CgroupStore::Absent,
                CgroupColumns::Present => CgroupStore::Present {
                    anon: OptColumn::new(rows),
                    shmem: Column::new(rows),
                },
            },
            others_processes: Column::new(rows),
            others_anon_kib: Column::new(rows),
            others_file_kib: Column::new(rows),
            others_shmem_kib: Column::new(rows),
        }
    }

    fn push(&mut self, r: &Row) {
        self.t_us.push(r.t_us);
        self.live_processes.push(r.live_processes);
        self.max_anon_kib.push(r.max_anon_kib);
        self.max_file_kib.push(r.max_file_kib);
        self.max_shmem_kib.push(r.max_shmem_kib);
        self.tree_anon_kib.push(r.tree_anon_kib);
        self.memfd_kib.push(r.memfd_kib);
        self.sysv_shm_kib.push(r.sysv_shm_kib);
        for (c, v) in self.tmpfs_kib.iter_mut().zip(&r.tmpfs_kib) {
            c.push(*v);
        }
        if let CgroupStore::Present { anon, shmem } = &mut self.cgroup {
            anon.push(r.cgroup.map(|c| c.anon_kib));
            if let Some(c) = r.cgroup {
                shmem.push(c.shmem_kib);
            }
        }
        self.others_processes.push(r.others.processes);
        self.others_anon_kib.push(r.others.mem.anon_kib);
        self.others_file_kib.push(r.others.mem.file_kib);
        self.others_shmem_kib.push(r.others.mem.shmem_kib);
    }

    /// Each row's cgroup figures under [`CgroupStore::Present`]; nothing
    /// under `Absent`.
    fn cgroup(&self) -> impl Iterator<Item = Option<CgroupKib>> + '_ {
        let (anon, mut shmem) = match &self.cgroup {
            CgroupStore::Absent => (None, None),
            CgroupStore::Present { anon, shmem } => (Some(anon.values()), Some(shmem.values())),
        };
        anon.into_iter().flatten().map(move |a| {
            a.and_then(|anon_kib| {
                Some(CgroupKib {
                    anon_kib,
                    shmem_kib: shmem.as_mut()?.next()?,
                })
            })
        })
    }

    fn blocks(&self, out: &mut Vec<Block>) {
        let rooms = [
            self.t_us.room(),
            self.live_processes.room(),
            self.max_anon_kib.room(),
            self.max_file_kib.room(),
            self.max_shmem_kib.room(),
            self.tree_anon_kib.room(),
            self.memfd_kib.room(),
            self.sysv_shm_kib.room(),
            self.others_processes.room(),
            self.others_anon_kib.room(),
            self.others_file_kib.room(),
            self.others_shmem_kib.room(),
        ];
        out.extend(rooms.into_iter().map(Block::of::<u8>));
        out.extend(self.tmpfs_kib.iter().map(|c| Block::of::<u8>(c.room())));
        out.push(Block::fixed::<OptColumn>(self.tmpfs_kib.len()));
        if let CgroupStore::Present { anon, shmem } = &self.cgroup {
            out.extend([Block::of::<u8>(anon.room()), Block::of::<u8>(shmem.room())]);
        }
    }
}

/// The processes each row lists, in rank order. Row i lists the first
/// `min(max_processes, live_processes)` of its sample, so neither a count
/// nor a row index is stored.
#[derive(Debug)]
struct Listed {
    slot: RankColumn<u32>,
    anon_kib: RankColumn<u64>,
    file_kib: RankColumn<u64>,
    shmem_kib: RankColumn<u64>,
    table: ProcessTable,
    /// The most processes listed in all, over every row.
    cap: usize,
}

impl Listed {
    /// For at most `rows` rows of at most `n` processes.
    fn new(n: NonZeroU32, rows: usize) -> Listed {
        let ranks = n.get() as usize;
        let cap = rows.saturating_mul(ranks);
        Listed {
            slot: RankColumn::new(ranks, cap),
            anon_kib: RankColumn::new(ranks, cap),
            file_kib: RankColumn::new(ranks, cap),
            shmem_kib: RankColumn::new(ranks, cap),
            table: ProcessTable::default(),
            cap,
        }
    }

    /// A row's processes, in rank order.
    fn push(&mut self, top: &[&ProcRead]) {
        let (table, cap) = (&mut self.table, self.cap);
        self.slot.push_row(top.iter().map(|p| table.slot(p, cap).0));
        self.anon_kib.push_row(top.iter().map(|p| p.mem.anon_kib));
        self.file_kib.push_row(top.iter().map(|p| p.mem.file_kib));
        self.shmem_kib.push_row(top.iter().map(|p| p.mem.shmem_kib));
    }

    /// With its own box.
    fn blocks(&self, out: &mut Vec<Block>) {
        out.push(Block::fixed::<Listed>(1));
        for (bytes, state) in [
            (self.slot.room(), self.slot.state_room()),
            (self.anon_kib.room(), self.anon_kib.state_room()),
            (self.file_kib.room(), self.file_kib.state_room()),
            (self.shmem_kib.room(), self.shmem_kib.state_room()),
        ] {
            out.extend([Block::of::<u8>(bytes), Block::of::<u64>(state)]);
        }
        out.push(Block::of::<(ProcKey, Comm)>(Room {
            capacity: self.table.procs.capacity(),
            cap: self.cap,
        }));
        out.push(Block {
            now: map_cost(self.table.slots.len() as u64),
            most: map_cost(self.cap as u64),
        });
        // Writing the file decodes one of these columns at a time, with a
        // row of state of its own.
        out.push(Block {
            now: 0,
            most: vec_cost::<u64>(self.slot.ranks() as u64),
        });
    }
}

#[derive(Debug)]
enum ProcessStore {
    /// [`ProcessColumns::Absent`].
    Absent,
    /// Boxed: a series without processes does not carry the room.
    Top(Box<Listed>),
}

/// The samples of one run, as [`SeriesSpec`] says to keep them.
#[derive(Debug)]
pub struct MemorySeries {
    spec: SeriesSpec,
    columns: RowColumns,
    processes: ProcessStore,
    /// Every sample taken: the rows kept and the `dropped`.
    samples: u64,
    /// Running samples taken once `max_samples` were kept.
    dropped: u64,
}

/// What the allocator adds to each allocation, rounded up.
const ALLOC_OVERHEAD: u64 = 16;

/// The heap bytes of a vector of `cap` elements of `T`.
fn vec_cost<T>(cap: u64) -> u64 {
    match cap {
        0 => 0,
        n => n.saturating_mul(size_of::<T>() as u64).saturating_add(ALLOC_OVERHEAD),
    }
}

/// The least entries in a node of std's B-tree but the root, as long as
/// nothing is removed (`MIN_LEN_AFTER_SPLIT` in alloc/collections/btree/node.rs).
const BTREE_MIN_LEN: u64 = 5;

/// The most bytes of one node of the slot map: a header (parent pointer,
/// index and length), 11 keys and values, and an internal node's 12 child
/// pointers, plus the allocator's overhead.
const BTREE_NODE: u64 = {
    let bytes = 16 + 11 * (size_of::<ProcKey>() + size_of::<Slot>()) + 12 * size_of::<usize>();
    bytes.next_multiple_of(8) as u64 + ALLOC_OVERHEAD
};

/// The most heap bytes the slot map takes with `n` entries: every node but
/// the root holds at least [`BTREE_MIN_LEN`], so there are at most 1 + n/5.
fn map_cost(n: u64) -> u64 {
    match n {
        0 => 0,
        n => (1 + n / BTREE_MIN_LEN).saturating_mul(BTREE_NODE),
    }
}

/// One heap block of a series: the bytes it takes now, and the most it can
/// take. [`MemorySeries::footprint`] and [`bound`] sum them.
#[derive(Clone, Copy, Debug)]
struct Block {
    now: u64,
    most: u64,
}

impl Block {
    /// A vector of `T` with `room`.
    fn of<T>(room: Room) -> Block {
        Block {
            now: vec_cost::<T>(room.capacity as u64),
            most: vec_cost::<T>(room.cap as u64),
        }
    }

    /// A block that never grows: `n` elements of `T`.
    fn fixed<T>(n: usize) -> Block {
        let cost = vec_cost::<T>(n as u64);
        Block { now: cost, most: cost }
    }
}

/// The most heap memory a series of this spec can take, with the cgroup
/// columns: `max_samples` running rows and the final one, each listing
/// `max_processes` processes never listed before, and every varint as long
/// as its type allows. That is [`MemorySeries::footprint`] at its most,
/// plus the state writing the file decodes with. An empty series allocates
/// nothing that grows with the spec, so it is built to count.
pub fn bound(max_samples: NonZeroU32, n_tmpfs: usize, max_processes: u32) -> u64 {
    MemorySeries::new(SeriesSpec {
        interval_ms: 1,
        max_samples,
        tmpfs: vec![PathBuf::new(); n_tmpfs],
        cgroup: CgroupColumns::Present,
        processes: ProcessColumns::new(max_processes),
        compression: SeriesCompression::None,
    })
    .bound()
}

impl MemorySeries {
    pub fn new(spec: SeriesSpec) -> MemorySeries {
        let rows = (spec.max_samples.get() as usize).saturating_add(1);
        MemorySeries {
            columns: RowColumns::new(&spec, rows),
            processes: match spec.processes {
                ProcessColumns::Absent => ProcessStore::Absent,
                ProcessColumns::Top(n) => ProcessStore::Top(Box::new(Listed::new(n, rows))),
            },
            spec,
            samples: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, t_us: u64, s: &Sample, when: When) {
        let keep = match when {
            When::Running => self.kept() < u64::from(self.spec.max_samples.get()),
            When::Final => true,
        };
        self.samples += 1;
        if !keep {
            self.dropped += 1;
            return;
        }
        let (row, top) = Row::of(&self.spec, t_us, s);
        self.columns.push(&row);
        if let ProcessStore::Top(l) = &mut self.processes {
            l.push(&top);
        }
    }

    /// The rows kept.
    pub fn kept(&self) -> u64 {
        self.samples - self.dropped
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The processes in the process table.
    pub fn listed(&self) -> usize {
        match &self.processes {
            ProcessStore::Absent => 0,
            ProcessStore::Top(l) => l.table.procs.len(),
        }
    }

    pub fn compression(&self) -> SeriesCompression {
        self.spec.compression
    }

    /// How many processes each row lists, row after row.
    fn lengths(&self) -> impl Iterator<Item = usize> + '_ {
        let n = self.spec.processes.max() as usize;
        self.columns.live_processes.values().map(move |l| (l as usize).min(n))
    }

    fn blocks(&self) -> Vec<Block> {
        let mut out = Vec::new();
        self.columns.blocks(&mut out);
        if let ProcessStore::Top(l) = &self.processes {
            l.blocks(&mut out);
        }
        out
    }

    /// The heap bytes the series holds, modelled as [`bound`] models them.
    pub fn footprint(&self) -> u64 {
        self.blocks().iter().fold(0, |b, x| b.saturating_add(x.now))
    }

    /// [`bound`] of this series' spec, with its own cgroup columns.
    pub fn bound(&self) -> u64 {
        self.blocks().iter().fold(0, |b, x| b.saturating_add(x.most))
    }
}

/// A column, decoded as it is written: `F` gives a fresh iterator.
struct Seq<F>(F);

impl<F, I> Serialize for Seq<F>
where
    F: Fn() -> I,
    I: IntoIterator,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_seq((self.0)())
    }
}

/// `{"interval_ms", "max_samples", "max_processes", "samples", "dropped",
/// "rows", "processes", "process_rows"}`, each table one array per column,
/// decoded from the columns while streaming.
impl Serialize for MemorySeries {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let listed = match &self.processes {
            ProcessStore::Absent => None,
            ProcessStore::Top(l) => Some(l),
        };
        let mut m = ser.serialize_struct("MemorySeries", 8)?;
        m.serialize_field("interval_ms", &self.spec.interval_ms)?;
        m.serialize_field("max_samples", &self.spec.max_samples)?;
        m.serialize_field("max_processes", &self.spec.processes.max())?;
        m.serialize_field("samples", &self.samples)?;
        m.serialize_field("dropped", &self.dropped)?;
        m.serialize_field("rows", &Columns(self))?;
        m.serialize_field("processes", &listed.map(|l| Processes(&l.table.procs)))?;
        m.serialize_field("process_rows", &listed.map(|l| ProcessRows(self, l)))?;
        m.end()
    }
}

struct Columns<'a>(&'a MemorySeries);

impl Serialize for Columns<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let c = &self.0.columns;
        let present = matches!(c.cgroup, CgroupStore::Present { .. });
        let listed = matches!(self.0.processes, ProcessStore::Top(_));
        let mut m = ser.serialize_struct("Rows", 15)?;
        m.serialize_field("t_us", &Seq(|| c.t_us.values()))?;
        m.serialize_field("live_processes", &Seq(|| c.live_processes.values()))?;
        m.serialize_field("max_anon_kib", &Seq(|| c.max_anon_kib.values()))?;
        m.serialize_field("max_file_kib", &Seq(|| c.max_file_kib.values()))?;
        m.serialize_field("max_shmem_kib", &Seq(|| c.max_shmem_kib.values()))?;
        m.serialize_field("tree_anon_kib", &Seq(|| c.tree_anon_kib.values()))?;
        m.serialize_field("memfd_kib", &Seq(|| c.memfd_kib.values()))?;
        m.serialize_field("sysv_shm_kib", &Seq(|| c.sysv_shm_kib.values()))?;
        m.serialize_field("tmpfs_kib", &Tmpfs(self.0))?;
        m.serialize_field(
            "cgroup_anon_kib",
            &present.then_some(Seq(|| c.cgroup().map(|x| x.map(|x| x.anon_kib)))),
        )?;
        m.serialize_field(
            "cgroup_shmem_kib",
            &present.then_some(Seq(|| c.cgroup().map(|x| x.map(|x| x.shmem_kib)))),
        )?;
        m.serialize_field(
            "others_processes",
            &listed.then_some(Seq(|| c.others_processes.values())),
        )?;
        m.serialize_field("others_anon_kib", &listed.then_some(Seq(|| c.others_anon_kib.values())))?;
        m.serialize_field("others_file_kib", &listed.then_some(Seq(|| c.others_file_kib.values())))?;
        m.serialize_field(
            "others_shmem_kib",
            &listed.then_some(Seq(|| c.others_shmem_kib.values())),
        )?;
        m.end()
    }
}

/// `{"pid", "start_ticks", "name"}`: slot i is entry i.
struct Processes<'a>(&'a [(ProcKey, Comm)]);

impl Serialize for Processes<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let p = self.0;
        let mut m = ser.serialize_struct("Processes", 3)?;
        m.serialize_field("pid", &Seq(|| p.iter().map(|e| e.0.pid)))?;
        m.serialize_field("start_ticks", &Seq(|| p.iter().map(|e| e.0.start.0)))?;
        // The sandbox picks its names: escaped as the log escapes them.
        m.serialize_field("name", &Seq(|| p.iter().map(|e| log::untrusted_bytes(e.1.as_bytes()))))?;
        m.end()
    }
}

/// `{"row", "process", "anon_kib", "file_kib", "shmem_kib"}`, by row, then
/// in rank order.
struct ProcessRows<'a>(&'a MemorySeries, &'a Listed);

impl Serialize for ProcessRows<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let (s, l) = (self.0, self.1);
        let mut m = ser.serialize_struct("ProcessRows", 5)?;
        m.serialize_field(
            "row",
            &Seq(|| s.lengths().enumerate().flat_map(|(i, n)| std::iter::repeat_n(i, n))),
        )?;
        m.serialize_field("process", &Seq(|| l.slot.values(s.lengths())))?;
        m.serialize_field("anon_kib", &Seq(|| l.anon_kib.values(s.lengths())))?;
        m.serialize_field("file_kib", &Seq(|| l.file_kib.values(s.lengths())))?;
        m.serialize_field("shmem_kib", &Seq(|| l.shmem_kib.values(s.lengths())))?;
        m.end()
    }
}

/// `{"<mount>": [...]}` per measured tmpfs mount.
struct Tmpfs<'a>(&'a MemorySeries);

impl Serialize for Tmpfs<'_> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let s = self.0;
        ser.collect_map(
            s.spec
                .tmpfs
                .iter()
                .zip(&s.columns.tmpfs_kib)
                .map(|(path, c)| (path.display().to_string(), Seq(|| c.values()))),
        )
    }
}

/// The rows and the listed processes, decoded as the file is.
#[cfg(test)]
impl MemorySeries {
    pub fn rows(&self) -> Vec<Row> {
        let c = &self.columns;
        let (mut t_us, mut live, mut max_anon, mut max_file, mut max_shmem, mut tree_anon, mut memfd) = (
            c.t_us.values(),
            c.live_processes.values(),
            c.max_anon_kib.values(),
            c.max_file_kib.values(),
            c.max_shmem_kib.values(),
            c.tree_anon_kib.values(),
            c.memfd_kib.values(),
        );
        let mut sysv = c.sysv_shm_kib.values();
        let mut tmpfs: Vec<_> = c.tmpfs_kib.iter().map(OptColumn::values).collect();
        let mut cgroup = c.cgroup();
        let (mut op, mut oa, mut of, mut os) = (
            c.others_processes.values(),
            c.others_anon_kib.values(),
            c.others_file_kib.values(),
            c.others_shmem_kib.values(),
        );
        std::iter::from_fn(|| {
            Some(Row {
                t_us: t_us.next()?,
                live_processes: live.next()?,
                max_anon_kib: max_anon.next()?,
                max_file_kib: max_file.next()?,
                max_shmem_kib: max_shmem.next()?,
                tree_anon_kib: tree_anon.next()?,
                memfd_kib: memfd.next()?,
                sysv_shm_kib: sysv.next()?,
                tmpfs_kib: tmpfs.iter_mut().map(Iterator::next).collect::<Option<_>>()?,
                cgroup: cgroup.next().flatten(),
                others: Others {
                    processes: op.next()?,
                    mem: ProcMem {
                        anon_kib: oa.next()?,
                        file_kib: of.next()?,
                        shmem_kib: os.next()?,
                    },
                },
            })
        })
        .collect()
    }

    pub fn entries(&self) -> Vec<ProcessRow> {
        let ProcessStore::Top(l) = &self.processes else {
            return vec![];
        };
        let rows = self
            .lengths()
            .enumerate()
            .flat_map(|(i, n)| std::iter::repeat_n(i as u32, n));
        rows.zip(l.slot.values(self.lengths()))
            .zip(l.anon_kib.values(self.lengths()))
            .zip(l.file_kib.values(self.lengths()))
            .zip(l.shmem_kib.values(self.lengths()))
            .map(|((((row, slot), anon_kib), file_kib), shmem_kib)| ProcessRow {
                row,
                process: Slot(slot),
                mem: ProcMem {
                    anon_kib,
                    file_kib,
                    shmem_kib,
                },
            })
            .collect()
    }

    /// The process table: slot i is entry i.
    pub fn procs(&self) -> &[(ProcKey, Comm)] {
        match &self.processes {
            ProcessStore::Absent => &[],
            ProcessStore::Top(l) => &l.table.procs,
        }
    }

    /// The processes in the slot map.
    fn slots(&self) -> usize {
        match &self.processes {
            ProcessStore::Absent => 0,
            ProcessStore::Top(l) => l.table.slots.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::tests::{comm, sample_of, TMPFS};
    use crate::memory::{CgroupMem, Pid, Tally};
    use crate::procfs::StartTicks;
    use crate::report::{series_file, series_json};
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::io::Read;
    use std::time::Duration;

    const STEP_US: u64 = 20_000;

    fn spec(max_samples: u32, n_tmpfs: usize, cgroup: bool, max_processes: u32) -> SeriesSpec {
        SeriesSpec {
            interval_ms: STEP_US / 1000,
            max_samples: NonZeroU32::new(max_samples).unwrap(),
            tmpfs: TMPFS[..n_tmpfs].iter().map(PathBuf::from).collect(),
            cgroup: if cgroup {
                CgroupColumns::Present
            } else {
                CgroupColumns::Absent
            },
            processes: ProcessColumns::new(max_processes),
            compression: SeriesCompression::None,
        }
    }

    /// A spec, the samples taken while the program ran, and the final one.
    fn run() -> impl Strategy<Value = (SeriesSpec, Vec<Sample>, Sample)> {
        (1..12u32, 0..=TMPFS.len(), any::<bool>(), 0..5u32).prop_flat_map(|(max, n, cg, procs)| {
            (
                Just(spec(max, n, cg, procs)),
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

    /// Brute force: the `n` first of a sample's processes when all are
    /// sorted by resident set, largest first, then by (pid, start).
    fn largest(s: &Sample, n: u32) -> Vec<ProcRead> {
        let mut v = s.procs.clone();
        v.sort_by_key(|p| (Reverse(p.mem.anon_kib + p.mem.file_kib + p.mem.shmem_kib), p.key));
        v.truncate(n as usize);
        v
    }

    /// Larger resident set first, then (pid, start), as in the JSON.
    type Rank = (Reverse<u64>, (u64, u64));

    /// Row i's listed processes, through the process table.
    fn listed_in(s: &MemorySeries, i: usize) -> Vec<(ProcKey, ProcMem)> {
        s.entries()
            .iter()
            .filter(|e| e.row as usize == i)
            .map(|e| (s.procs()[e.process.0 as usize].0, e.mem))
            .collect()
    }

    /// The file as `main` writes it.
    fn file(s: &MemorySeries) -> Vec<u8> {
        let mut out = vec![];
        series_file(&mut out, "v0.5", s).unwrap();
        out
    }

    fn json(s: &MemorySeries) -> serde_json::Value {
        serde_json::from_slice(&file(s)).unwrap()
    }

    fn numbers(v: &serde_json::Value) -> Vec<u64> {
        v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect()
    }

    /// Whose processes a sample lists.
    #[derive(Clone, Copy, Debug)]
    enum Procs {
        /// Processes no other sample has: the process table's worst case.
        New,
        /// The same as every other sample: the table stays small, so what
        /// each rank costs shows.
        Same,
    }

    /// Sample `i` at its worst for the series' memory: `k` processes,
    /// figures far from the last sample's (half the range for the cgroup,
    /// memfd, SysV and tmpfs bytes; a delta of 2^56 KiB per process, so
    /// that the sums of up to 128 stay in range), and a failed read every third sample.
    fn worst(i: usize, k: usize, n_tmpfs: usize, procs: Procs) -> Sample {
        let far = |x: u64| if i.is_multiple_of(2) { 0 } else { x };
        let read = |x: u64| (i % 3 != 2).then(|| far(x));
        let id = match procs {
            Procs::New => i,
            Procs::Same => 0,
        };
        Sample {
            procs: (0..k)
                .map(|j| ProcRead {
                    key: ProcKey {
                        pid: (id * 128 + j) as Pid + 1,
                        start: StartTicks(id as u64),
                    },
                    name: Comm::new(b"worst"),
                    mem: ProcMem {
                        anon_kib: far(1 << 56) + j as u64,
                        file_kib: far(1 << 56),
                        shmem_kib: far(1 << 56),
                    },
                })
                .collect(),
            memfd_bytes: far(1 << 63),
            sysv_bytes: read(1 << 63),
            tmpfs_bytes: TMPFS[..n_tmpfs]
                .iter()
                .map(|m| (PathBuf::from(m), read(1 << 63)))
                .collect(),
            cgroup: read(1 << 63).map(|b| CgroupMem {
                anon_bytes: b,
                shmem_bytes: b,
            }),
        }
    }

    /// A time half the range away from the last one's.
    fn worst_t(i: usize) -> u64 {
        if i.is_multiple_of(2) {
            0
        } else {
            1 << 63
        }
    }

    /// A series of `pushes` running samples and the final one, at their worst.
    fn worst_series(spec: SeriesSpec, k: usize, pushes: usize, procs: Procs) -> MemorySeries {
        let n = spec.tmpfs.len();
        let mut s = MemorySeries::new(spec);
        for i in 0..pushes {
            s.push(worst_t(i), &worst(i, k, n, procs), When::Running);
        }
        s.push(worst_t(pushes), &worst(pushes, k, n, procs), When::Final);
        s
    }

    proptest! {
        #[test]
        fn kept_rows_are_the_first_samples_and_the_final_one((spec, running, last) in run()) {
            let s = record(&spec, &running, &last);
            let kept = running.len().min(spec.max_samples.get() as usize);
            let mut want: Vec<Row> = running[..kept]
                .iter()
                .enumerate()
                .map(|(i, x)| Row::of(&spec, i as u64 * STEP_US, x).0)
                .collect();
            want.push(Row::of(&spec, running.len() as u64 * STEP_US, &last).0);
            prop_assert_eq!(s.rows(), want);
            prop_assert_eq!(s.samples, running.len() as u64 + 1);
            prop_assert_eq!(s.dropped(), (running.len() - kept) as u64);
            prop_assert_eq!(s.kept(), s.rows().len() as u64);
            prop_assert_eq!(s.samples, s.kept() + s.dropped());
        }

        #[test]
        fn listed_processes_are_the_largest_of_their_sample((spec, running, last) in run()) {
            let s = record(&spec, &running, &last);
            for (i, x) in kept(&spec, &running, &last).into_iter().enumerate() {
                let want: Vec<(ProcKey, ProcMem)> =
                    largest(x, spec.processes.max()).iter().map(|p| (p.key, p.mem)).collect();
                prop_assert_eq!(listed_in(&s, i), want, "row {}", i);
            }
        }

        #[test]
        fn listed_and_others_add_up_to_the_sample((spec, running, last) in run()) {
            let s = record(&spec, &running, &last);
            for (i, (row, x)) in s.rows().iter().zip(kept(&spec, &running, &last)).enumerate() {
                let listed = listed_in(&s, i);
                let sum = |f: fn(&ProcMem) -> u64| listed.iter().map(|(_, m)| f(m)).sum::<u64>();
                let all = |f: fn(&ProcMem) -> u64| x.procs.iter().map(|p| f(&p.mem)).sum::<u64>();
                prop_assert_eq!(listed.len() as u32 + row.others.processes, row.live_processes, "row {}", i);
                prop_assert_eq!(sum(|m| m.anon_kib) + row.others.mem.anon_kib, row.tree_anon_kib, "row {}", i);
                prop_assert_eq!(sum(|m| m.file_kib) + row.others.mem.file_kib, all(|m| m.file_kib), "row {}", i);
                prop_assert_eq!(sum(|m| m.shmem_kib) + row.others.mem.shmem_kib, all(|m| m.shmem_kib), "row {}", i);
            }
        }

        #[test]
        fn the_process_table_holds_exactly_the_listed_processes_with_their_latest_name(
            (spec, running, last) in run(),
        ) {
            let s = record(&spec, &running, &last);
            // Each process a kept row lists, with the name of the last such row.
            let mut want: BTreeMap<ProcKey, Comm> = BTreeMap::new();
            for x in kept(&spec, &running, &last) {
                for p in largest(x, spec.processes.max()) {
                    want.insert(p.key, p.name);
                }
            }
            let got: BTreeMap<ProcKey, Comm> = s.procs().iter().copied().collect();
            prop_assert_eq!(got.len(), s.procs().len(), "a process twice in {:?}", s.procs());
            prop_assert_eq!(got, want);
            prop_assert_eq!(s.listed(), s.slots());
        }

        #[test]
        fn a_recycled_pid_is_a_new_process(
            pid in 1..Pid::MAX,
            first in 0..u64::MAX / 2,
            later in 1..u64::MAX / 2,
            names in (comm(), comm()),
        ) {
            let one = |start: u64, name: Comm| Sample {
                procs: vec![ProcRead { key: ProcKey { pid, start: StartTicks(start) }, name, mem: ProcMem::default() }],
                ..Sample::default()
            };
            let (old, new) = (one(first, names.0), one(first + later, names.1));
            let mut s = MemorySeries::new(spec(5, 0, false, 1));
            s.push(0, &old, When::Running);
            s.push(1, &new, When::Running);
            s.push(2, &new, When::Final);
            let slots: Vec<u32> = s.entries().iter().map(|e| e.process.0).collect();
            prop_assert_eq!(slots, vec![0, 1, 1]);
            prop_assert_eq!(s.procs(), &[(old.procs[0].key, names.0), (new.procs[0].key, names.1)][..]);
        }

        #[test]
        fn process_rows_point_at_existing_rows_and_processes((spec, running, last) in run()) {
            let s = record(&spec, &running, &last);
            let v = json(&s);
            let m = &v["memory"];
            prop_assert_eq!(&m["max_processes"], spec.processes.max());
            let ProcessColumns::Top(n) = spec.processes else {
                prop_assert!(m["processes"].is_null() && m["process_rows"].is_null(), "{}", m);
                return Ok(());
            };
            let (procs, entries) = (&m["processes"], &m["process_rows"]);
            let pid = numbers(&procs["pid"]);
            let start = numbers(&procs["start_ticks"]);
            let names = procs["name"].as_array().unwrap();
            prop_assert_eq!((pid.len(), start.len(), names.len()), (s.listed(), s.listed(), s.listed()));
            let keys: BTreeSet<(u64, u64)> = pid.iter().copied().zip(start.iter().copied()).collect();
            prop_assert_eq!(keys.len(), pid.len(), "a process twice");
            prop_assert!(names.iter().all(|n| !n.as_str().unwrap().chars().any(char::is_control)));

            let cols: Vec<Vec<u64>> = ["row", "process", "anon_kib", "file_kib", "shmem_kib"]
                .iter()
                .map(|k| numbers(&entries[*k]))
                .collect();
            let entries = s.entries().len();
            prop_assert!(cols.iter().all(|c| c.len() == entries));
            let rows = m["rows"]["t_us"].as_array().unwrap().len() as u64;
            // Per row, each entry's rank: (larger resident set first, pid, start).
            let mut per_row: BTreeMap<u64, Vec<Rank>> = BTreeMap::new();
            for i in 0..entries {
                let (row, process) = (cols[0][i], cols[1][i] as usize);
                prop_assert!(row < rows && process < pid.len(), "entry {}: row {} process {}", i, row, process);
                prop_assert!(i == 0 || cols[0][i - 1] <= row, "rows out of order");
                let rss = cols[2][i] + cols[3][i] + cols[4][i];
                per_row.entry(row).or_default().push((Reverse(rss), (pid[process], start[process])));
            }
            for (row, ranks) in per_row {
                prop_assert!(ranks.len() <= n.get() as usize, "row {} lists {}", row, ranks.len());
                prop_assert!(ranks.windows(2).all(|w| w[0] < w[1]), "row {} not in rank order: {:?}", row, ranks);
            }
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
            let rows = &rows[..];
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
            let out = file(&s);
            prop_assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1, "one line");
            prop_assert_eq!(out.last(), Some(&b'\n'));
            let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
            prop_assert_eq!(v.as_object().unwrap().len(), 2);
            prop_assert_eq!(&v["sbx_version"], "v0.5");
            let m = &v["memory"];
            prop_assert_eq!(m.as_object().unwrap().len(), 8);
            prop_assert_eq!(&m["interval_ms"], spec.interval_ms);
            prop_assert_eq!(&m["max_samples"], spec.max_samples.get());
            prop_assert_eq!(&m["max_processes"], spec.processes.max());
            prop_assert_eq!(&m["samples"], running.len() as u64 + 1);
            prop_assert_eq!(&m["dropped"], s.dropped());

            let kept = kept(&spec, &running, &last);
            let rows = m["rows"].as_object().unwrap();
            let names: BTreeSet<&str> = rows.keys().map(String::as_str).collect();
            prop_assert_eq!(names, BTreeSet::from([
                "t_us", "live_processes", "max_anon_kib", "max_file_kib", "max_shmem_kib", "tree_anon_kib",
                "memfd_kib", "sysv_shm_kib", "tmpfs_kib", "cgroup_anon_kib", "cgroup_shmem_kib",
                "others_processes", "others_anon_kib", "others_file_kib", "others_shmem_kib",
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
                all(&|s| s.procs.iter().map(|p| p.mem.anon_kib).max().unwrap_or(0))
            );
            prop_assert_eq!(
                column(&rows["max_file_kib"]),
                all(&|s| s.procs.iter().map(|p| p.mem.file_kib).max().unwrap_or(0))
            );
            prop_assert_eq!(
                column(&rows["max_shmem_kib"]),
                all(&|s| s.procs.iter().map(|p| p.mem.shmem_kib).max().unwrap_or(0))
            );
            prop_assert_eq!(column(&rows["tree_anon_kib"]), all(&|s| s.procs.iter().map(|p| p.mem.anon_kib).sum()));
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

            let others = ["others_processes", "others_anon_kib", "others_file_kib", "others_shmem_kib"];
            match spec.processes {
                ProcessColumns::Absent => {
                    prop_assert!(others.iter().all(|k| rows[*k].is_null()));
                }
                ProcessColumns::Top(n) => {
                    // What the n largest leave over.
                    let rest = |f: fn(&ProcRead) -> u64| -> Vec<Option<u64>> {
                        kept.iter()
                            .map(|s| {
                                let all: u64 = s.procs.iter().map(f).sum();
                                Some(all - largest(s, n.get()).iter().map(f).sum::<u64>())
                            })
                            .collect()
                    };
                    prop_assert_eq!(column(&rows["others_processes"]), rest(|_| 1));
                    prop_assert_eq!(column(&rows["others_anon_kib"]), rest(|p| p.mem.anon_kib));
                    prop_assert_eq!(column(&rows["others_file_kib"]), rest(|p| p.mem.file_kib));
                    prop_assert_eq!(column(&rows["others_shmem_kib"]), rest(|p| p.mem.shmem_kib));
                }
            }
        }

        /// The worst case for the process table: every sample's processes
        /// are new, and more than a row lists; and for the columns: every
        /// figure far from the last sample's.
        #[test]
        fn the_bound_covers_every_series_the_spec_allows(
            max in 1..200u32,
            n in 0..=TMPFS.len(),
            procs in 0..6u32,
            pushes in 0..500usize,
        ) {
            let spec = spec(max, n, true, procs);
            let s = worst_series(spec.clone(), procs as usize + 2, pushes, Procs::New);
            for b in s.blocks() {
                prop_assert!(b.now <= b.most, "a block above its most: {:?}", b);
            }
            prop_assert_eq!(s.bound(), bound(spec.max_samples, n, procs));
            prop_assert!(s.footprint() <= s.bound(), "{} above the bound {}", s.footprint(), s.bound());
            let without = MemorySeries::new(SeriesSpec { cgroup: CgroupColumns::Absent, ..spec });
            prop_assert!(without.bound() < s.bound(), "the cgroup columns are not counted");
        }

        /// The cost model against the heap the series really holds. With
        /// the same processes in every sample, the slot map's slack is too
        /// small to hide a missing row of state.
        #[test]
        fn the_footprint_covers_the_series_real_memory(
            max in 1..100u32,
            n in 0..=TMPFS.len(),
            procs in 0..70u32,
            pushes in 0..100usize,
            which in prop_oneof![Just(Procs::New), Just(Procs::Same)],
        ) {
            let spec = spec(max, n, true, procs);
            let (s, used) = heap::held_by(|| worst_series(spec, procs as usize + 2, pushes, which));
            prop_assert!(used <= s.footprint(), "{} bytes held, {} modelled", used, s.footprint());
        }

        #[test]
        fn gzip_output_inflates_to_the_plain_json((spec, running, last) in run()) {
            let plain = record(&spec, &running, &last);
            let mut json = vec![];
            series_json(&mut json, "v0.5", &plain).unwrap();
            prop_assert_eq!(file(&plain), json.clone(), "\"none\" writes the JSON as is");
            let gz = file(&record(&SeriesSpec { compression: SeriesCompression::Gzip, ..spec }, &running, &last));
            prop_assert_eq!(&gz[..2], &[0x1f, 0x8b][..], "the gzip magic");
            let mut inflated = vec![];
            flate2::read::GzDecoder::new(&gz[..]).read_to_end(&mut inflated).unwrap();
            prop_assert_eq!(inflated, json);
        }

        /// The slot map's model against the heap a B-tree really holds, the
        /// keys inserted in order, in reverse or shuffled.
        #[test]
        fn the_btree_model_covers_its_real_memory(n in 0..5000usize, order in 0..3u8, seed in any::<u64>()) {
            let (used, _) = btree_held(n, order, seed);
            prop_assert!(used <= map_cost(n as u64), "{} entries: {} bytes held, {} modelled", n, used, map_cost(n as u64));
        }
    }

    /// The heap bytes a slot map of `n` keys holds, and the map.
    fn btree_held(n: usize, order: u8, seed: u64) -> (u64, BTreeMap<ProcKey, Slot>) {
        let mut keys: Vec<ProcKey> = (0..n)
            .map(|i| ProcKey {
                pid: i as Pid,
                start: StartTicks(i as u64 * 7),
            })
            .collect();
        match order {
            0 => {}
            1 => keys.reverse(),
            // A deterministic shuffle.
            _ => keys.sort_by_key(|k| (k.pid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed),
        }
        let (map, used) = heap::held_by(|| {
            let mut m = BTreeMap::new();
            for (i, k) in keys.iter().enumerate() {
                m.insert(*k, Slot(i as u32));
            }
            m
        });
        (used, map)
    }

    #[test]
    fn the_btree_model_and_the_measured_figure_per_entry() {
        let n = 100_000;
        for (order, how) in [(0, "in order"), (2, "shuffled")] {
            let (used, map) = btree_held(n, order, 42);
            assert_eq!(map.len(), n);
            let model = map_cost(n as u64);
            eprintln!(
                "slot map, {n} keys {how}: {:.1} bytes per entry held, {:.1} modelled",
                used as f64 / n as f64,
                model as f64 / n as f64
            );
            assert!(used <= model, "{used} bytes held, {model} modelled");
        }
    }

    /// Heap accounting for the tests: the system allocator, counting what
    /// each thread holds. Per thread, so tests running in parallel do not
    /// see each other's allocations.
    mod heap {
        use crate::series::ALLOC_OVERHEAD;
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        struct Counting;

        thread_local! {
            // Const and without Drop: reading them never allocates.
            static BYTES: Cell<i64> = const { Cell::new(0) };
            static BLOCKS: Cell<i64> = const { Cell::new(0) };
        }

        fn add(bytes: i64, blocks: i64) {
            let _ = BYTES.try_with(|b| b.set(b.get() + bytes));
            let _ = BLOCKS.try_with(|b| b.set(b.get() + blocks));
        }

        // SAFETY: every call goes to System unchanged; only counters change.
        unsafe impl GlobalAlloc for Counting {
            unsafe fn alloc(&self, l: Layout) -> *mut u8 {
                // SAFETY: as GlobalAlloc::alloc's caller guarantees.
                let p = unsafe { System.alloc(l) };
                if !p.is_null() {
                    add(l.size() as i64, 1);
                }
                p
            }

            unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
                // SAFETY: as GlobalAlloc::alloc_zeroed's caller guarantees.
                let p = unsafe { System.alloc_zeroed(l) };
                if !p.is_null() {
                    add(l.size() as i64, 1);
                }
                p
            }

            unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
                // SAFETY: as GlobalAlloc::dealloc's caller guarantees.
                unsafe { System.dealloc(p, l) };
                add(-(l.size() as i64), -1);
            }

            unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
                // SAFETY: as GlobalAlloc::realloc's caller guarantees.
                let q = unsafe { System.realloc(p, l, new) };
                if !q.is_null() {
                    add(new as i64 - l.size() as i64, 0);
                }
                q
            }
        }

        #[global_allocator]
        static COUNTING: Counting = Counting;

        /// Run `f`; what it returns, and the heap bytes allocated meanwhile
        /// and still held, with the allocator's overhead for each block.
        pub fn held_by<T>(f: impl FnOnce() -> T) -> (T, u64) {
            let now = || (BYTES.with(Cell::get), BLOCKS.with(Cell::get));
            let before = now();
            let v = f();
            let after = now();
            let held = (after.0 - before.0) + (after.1 - before.1) * ALLOC_OVERHEAD as i64;
            (v, u64::try_from(held).unwrap_or(0))
        }
    }
}
