//! How a memory series holds its numbers: each column is an append-only
//! buffer of LEB128 varints, each the zigzag of the wrapping delta from the
//! value before it. Memory figures change slowly from one sample to the
//! next, so most of them take a byte or two.
//!
//! Pure: [`super::MemorySeries`] pushes and decodes.

use std::marker::PhantomData;

/// The most bytes a varint takes: no value is above 2^64, which needs 65
/// bits, and a byte holds 7.
pub const MAX_VARINT: usize = 10;

/// Elements reserved at a buffer's first growth.
const FIRST_RESERVE: usize = 64;

/// Make room for `extra` more elements: by doubling, but never beyond `cap`
/// in all, so that the footprint stays within the bound. The caller pushes
/// at most `cap` elements in all.
pub fn room_for<T>(v: &mut Vec<T>, extra: usize, cap: usize) {
    if v.capacity() - v.len() < extra {
        let room = cap.saturating_sub(v.len());
        v.reserve_exact(v.capacity().max(FIRST_RESERVE).min(room).max(extra));
    }
}

/// Small magnitudes to small numbers, whatever the sign: 0, -1, 1, -2 to
/// 0, 1, 2, 3.
pub fn zigzag(d: i64) -> u64 {
    ((d << 1) ^ (d >> 63)) as u64
}

pub fn unzigzag(z: u64) -> i64 {
    ((z >> 1) as i64) ^ -((z & 1) as i64)
}

/// `v` as the delta from `prev`, wrapping, so that every pair has one.
fn delta(prev: u64, v: u64) -> u64 {
    zigzag(v.wrapping_sub(prev) as i64)
}

fn undelta(prev: u64, z: u64) -> u64 {
    prev.wrapping_add(unzigzag(z) as u64)
}

/// The LEB128 bytes of `v`, low 7 bits first, the high bit set on every
/// byte but the last. Only [`Varints`] calls it, with at most 2^64.
fn encode(mut v: u128) -> ([u8; MAX_VARINT], usize) {
    let mut out = [0; MAX_VARINT];
    for (n, b) in out.iter_mut().enumerate() {
        *b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 || n + 1 == MAX_VARINT {
            return (out, n + 1);
        }
        *b |= 0x80;
    }
    (out, MAX_VARINT)
}

/// The varint at the front of `bytes`, which then holds the rest. Total: it
/// stops at the end of `bytes` too, and drops bits past the tenth byte.
fn take(bytes: &mut &[u8]) -> u128 {
    let mut v = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i < MAX_VARINT {
            v |= u128::from(b & 0x7f) << (7 * i);
        }
        if b & 0x80 == 0 {
            *bytes = &bytes[i + 1..];
            return v;
        }
    }
    *bytes = &[];
    v
}

/// A value a column holds, widened to u64 for the delta.
pub trait Word: Copy {
    /// The most bytes one value of this type takes in a [`Column`].
    const MAX_BYTES: usize;
    fn widen(self) -> u64;
    /// The inverse of [`Word::widen`] on what it returns.
    fn narrow(w: u64) -> Self;
}

impl Word for u64 {
    const MAX_BYTES: usize = MAX_VARINT;
    fn widen(self) -> u64 {
        self
    }
    fn narrow(w: u64) -> u64 {
        w
    }
}

impl Word for u32 {
    /// The delta between two u32 is below 2^32 either way, so its zigzag is
    /// below 2^33: 5 bytes of 7 bits.
    const MAX_BYTES: usize = 5;
    fn widen(self) -> u64 {
        u64::from(self)
    }
    fn narrow(w: u64) -> u32 {
        w as u32
    }
}

/// An append-only buffer of varints that never holds more than `cap` bytes.
#[derive(Debug)]
struct Varints {
    bytes: Vec<u8>,
    cap: usize,
}

impl Varints {
    fn new(cap: usize) -> Varints {
        Varints { bytes: Vec::new(), cap }
    }

    /// The caller keeps `v` at most 2^64.
    fn put(&mut self, v: u128) {
        let (b, n) = encode(v);
        room_for(&mut self.bytes, n, self.cap);
        self.bytes.extend_from_slice(&b[..n]);
    }
}

/// The elements a buffer has room for now, and the most it can ever have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Room {
    pub capacity: usize,
    pub cap: usize,
}

/// Values in order, each the delta from the one before; the first from 0.
#[derive(Debug)]
pub struct Column<T> {
    buf: Varints,
    last: u64,
    word: PhantomData<T>,
}

impl<T: Word> Column<T> {
    /// A column of at most `values` values.
    pub fn new(values: usize) -> Column<T> {
        Column {
            buf: Varints::new(values.saturating_mul(T::MAX_BYTES)),
            last: 0,
            word: PhantomData,
        }
    }

    pub fn push(&mut self, v: T) {
        let w = v.widen();
        self.buf.put(u128::from(delta(self.last, w)));
        self.last = w;
    }

    pub fn values(&self) -> impl Iterator<Item = T> + '_ {
        let mut bytes = &self.buf.bytes[..];
        let mut last = 0;
        std::iter::from_fn(move || {
            if bytes.is_empty() {
                return None;
            }
            last = undelta(last, take(&mut bytes) as u64);
            Some(T::narrow(last))
        })
    }

    pub fn room(&self) -> Room {
        Room {
            capacity: self.buf.bytes.capacity(),
            cap: self.buf.cap,
        }
    }
}

/// Values that may be missing: `null` as 0, a value as its delta from the
/// last value plus 1. A `null` leaves the last value as it was.
#[derive(Debug)]
pub struct OptColumn {
    buf: Varints,
    last: u64,
}

impl OptColumn {
    /// A column of at most `values` values; a delta plus 1 is at most 2^64.
    pub fn new(values: usize) -> OptColumn {
        OptColumn {
            buf: Varints::new(values.saturating_mul(MAX_VARINT)),
            last: 0,
        }
    }

    pub fn push(&mut self, v: Option<u64>) {
        match v {
            None => self.buf.put(0),
            Some(v) => {
                self.buf.put(u128::from(delta(self.last, v)) + 1);
                self.last = v;
            }
        }
    }

    pub fn values(&self) -> impl Iterator<Item = Option<u64>> + '_ {
        let mut bytes = &self.buf.bytes[..];
        let mut last = 0;
        std::iter::from_fn(move || {
            if bytes.is_empty() {
                return None;
            }
            match take(&mut bytes) {
                0 => Some(None),
                z => {
                    last = undelta(last, (z - 1) as u64);
                    Some(Some(last))
                }
            }
        })
    }

    pub fn room(&self) -> Room {
        Room {
            capacity: self.buf.bytes.capacity(),
            cap: self.buf.cap,
        }
    }
}

/// Rows of up to `ranks` values each, in rank order: each value is the
/// delta from the last one at the same rank, in whichever row last reached
/// it; a rank never reached before starts from 0. A process keeps its rank
/// from one sample to the next as long as its size keeps its place.
#[derive(Debug)]
pub struct RankColumn<T> {
    buf: Varints,
    /// The last value at each rank reached so far: ranks are reached in
    /// order, so this grows to at most `ranks`, and only as rows need.
    prev: Vec<u64>,
    ranks: usize,
    word: PhantomData<T>,
}

/// `v` at `rank`, the last value at each rank so far in `prev`: the value
/// before, now replaced by `v`. Ranks are reached in order.
fn replace_at(prev: &mut Vec<u64>, ranks: usize, rank: usize, v: u64) -> u64 {
    match prev.get_mut(rank) {
        Some(p) => std::mem::replace(p, v),
        None => {
            room_for(prev, 1, ranks);
            prev.push(v);
            0
        }
    }
}

impl<T: Word> RankColumn<T> {
    /// A column of rows of at most `ranks` values, and at most `values` in all.
    pub fn new(ranks: usize, values: usize) -> RankColumn<T> {
        RankColumn {
            buf: Varints::new(values.saturating_mul(T::MAX_BYTES)),
            prev: Vec::new(),
            ranks,
            word: PhantomData,
        }
    }

    /// The most values a row holds.
    pub fn ranks(&self) -> usize {
        self.ranks
    }

    /// One row, in rank order; values past the last rank are not kept.
    pub fn push_row(&mut self, row: impl IntoIterator<Item = T>) {
        for (rank, v) in row.into_iter().take(self.ranks).enumerate() {
            let w = v.widen();
            let prev = replace_at(&mut self.prev, self.ranks, rank, w);
            self.buf.put(u128::from(delta(prev, w)));
        }
    }

    /// The values row after row, given how many each row holds: the
    /// lengths are capped at [`RankColumn::ranks`] as [`Self::push_row`]
    /// caps them. Decoding holds a row of state of its own, which grows as
    /// the encoder's did.
    pub fn values<I: Iterator<Item = usize>>(&self, lengths: I) -> RankValues<'_, T, I> {
        RankValues {
            bytes: &self.buf.bytes,
            prev: Vec::new(),
            ranks: self.ranks,
            lengths,
            rank: 0,
            row_len: 0,
            word: PhantomData,
        }
    }

    pub fn room(&self) -> Room {
        Room {
            capacity: self.buf.bytes.capacity(),
            cap: self.buf.cap,
        }
    }

    /// The last values at each rank, in u64.
    pub fn state_room(&self) -> Room {
        Room {
            capacity: self.prev.capacity(),
            cap: self.ranks,
        }
    }
}

/// The values of a [`RankColumn`], decoded as they are read.
pub struct RankValues<'a, T, I> {
    bytes: &'a [u8],
    prev: Vec<u64>,
    ranks: usize,
    lengths: I,
    /// The next value's rank in the row being read, of `row_len`.
    rank: usize,
    row_len: usize,
    word: PhantomData<T>,
}

impl<T: Word, I: Iterator<Item = usize>> Iterator for RankValues<'_, T, I> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        while self.rank == self.row_len {
            self.row_len = self.lengths.next()?.min(self.ranks);
            self.rank = 0;
        }
        if self.bytes.is_empty() {
            return None;
        }
        let z = take(&mut self.bytes) as u64;
        let prev = self.prev.get(self.rank).copied().unwrap_or(0);
        let v = undelta(prev, z);
        replace_at(&mut self.prev, self.ranks, self.rank, v);
        self.rank += 1;
        Some(T::narrow(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Any value, with the extremes and the halfway point often, so that
    /// deltas wrap.
    fn word64() -> impl Strategy<Value = u64> {
        prop_oneof![
            Just(0),
            Just(u64::MAX),
            Just(1 << 63),
            Just((1 << 63) - 1),
            any::<u64>(),
            0..300u64
        ]
    }

    fn word32() -> impl Strategy<Value = u32> {
        prop_oneof![Just(0), Just(u32::MAX), Just(1 << 31), any::<u32>(), 0..300u32]
    }

    proptest! {
        #[test]
        fn varints_round_trip(
            vs in prop::collection::vec(
                prop_oneof![any::<u64>().prop_map(u128::from), Just(u128::from(u64::MAX)), Just(1u128 << 64)],
                0..20,
            ),
        ) {
            let mut buf = Varints::new(vs.len() * MAX_VARINT);
            for &v in &vs {
                let before = buf.bytes.len();
                buf.put(v);
                let n = buf.bytes.len() - before;
                prop_assert!(n <= MAX_VARINT, "{} takes {} bytes", v, n);
                let mut one = &buf.bytes[before..];
                prop_assert_eq!(take(&mut one), v);
                prop_assert!(one.is_empty(), "{} left bytes over", v);
            }
            let mut all = &buf.bytes[..];
            let back: Vec<u128> = std::iter::from_fn(|| (!all.is_empty()).then(|| take(&mut all))).collect();
            prop_assert_eq!(back, vs);
            prop_assert!(buf.bytes.capacity() <= buf.cap);
        }

        #[test]
        fn zigzag_round_trips_and_keeps_small_magnitudes_small(d in any::<i64>()) {
            prop_assert_eq!(unzigzag(zigzag(d)), d);
            prop_assert_eq!(u128::from(zigzag(d)), u128::from(d.unsigned_abs()) * 2 - u128::from(d < 0));
        }

        #[test]
        fn encoded_columns_decode_to_the_values(
            v64 in prop::collection::vec(word64(), 0..40),
            v32 in prop::collection::vec(word32(), 0..40),
            opt in prop::collection::vec(prop::option::of(word64()), 0..40),
            ranks in 1..6usize,
            rows in prop::collection::vec(prop::collection::vec(word64(), 0..8), 0..12),
        ) {
            let mut c = Column::<u64>::new(v64.len());
            v64.iter().for_each(|&v| c.push(v));
            prop_assert_eq!(c.values().collect::<Vec<_>>(), v64.clone());
            prop_assert!(c.buf.bytes.len() <= v64.len() * u64::MAX_BYTES);
            prop_assert!(c.room().capacity <= c.room().cap, "{:?}", c.room());

            let mut c = Column::<u32>::new(v32.len());
            v32.iter().for_each(|&v| c.push(v));
            prop_assert_eq!(c.values().collect::<Vec<_>>(), v32.clone());
            prop_assert!(c.buf.bytes.len() <= v32.len() * u32::MAX_BYTES, "{} bytes", c.buf.bytes.len());
            prop_assert!(c.room().capacity <= c.room().cap);

            let mut c = OptColumn::new(opt.len());
            opt.iter().for_each(|&v| c.push(v));
            prop_assert_eq!(c.values().collect::<Vec<_>>(), opt.clone());
            prop_assert!(c.buf.bytes.len() <= opt.len() * MAX_VARINT);
            prop_assert!(c.room().capacity <= c.room().cap);

            // Rows longer than `ranks` keep their first `ranks` values.
            let kept: Vec<Vec<u64>> = rows.iter().map(|r| r[..r.len().min(ranks)].to_vec()).collect();
            let n: usize = kept.iter().map(Vec::len).sum();
            let mut c = RankColumn::<u64>::new(ranks, n);
            rows.iter().for_each(|r| c.push_row(r.iter().copied()));
            let back: Vec<u64> = c.values(rows.iter().map(Vec::len)).collect();
            prop_assert_eq!(back, kept.concat());
            prop_assert!(c.buf.bytes.len() <= n * u64::MAX_BYTES);
            prop_assert!(c.room().capacity <= c.room().cap);
            prop_assert!(c.state_room().capacity <= ranks, "{:?}", c.state_room());
        }

        /// A value at an unchanged rank costs one byte if it did not change.
        #[test]
        fn a_steady_rank_takes_a_byte(v in word64(), w in word64(), times in 1..20usize) {
            let mut c = RankColumn::<u64>::new(2, 2 * (times + 1));
            for _ in 0..=times {
                c.push_row([v, w]);
            }
            let first = encode(u128::from(zigzag(v as i64))).1 + encode(u128::from(zigzag(w as i64))).1;
            prop_assert_eq!(c.buf.bytes.len(), first + 2 * times);
        }
    }

    #[test]
    fn the_largest_varint_is_ten_bytes() {
        assert_eq!(encode(1 << 64).1, MAX_VARINT);
        assert_eq!(encode(u128::from(u64::MAX)).1, MAX_VARINT);
        assert_eq!(encode((1 << 63) - 1).1, 9);
        assert_eq!(encode(127).1, 1);
        assert_eq!(encode(128).1, 2);
        // The largest zigzag of a delta between two u32.
        assert_eq!(encode(u128::from(zigzag(-i64::from(u32::MAX)))).1, u32::MAX_BYTES);
    }
}
