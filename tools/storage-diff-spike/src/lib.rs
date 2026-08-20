//! SL-P0 semantics differential (local lane, pinned SlateDB f88be86d).
//!
//! TypeDB's keyspace layer assumes of its storage engine: total byte-order,
//! exact range scans over half-open bounds, atomic multi-key batches,
//! read-your-writes visibility, and reopen durability. The U2 lane (SlateDB
//! LocalFS behind `StorageFactory`, TB-P7) swaps RocksDB for SlateDB under
//! those exact assumptions — this spike validates each of them against an
//! ordered-map oracle on seeded workloads, so the swap's semantic ground is
//! proven locally before any fork surgery.

use std::collections::BTreeMap;

/// Deterministic keys/values: seeded LCG, shared prefixes to exercise
/// prefix-range scans the way TypeDB's encoding layer does.
pub struct Lcg(pub u64);

impl Lcg {
    // R6-HYGIENE-01, documented allowance: `next` is deliberately NOT
    // `Iterator::next`. This is an infinite seeded generator, not an
    // iterator - it has no `None`, and wrapping it in `Iterator` would let
    // callers reach for `take`/`collect` and quietly change how many draws a
    // differential workload makes, which is exactly the determinism this
    // oracle depends on. The clippy lint is right in general and wrong here.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }

    pub fn key(&mut self) -> Vec<u8> {
        let prefix = (self.next() % 8) as u8; // 8 keyspace-like prefixes
        let mid = (self.next() % 64) as u8;
        let tail = (self.next() % 256) as u8;
        vec![prefix, mid, tail]
    }

    pub fn value(&mut self) -> Vec<u8> {
        let n = (self.next() % 48 + 1) as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push((self.next() % 256) as u8);
        }
        v
    }
}

pub type Oracle = BTreeMap<Vec<u8>, Vec<u8>>;

/// One workload step mirrored into both the oracle and the engine under test.
#[derive(Debug, Clone)]
pub enum Op {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    /// atomic multi-key batch: all visible or none
    Batch(Vec<(Vec<u8>, Option<Vec<u8>>)>),
}

pub fn generate_workload(seed: u64, steps: usize) -> Vec<Op> {
    let mut rng = Lcg(seed);
    let mut ops = Vec::with_capacity(steps);
    for _ in 0..steps {
        match rng.next() % 10 {
            0..=5 => ops.push(Op::Put(rng.key(), rng.value())),
            6..=7 => ops.push(Op::Delete(rng.key())),
            _ => {
                let n = (rng.next() % 6 + 2) as usize;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    if rng.next().is_multiple_of(4) {
                        entries.push((rng.key(), None));
                    } else {
                        entries.push((rng.key(), Some(rng.value())));
                    }
                }
                ops.push(Op::Batch(entries));
            }
        }
    }
    ops
}

pub fn apply_to_oracle(oracle: &mut Oracle, op: &Op) {
    match op {
        Op::Put(k, v) => {
            oracle.insert(k.clone(), v.clone());
        }
        Op::Delete(k) => {
            oracle.remove(k);
        }
        Op::Batch(entries) => {
            // last-writer-wins within the batch, applied atomically
            for (k, v) in entries {
                match v {
                    Some(v) => {
                        oracle.insert(k.clone(), v.clone());
                    }
                    None => {
                        oracle.remove(k);
                    }
                }
            }
        }
    }
}

/// The prefix ranges TypeDB-style readers scan: [prefix, next) where `next`
/// is `None` for the top prefix byte (an unbounded upper end) - `0xFF + 1`
/// does not exist as a single-byte bound.
pub fn prefix_bounds(prefix: u8) -> (Vec<u8>, Option<Vec<u8>>) {
    let end = prefix.checked_add(1).map(|next| vec![next]);
    (vec![prefix], end)
}
