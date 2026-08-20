//! J.3 pure shared-resolver model (directive §9.2/§16.1, contract inv.
//! "transaction truth is the deterministic shared resolver result over an
//! immutable `ValidationBasisV1`").
//!
//! This is the CONTAINMENT-STAGE model: a pure, clock-free, I/O-free
//! resolver plus the certificate-memo (status-singleton) admission rules,
//! NOT the J.5 production integration. It exists so the production code has
//! an executable oracle for:
//! - determinism: one immutable basis, one resolution - byte-identical
//!   however many times, wherever computed (live commit, recovery, scratch
//!   replay, cache repair, differential verification all share it);
//! - memoization is a CACHE, not authority: a same-certificate retry
//!   returns the original physical record; an opposite verdict, a changed
//!   basis/apply digest, or a distinct second physical singleton record
//!   QUARANTINES - never overwrite, never last-write-wins;
//! - resolver infrastructure error never fabricates an abort: retry on the
//!   same basis within a bound, then quarantine.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// canonical digesting (FNV-1a 64; the model needs stability, not security)

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(bytes: impl IntoIterator<Item = u8>, seed: u64) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn digest_str(hash: u64, text: &str) -> u64 {
    // length-prefixed so field boundaries cannot alias
    let with_len = fnv1a((text.len() as u64).to_be_bytes(), hash);
    fnv1a(text.bytes(), with_len)
}

fn digest_u64(hash: u64, value: u64) -> u64 {
    fnv1a(value.to_be_bytes(), hash)
}

// ---------------------------------------------------------------------------
// the immutable basis

/// `ValidationBasisV1`: everything the verdict may depend on, captured once,
/// immutable. The contract fields are all here; the write/interference sets
/// stand in for the full mutation payload at model scale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationBasisV1 {
    pub database_id: String,
    pub generation: u64,
    pub commit_sequence: u64,
    pub commit_lsn: u64,
    pub iterator_snapshot_lsn: u64,
    pub checkpoint_base_lsn: u64,
    pub visibility_watermark: u64,
    pub isolation_start_sequence: u64,
    pub resolver_version: u64,
    pub source_version: u64,
    pub config_version: u64,
    pub registry_version: u64,
    pub predecessor_resolution_root: u64,
    /// keys this transaction writes
    pub write_set: Vec<String>,
    /// committed writers visible to validation: (commit_sequence, their keys)
    pub committed_interference: Vec<(u64, Vec<String>)>,
}

impl ValidationBasisV1 {
    /// Canonical digest over EVERY field, length-prefixed, order-fixed: two
    /// bases agree iff their digests do (at model scale).
    pub fn digest(&self) -> u64 {
        let mut h = FNV_OFFSET;
        h = digest_str(h, &self.database_id);
        for scalar in [
            self.generation,
            self.commit_sequence,
            self.commit_lsn,
            self.iterator_snapshot_lsn,
            self.checkpoint_base_lsn,
            self.visibility_watermark,
            self.isolation_start_sequence,
            self.resolver_version,
            self.source_version,
            self.config_version,
            self.registry_version,
            self.predecessor_resolution_root,
        ] {
            h = digest_u64(h, scalar);
        }
        h = digest_u64(h, self.write_set.len() as u64);
        for key in &self.write_set {
            h = digest_str(h, key);
        }
        h = digest_u64(h, self.committed_interference.len() as u64);
        for (seq, keys) in &self.committed_interference {
            h = digest_u64(h, *seq);
            h = digest_u64(h, keys.len() as u64);
            for key in keys {
                h = digest_str(h, key);
            }
        }
        h
    }
}

// ---------------------------------------------------------------------------
// the resolution certificate

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Commit,
    AbortConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionResolutionV1 {
    pub basis_digest: u64,
    pub verdict: Verdict,
    /// which key convicted an abort (the conflict class at model scale)
    pub conflict_class: Option<String>,
    /// digest of the normalized apply plan (Commit) - absent on abort
    pub apply_plan_digest: Option<u64>,
    /// digest binding (basis, verdict, plan): the certificate identity
    pub resolution_digest: u64,
}

/// The pure shared resolver. No clocks, no randomness, no I/O, no ambient
/// state: the verdict is a mathematical function of the basis.
pub fn resolve(basis: &ValidationBasisV1) -> TransactionResolutionV1 {
    let basis_digest = basis.digest();
    // serializability check at model scale: a committed writer whose
    // sequence lands inside our isolation window and whose write set
    // intersects ours convicts a deterministic conflict. First convicting
    // (sequence, key) in canonical order names the conflict class, so even
    // the abort REASON is deterministic.
    let mut convicted: Option<(u64, String)> = None;
    for (seq, keys) in &basis.committed_interference {
        if *seq <= basis.isolation_start_sequence || *seq >= basis.commit_sequence {
            continue; // outside the isolation window: not interference
        }
        for key in keys {
            if basis.write_set.contains(key) {
                let candidate = (*seq, key.clone());
                if convicted.as_ref().is_none_or(|current| candidate < *current) {
                    convicted = Some(candidate);
                }
            }
        }
    }
    let (verdict, conflict_class, apply_plan_digest) = match convicted {
        Some((seq, key)) => (Verdict::AbortConflict, Some(format!("ww-conflict/{seq}/{key}")), None),
        None => {
            // normalized apply plan: the write set in canonical order under
            // the commit sequence
            let mut plan = digest_u64(basis_digest, basis.commit_sequence);
            let mut ordered: Vec<&String> = basis.write_set.iter().collect();
            ordered.sort();
            for key in ordered {
                plan = digest_str(plan, key);
            }
            (Verdict::Commit, None, Some(plan))
        }
    };
    let mut resolution_digest = digest_u64(FNV_OFFSET, basis_digest);
    resolution_digest = digest_u64(resolution_digest, matches!(verdict, Verdict::Commit) as u64);
    if let Some(class) = &conflict_class {
        resolution_digest = digest_str(resolution_digest, class);
    }
    if let Some(plan) = apply_plan_digest {
        resolution_digest = digest_u64(resolution_digest, plan);
    }
    TransactionResolutionV1 { basis_digest, verdict, conflict_class, apply_plan_digest, resolution_digest }
}

// ---------------------------------------------------------------------------
// infrastructure-error containment (directive §9.2 step 5)

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    Resolved(TransactionResolutionV1),
    /// retries exhausted: recovery's problem - NEVER an abort verdict
    Quarantined {
        attempts: u32,
    },
}

/// Drive `resolve` through an infrastructure-fault schedule: `faults[i]`
/// true means attempt i dies before producing a result. A fault is retried
/// on the SAME basis up to `bound` attempts; exhaustion quarantines.
pub fn resolve_with_faults(basis: &ValidationBasisV1, faults: &[bool], bound: u32) -> ResolveOutcome {
    for attempt in 0..bound {
        let faulted = faults.get(attempt as usize).copied().unwrap_or(false);
        if !faulted {
            return ResolveOutcome::Resolved(resolve(basis));
        }
    }
    ResolveOutcome::Quarantined { attempts: bound }
}

// ---------------------------------------------------------------------------
// the certificate memo (status singleton) admission rules

/// Unique logical key of one transaction's status singleton.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatusKey {
    pub database_id: String,
    pub generation: u64,
    pub commit_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRecord {
    /// physical identity assigned at first admission (append LSN stand-in)
    pub record_id: u64,
    pub resolution: TransactionResolutionV1,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// first admission: a new physical record now exists
    Recorded(u64),
    /// same-certificate retry: the ORIGINAL record answers (memo, not authority)
    Original(u64),
    /// opposite verdict / changed digest / duplicate physical record
    Quarantine(&'static str),
}

/// The status store: one physical record per logical key, admission is
/// compare-then-insert, conflicts are terminal quarantines.
#[derive(Default)]
pub struct StatusStore {
    records: BTreeMap<StatusKey, Vec<PhysicalRecord>>,
    next_record_id: u64,
}

impl StatusStore {
    pub fn admit(&mut self, key: StatusKey, resolution: TransactionResolutionV1) -> AdmitOutcome {
        let slot = self.records.entry(key).or_default();
        match slot.len() {
            0 => {
                self.next_record_id += 1;
                let id = self.next_record_id;
                slot.push(PhysicalRecord { record_id: id, resolution });
                AdmitOutcome::Recorded(id)
            }
            1 => {
                let existing = &slot[0];
                if existing.resolution == resolution {
                    AdmitOutcome::Original(existing.record_id)
                } else if existing.resolution.verdict != resolution.verdict {
                    AdmitOutcome::Quarantine("opposite-verdict")
                } else {
                    AdmitOutcome::Quarantine("changed-digest")
                }
            }
            // the durability boundary is supposed to make this unreachable;
            // if it happens anyway it is a quarantine, never a tiebreak
            _ => AdmitOutcome::Quarantine("duplicate-physical-record"),
        }
    }

    /// Model the durability-boundary failure: a second physical record got
    /// appended under one logical key (e.g. two racing recoveries). Every
    /// later admission must observe it and quarantine.
    pub fn inject_duplicate_physical(&mut self, key: StatusKey, resolution: TransactionResolutionV1) {
        self.next_record_id += 1;
        let id = self.next_record_id;
        self.records.entry(key).or_default().push(PhysicalRecord { record_id: id, resolution });
    }

    pub fn record_count(&self, key: &StatusKey) -> usize {
        self.records.get(key).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn basis(write_set: &[&str], interference: &[(u64, &[&str])]) -> ValidationBasisV1 {
        ValidationBasisV1 {
            database_id: "db1".into(),
            generation: 3,
            commit_sequence: 10,
            commit_lsn: 42,
            iterator_snapshot_lsn: 41,
            checkpoint_base_lsn: 30,
            visibility_watermark: 40,
            isolation_start_sequence: 5,
            resolver_version: 1,
            source_version: 1,
            config_version: 1,
            registry_version: 1,
            predecessor_resolution_root: 0xfeed,
            write_set: keys(write_set),
            committed_interference: interference.iter().map(|(s, k)| (*s, keys(k))).collect(),
        }
    }

    fn status_key() -> StatusKey {
        StatusKey { database_id: "db1".into(), generation: 3, commit_sequence: 10 }
    }

    /// Determinism over a bounded enumeration: every basis in the space
    /// resolves byte-identically on repeat and on a deep clone (a second
    /// "site" computing from the same immutable basis).
    #[test]
    fn one_basis_one_resolution_everywhere() {
        let key_space: &[&[&str]] = &[&[], &["a"], &["a", "b"], &["b", "c"]];
        for write_set in key_space {
            for interference_keys in key_space {
                for seq in [4u64, 5, 6, 9, 10, 11] {
                    let b = basis(write_set, &[(seq, interference_keys)]);
                    let live = resolve(&b);
                    let recovery = resolve(&b.clone());
                    let differential = resolve(&b);
                    assert_eq!(live, recovery);
                    assert_eq!(live, differential);
                    assert_eq!(live.basis_digest, b.digest());
                }
            }
        }
    }

    /// The verdict is the serializability rule and nothing else: only a
    /// committed writer strictly inside (isolation_start, commit_sequence)
    /// with an overlapping write set convicts.
    #[test]
    fn conflict_rule_is_exactly_the_isolation_window() {
        // overlap inside the window: abort, deterministically classed
        let convicted = resolve(&basis(&["a", "b"], &[(7, &["b"])]));
        assert_eq!(convicted.verdict, Verdict::AbortConflict);
        assert_eq!(convicted.conflict_class.as_deref(), Some("ww-conflict/7/b"));
        assert_eq!(convicted.apply_plan_digest, None);
        // disjoint write sets: commit
        assert_eq!(resolve(&basis(&["a"], &[(7, &["z"])])).verdict, Verdict::Commit);
        // overlap OUTSIDE the window (at or before isolation start, at or
        // after own sequence): not interference
        assert_eq!(resolve(&basis(&["a"], &[(5, &["a"])])).verdict, Verdict::Commit);
        assert_eq!(resolve(&basis(&["a"], &[(10, &["a"])])).verdict, Verdict::Commit);
        assert_eq!(resolve(&basis(&["a"], &[(11, &["a"])])).verdict, Verdict::Commit);
        // two convictions: the canonical (seq, key) minimum names the class
        let multi = resolve(&basis(&["a", "b"], &[(8, &["b"]), (6, &["a"])]));
        assert_eq!(multi.conflict_class.as_deref(), Some("ww-conflict/6/a"));
    }

    /// Every contract field is load-bearing in the basis digest: perturbing
    /// any one of them changes the digest, and the resolution certificate
    /// binds it - so "same certificate" can never span two different bases.
    #[test]
    fn every_basis_field_is_bound_by_the_digest() {
        let reference = basis(&["a"], &[(7, &["z"])]);
        let reference_digest = reference.digest();
        let mut variants: Vec<ValidationBasisV1> = Vec::new();
        macro_rules! perturb {
            ($field:ident) => {{
                let mut b = reference.clone();
                b.$field += 1;
                variants.push(b);
            }};
        }
        perturb!(generation);
        perturb!(commit_sequence);
        perturb!(commit_lsn);
        perturb!(iterator_snapshot_lsn);
        perturb!(checkpoint_base_lsn);
        perturb!(visibility_watermark);
        perturb!(isolation_start_sequence);
        perturb!(resolver_version);
        perturb!(source_version);
        perturb!(config_version);
        perturb!(registry_version);
        perturb!(predecessor_resolution_root);
        let mut renamed = reference.clone();
        renamed.database_id = "db2".into();
        variants.push(renamed);
        let mut wider = reference.clone();
        wider.write_set.push("b".into());
        variants.push(wider);
        let mut shifted = reference.clone();
        shifted.committed_interference[0].0 = 8;
        variants.push(shifted);
        for variant in &variants {
            assert_ne!(variant.digest(), reference_digest, "field not bound: {variant:?}");
            assert_ne!(resolve(variant).resolution_digest, resolve(&reference).resolution_digest);
        }
    }

    /// Memoization is a cache: a same-certificate retry returns the ORIGINAL
    /// physical record, however many times, across simulated crash-replays -
    /// the store converges on exactly one record.
    #[test]
    fn same_certificate_retry_returns_the_original_record() {
        let resolution = resolve(&basis(&["a"], &[]));
        for replays in 1..6 {
            let mut store = StatusStore::default();
            let first = store.admit(status_key(), resolution.clone());
            let AdmitOutcome::Recorded(original_id) = first else {
                panic!("first admission must record");
            };
            for _ in 0..replays {
                assert_eq!(store.admit(status_key(), resolution.clone()), AdmitOutcome::Original(original_id));
            }
            assert_eq!(store.record_count(&status_key()), 1);
        }
    }

    /// An opposite verdict or a changed digest under the same logical key is
    /// a QUARANTINE - the stored certificate is never overwritten and the
    /// second one is never silently accepted (no last-write-wins).
    #[test]
    fn conflicting_certificates_quarantine_never_overwrite() {
        let committed = resolve(&basis(&["a"], &[]));
        let aborted = resolve(&basis(&["a"], &[(7, &["a"])]));
        assert_eq!(aborted.verdict, Verdict::AbortConflict);
        // opposite verdict
        let mut store = StatusStore::default();
        store.admit(status_key(), committed.clone());
        assert_eq!(store.admit(status_key(), aborted.clone()), AdmitOutcome::Quarantine("opposite-verdict"));
        // changed digest, same verdict (a different commit's certificate)
        let other_commit = resolve(&basis(&["b"], &[]));
        assert_eq!(other_commit.verdict, Verdict::Commit);
        assert_eq!(store.admit(status_key(), other_commit), AdmitOutcome::Quarantine("changed-digest"));
        // and the original is still the one record standing
        assert_eq!(store.record_count(&status_key()), 1);
        assert_eq!(store.admit(status_key(), committed), AdmitOutcome::Original(1));
    }

    /// A second physical record under one singleton key (the durability
    /// boundary failed) quarantines every later admission - a distinct
    /// duplicate is never tiebroken.
    #[test]
    fn duplicate_physical_singleton_quarantines() {
        let resolution = resolve(&basis(&["a"], &[]));
        let mut store = StatusStore::default();
        store.admit(status_key(), resolution.clone());
        store.inject_duplicate_physical(status_key(), resolution.clone());
        assert_eq!(store.record_count(&status_key()), 2);
        assert_eq!(store.admit(status_key(), resolution), AdmitOutcome::Quarantine("duplicate-physical-record"),);
    }

    /// §9.2 step 5: infrastructure error NEVER creates an abort. Exhaust
    /// every fault schedule up to the retry bound: each either resolves to
    /// exactly the pure verdict or quarantines; no schedule can flip a
    /// commit into an abort (or invent either).
    #[test]
    fn infrastructure_error_never_fabricates_a_verdict() {
        let bound = 3u32;
        for basis in [basis(&["a"], &[]), basis(&["a"], &[(7, &["a"])])] {
            let truth = resolve(&basis);
            for schedule_bits in 0..(1u32 << bound) {
                let faults: Vec<bool> = (0..bound).map(|i| schedule_bits & (1 << i) != 0).collect();
                match resolve_with_faults(&basis, &faults, bound) {
                    ResolveOutcome::Resolved(resolution) => assert_eq!(resolution, truth),
                    ResolveOutcome::Quarantined { attempts } => {
                        assert_eq!(attempts, bound);
                        assert!(faults.iter().all(|f| *f), "quarantine requires every attempt faulted");
                    }
                }
            }
        }
    }

    /// Negative control: a resolver that reads ambient state (the defect the
    /// determinism property exists to catch) fails the one-basis-one-
    /// resolution assertion; and a last-write-wins store (the defect the
    /// quarantine rules exist to catch) fails the never-overwrite assertion.
    #[test]
    fn weakened_mutants_are_observable() {
        // MUTANT resolver: verdict depends on a call counter
        let mut calls = 0u64;
        let mut broken_resolve = |b: &ValidationBasisV1| {
            calls += 1;
            let mut r = resolve(b);
            r.resolution_digest ^= calls; // ambient state leaks into the certificate
            r
        };
        let b = basis(&["a"], &[]);
        let first = broken_resolve(&b);
        let second = broken_resolve(&b);
        assert_ne!(first, second, "the determinism assertion would fail under this mutant");

        // MUTANT store: last-write-wins overwrite
        let committed = resolve(&basis(&["a"], &[]));
        let aborted = resolve(&basis(&["a"], &[(7, &["a"])]));
        let mut lww: BTreeMap<StatusKey, TransactionResolutionV1> = BTreeMap::new();
        lww.insert(status_key(), committed.clone());
        lww.insert(status_key(), aborted.clone()); // silently replaces
        assert_eq!(
            lww.get(&status_key()),
            Some(&aborted),
            "the quarantine assertion would fail under this mutant: the verdict flipped"
        );
        let mut correct = StatusStore::default();
        correct.admit(status_key(), committed.clone());
        correct.admit(status_key(), aborted);
        assert_eq!(correct.admit(status_key(), committed), AdmitOutcome::Original(1));
    }
}
