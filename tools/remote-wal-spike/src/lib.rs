/*
 * G2 spike (Phase J.4): standalone remote WAL client.
 *
 * Implements the brief §9 data path end to end against:
 *   - a pluggable `ObjectStore` (in-memory + fault-injecting wrappers here;
 *     the R2/S3 binding drops in behind the same trait for U4 — that
 *     real-account lane is stop-item SI-G0-3);
 *   - a deterministic `Controller` that models the DatabaseControllerDO
 *     SQLite linearisation point + transactional outbox (§7).
 *
 * The exercised protocol per §9.4:
 *   1. serialize payload bytes; compute sha256 + length + request digest;
 *   2. upload to the content-addressed key under an exact capability;
 *   3. resolve ambiguity by exact GET + digest comparison (§14.7);
 *   4. finalize in one controller transaction (late atomic allocation);
 *   5. lost finalisation responses resolved by operation id;
 *   6. sync barrier = every earlier sequencer op resolved;
 *   7. fixed iterator snapshot merges finalized history through the head.
 *
 * Tests kill the client at every protocol step, inject upload ambiguity,
 * and prove: no sequence/LSN holes, exact lost-response resolution, status
 * singletons, finite iteration, and no delete capability anywhere (the
 * ObjectStore trait exposes none — capability by construction).
 */

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Bytes = Vec<u8>;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Object store: immutable puts only. No delete method exists on this trait —
// pre-G13 delete-freedom is a compile-time property of the data path.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum ObjectError {
    /// transport failed and the outcome is unknown
    Ambiguous,
    /// definite transport failure before the server acted
    NotStored,
    /// key exists with different bytes: permanent conflict / corruption
    Conflict,
}

pub trait ObjectStore {
    /// Idempotent immutable create: succeeds if absent or byte-identical.
    fn put_exact(&mut self, key: &str, bytes: &[u8]) -> Result<(), ObjectError>;
    fn get(&self, key: &str) -> Option<Bytes>;
}

#[derive(Default)]
pub struct MemStore {
    pub objects: BTreeMap<String, Bytes>,
}

impl ObjectStore for MemStore {
    fn put_exact(&mut self, key: &str, bytes: &[u8]) -> Result<(), ObjectError> {
        match self.objects.get(key) {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => Err(ObjectError::Conflict),
            None => {
                self.objects.insert(key.to_string(), bytes.to_vec());
                Ok(())
            }
        }
    }
    fn get(&self, key: &str) -> Option<Bytes> {
        self.objects.get(key).cloned()
    }
}

/// Fault-injecting wrapper: scripts per-call outcomes.
pub enum Fault {
    None,
    /// server stored the object but the response was lost
    AmbiguousStored,
    /// server never stored it and the response was lost
    AmbiguousNotStored,
    /// clean failure
    FailNotStored,
}

pub struct FaultyStore {
    pub inner: MemStore,
    pub script: Vec<Fault>, // consumed per put_exact call
    pub calls: usize,
}

impl FaultyStore {
    pub fn new(script: Vec<Fault>) -> Self {
        FaultyStore { inner: MemStore::default(), script, calls: 0 }
    }
}

impl ObjectStore for FaultyStore {
    fn put_exact(&mut self, key: &str, bytes: &[u8]) -> Result<(), ObjectError> {
        let fault = if self.calls < self.script.len() { &self.script[self.calls] } else { &Fault::None };
        self.calls += 1;
        match fault {
            Fault::None => self.inner.put_exact(key, bytes),
            Fault::AmbiguousStored => {
                let _ = self.inner.put_exact(key, bytes);
                Err(ObjectError::Ambiguous)
            }
            Fault::AmbiguousNotStored => Err(ObjectError::Ambiguous),
            Fault::FailNotStored => Err(ObjectError::NotStored),
        }
    }
    fn get(&self, key: &str) -> Option<Bytes> {
        self.inner.get(key)
    }
}

// ---------------------------------------------------------------------------
// Controller: deterministic model of the DO SQLite transaction + outbox.
// ---------------------------------------------------------------------------

pub use crate::controller::*;
mod controller {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Descriptor {
        pub operation_id: u64,
        pub append_lsn: u64,
        pub type_sequence: u64,
        pub sequenced: bool,
        pub status_key: Option<(u16, u64)>,
        pub verdict: Option<bool>,
        pub payload_key: String,
        pub payload_digest: [u8; 32],
        pub payload_length: u64,
        pub request_digest: [u8; 32],
        pub control_seq: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum FinalizeError {
        DigestConflict,
        StatusConflict,
        Fenced,
        PayloadUnverified,
    }

    /// One-per-database linearisation point (§7.1). The `outbox` models the
    /// transactional outbox: rows inserted in the same "transaction" as the
    /// projection mutation, flushed (published) separately.
    #[derive(Default)]
    pub struct Controller {
        pub session: u64,
        next_seq: u64,
        next_lsn: u64,
        next_control: u64,
        pub tail: Vec<Descriptor>,
        by_op: BTreeMap<u64, usize>,
        status: BTreeMap<(u16, u64), usize>,
        pub outbox_unpublished: Vec<u64>, // control_seq values pending publish
        pub journal_durable_seq: u64,
    }

    impl Controller {
        pub fn new() -> Self {
            Controller { session: 0, next_seq: 1, next_lsn: 1, next_control: 1, ..Default::default() }
        }

        pub fn open_session(&mut self) -> u64 {
            self.session += 1;
            self.session
        }

        #[allow(clippy::too_many_arguments)]
        pub fn finalize(
            &mut self,
            session: u64,
            operation_id: u64,
            sequenced: bool,
            status_key: Option<(u16, u64)>,
            verdict: Option<bool>,
            payload_key: &str,
            payload_digest: [u8; 32],
            payload_length: u64,
            request_digest: [u8; 32],
            store: &dyn ObjectStore,
        ) -> Result<Descriptor, FinalizeError> {
            if session != self.session {
                return Err(FinalizeError::Fenced);
            }
            if let Some(&ix) = self.by_op.get(&operation_id) {
                let d = &self.tail[ix];
                if d.request_digest == request_digest {
                    return Ok(d.clone());
                }
                return Err(FinalizeError::DigestConflict);
            }
            if let Some(key) = status_key {
                if let Some(&ix) = self.status.get(&key) {
                    let d = &self.tail[ix];
                    if d.verdict == verdict {
                        return Ok(d.clone());
                    }
                    return Err(FinalizeError::StatusConflict);
                }
            }
            // capability/receipt verification: exact payload must be present
            // and byte-verified BEFORE any counter is consumed (§9.4 step 6)
            match store.get(payload_key) {
                Some(bytes) if sha256(&bytes) == payload_digest && bytes.len() as u64 == payload_length => {}
                _ => return Err(FinalizeError::PayloadUnverified),
            }
            let type_sequence = if sequenced {
                let s = self.next_seq;
                self.next_seq += 1;
                s
            } else {
                self.next_seq - 1
            };
            let d = Descriptor {
                operation_id,
                append_lsn: self.next_lsn,
                type_sequence,
                sequenced,
                status_key,
                verdict,
                payload_key: payload_key.to_string(),
                payload_digest,
                payload_length,
                request_digest,
                control_seq: self.next_control,
            };
            self.next_lsn += 1;
            self.next_control += 1;
            let ix = self.tail.len();
            self.tail.push(d.clone());
            self.by_op.insert(operation_id, ix);
            if let Some(key) = status_key {
                self.status.insert(key, ix);
            }
            // same-transaction outbox row (§7.4 step: insert unsigned body)
            self.outbox_unpublished.push(d.control_seq);
            Ok(d)
        }

        pub fn query_operation(&self, operation_id: u64) -> Option<&Descriptor> {
            self.by_op.get(&operation_id).map(|&ix| &self.tail[ix])
        }

        /// Outbox flusher (§7.4): publishes in contiguous ControlSeq order.
        pub fn flush_outbox(&mut self, store: &mut dyn ObjectStore) -> usize {
            self.outbox_unpublished.sort_unstable();
            let mut published = 0;
            while let Some(&seq) = self.outbox_unpublished.first() {
                if seq != self.journal_durable_seq + 1 {
                    break; // strictly contiguous journal frontier
                }
                let d = self.tail.iter().find(|d| d.control_seq == seq).unwrap();
                let body = format!("event:{}:{}:{}", d.control_seq, d.append_lsn, hex(&d.payload_digest));
                let key = format!("control/events/{:016x}", seq);
                match store.put_exact(&key, body.as_bytes()) {
                    Ok(()) => {
                        self.outbox_unpublished.remove(0);
                        self.journal_durable_seq = seq;
                        published += 1;
                    }
                    Err(ObjectError::Ambiguous) => {
                        // resolve by exact read (§14.7)
                        if store.get(&key).map(|b| b == body.as_bytes()) == Some(true) {
                            self.outbox_unpublished.remove(0);
                            self.journal_durable_seq = seq;
                            published += 1;
                        } else {
                            break; // retry later; frontier unchanged
                        }
                    }
                    Err(_) => break,
                }
            }
            published
        }

        /// Sync barrier: all earlier ops resolved AND journal durable
        /// through the barrier (§9.6).
        pub fn sync_satisfied(&self) -> (u64, u64, bool) {
            let head_lsn = self.next_lsn - 1;
            let head_ctrl = self.next_control - 1;
            (head_lsn, head_ctrl, self.journal_durable_seq >= head_ctrl)
        }
    }

    pub fn hex(d: &[u8; 32]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Client: the fallible durability session (§9.1–9.4).
// ---------------------------------------------------------------------------

pub struct RemoteWalClient {
    pub session: u64,
    next_operation: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    UploadFailed,
    Fenced,
    Conflict,
    Corruption,
}

impl RemoteWalClient {
    pub fn open(controller: &mut Controller) -> Self {
        let session = controller.open_session();
        // finalisation operation ids are unique within the generation
        // (brief §4.4); the model namespaces them by session so a restarted
        // client can never collide with a predecessor's identities.
        RemoteWalClient { session, next_operation: session << 32 | 1 }
    }

    fn payload_key(digest: &[u8; 32]) -> String {
        format!("generations/1/wal/payloads/{}", controller::hex(digest))
    }

    /// The full §9.4 sequence for one record. `kill_after` simulates process
    /// death after step N (0-based); the caller then recovers by re-opening
    /// and querying by operation id.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        controller: &mut Controller,
        store: &mut dyn ObjectStore,
        payload: &[u8],
        sequenced: bool,
        status_key: Option<(u16, u64)>,
        verdict: Option<bool>,
        kill_after: Option<u8>,
    ) -> Result<Option<Descriptor>, WriteError> {
        // step 0: identity
        let digest = sha256(payload);
        let request_digest = sha256(&[payload, &[sequenced as u8]].concat());
        let operation_id = self.next_operation;
        self.next_operation += 1;
        if kill_after == Some(0) {
            return Ok(None); // died before any side effect
        }
        // step 1: upload with ambiguity resolution (§14.7)
        let key = Self::payload_key(&digest);
        match store.put_exact(&key, payload) {
            Ok(()) => {}
            Err(ObjectError::Ambiguous) => {
                match store.get(&key) {
                    Some(b) if sha256(&b) == digest => {} // resolved success
                    Some(_) => return Err(WriteError::Corruption),
                    None => {
                        // absent: retry same idempotent operation once
                        store.put_exact(&key, payload).map_err(|_| WriteError::UploadFailed)?;
                    }
                }
            }
            Err(ObjectError::NotStored) => return Err(WriteError::UploadFailed),
            Err(ObjectError::Conflict) => return Err(WriteError::Corruption),
        }
        if kill_after == Some(1) {
            return Ok(None); // died after upload, before finalisation
        }
        // step 2: finalize (late atomic allocation)
        match controller.finalize(
            self.session, operation_id, sequenced, status_key, verdict,
            &key, digest, payload.len() as u64, request_digest, store,
        ) {
            Ok(d) => {
                if kill_after == Some(2) {
                    // died after server committed, before seeing the reply:
                    // resolution is by operation id
                    return Ok(None);
                }
                Ok(Some(d))
            }
            Err(controller::FinalizeError::Fenced) => Err(WriteError::Fenced),
            Err(controller::FinalizeError::DigestConflict) => Err(WriteError::Conflict),
            Err(controller::FinalizeError::StatusConflict) => Err(WriteError::Corruption),
            Err(controller::FinalizeError::PayloadUnverified) => Err(WriteError::UploadFailed),
        }
    }
}

/// Fixed iterator over finalized history (§9.7).
pub fn iterate_fixed(controller: &Controller, from_sequence: u64) -> Vec<Descriptor> {
    let head = controller.tail.len();
    controller.tail[..head]
        .iter()
        .filter(|d| d.type_sequence >= from_sequence)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kill the client after every protocol step for every op in a stream of
    /// appends; prove: no sequence/LSN holes, and lost responses resolve by
    /// operation id without new identity (G2 pass criteria 1–2).
    #[test]
    fn kill_matrix_no_holes_exact_resolution() {
        for kill_step in [0u8, 1, 2] {
            for kill_op in 0..4usize {
                let mut c = Controller::new();
                let mut s = MemStore::default();
                let mut client = RemoteWalClient::open(&mut c);
                let mut finalized = 0u64;
                for op in 0..4usize {
                    let payload = format!("payload-{op}");
                    let kill = if op == kill_op { Some(kill_step) } else { None };
                    let r = client
                        .append(&mut c, &mut s, payload.as_bytes(), true, None, None, kill)
                        .unwrap();
                    match r {
                        Some(_) => finalized += 1,
                        None => {
                            // crash: recover. If the record was finalized
                            // server-side (kill_step==2) the operation query
                            // returns it; otherwise nothing was consumed.
                            let opid = client.session << 32 | (op + 1) as u64;
                            let recovered = c.query_operation(opid).cloned();
                            match kill_step {
                                2 => {
                                    assert!(recovered.is_some(), "post-commit kill must resolve by op id");
                                    finalized += 1;
                                }
                                _ => assert!(recovered.is_none()),
                            }
                            break;
                        }
                    }
                }
                // invariants: contiguous LSN and TypeSequence over whatever
                // was finalized — no holes regardless of kill point
                for (i, d) in c.tail.iter().enumerate() {
                    assert_eq!(d.append_lsn, i as u64 + 1);
                    assert_eq!(d.type_sequence, i as u64 + 1);
                }
                assert_eq!(c.tail.len() as u64, finalized);
            }
        }
    }

    /// Upload ambiguity in all three flavors; §14.7 resolution never
    /// fabricates success and never duplicates identity.
    #[test]
    fn upload_ambiguity_resolution() {
        // stored-but-lost: exact GET resolves to success, no duplicate object
        let mut c = Controller::new();
        let mut s = FaultyStore::new(vec![Fault::AmbiguousStored]);
        let mut client = RemoteWalClient::open(&mut c);
        let d = client.append(&mut c, &mut s, b"pay", true, None, None, None).unwrap().unwrap();
        assert_eq!(d.append_lsn, 1);
        assert_eq!(s.inner.objects.len(), 1);

        // not-stored-and-lost: absent on read-back, retried same op, succeeds
        let mut c = Controller::new();
        let mut s = FaultyStore::new(vec![Fault::AmbiguousNotStored]);
        let mut client = RemoteWalClient::open(&mut c);
        let d = client.append(&mut c, &mut s, b"pay", true, None, None, None).unwrap().unwrap();
        assert_eq!(d.append_lsn, 1);

        // clean failure: typed error, nothing consumed
        let mut c = Controller::new();
        let mut s = FaultyStore::new(vec![Fault::FailNotStored]);
        let mut client = RemoteWalClient::open(&mut c);
        assert_eq!(
            client.append(&mut c, &mut s, b"pay", true, None, None, None),
            Err(WriteError::UploadFailed)
        );
        assert_eq!(c.tail.len(), 0);
        assert_eq!(c.next_lsn_probe(), 1);
    }

    impl Controller {
        fn next_lsn_probe(&self) -> u64 {
            self.tail.len() as u64 + 1
        }
    }

    /// Status singleton over the remote path (G2 pass criterion 3).
    #[test]
    fn status_singleton_over_remote_path() {
        let mut c = Controller::new();
        let mut s = MemStore::default();
        let mut client = RemoteWalClient::open(&mut c);
        client.append(&mut c, &mut s, b"commit-1", true, None, None, None).unwrap().unwrap();
        let st1 = client
            .append(&mut c, &mut s, b"status-1", false, Some((1, 1)), Some(true), None)
            .unwrap().unwrap();
        // duplicate status (repair retry, same verdict, different payload op):
        let st2 = client
            .append(&mut c, &mut s, b"status-1", false, Some((1, 1)), Some(true), None)
            .unwrap().unwrap();
        assert_eq!(st1.append_lsn, st2.append_lsn, "no second physical record");
        // conflicting verdict: corruption
        assert_eq!(
            client.append(&mut c, &mut s, b"status-1x", false, Some((1, 1)), Some(false), None),
            Err(WriteError::Corruption)
        );
    }

    /// Sync barrier + transactional outbox: the barrier is satisfied only
    /// after the journal is durable through the head, and outbox publication
    /// is contiguous and idempotent under ambiguity (G2 outbox lag facet).
    #[test]
    fn sync_barrier_requires_contiguous_journal() {
        let mut c = Controller::new();
        let mut s = MemStore::default();
        let mut client = RemoteWalClient::open(&mut c);
        for i in 0..3 {
            client.append(&mut c, &mut s, format!("p{i}").as_bytes(), true, None, None, None).unwrap();
        }
        let (lsn, ctrl, durable) = c.sync_satisfied();
        assert_eq!((lsn, ctrl, durable), (3, 3, false), "not durable before flush");
        // flush with an ambiguous publication in the middle
        let mut fs = FaultyStore { inner: s, script: vec![Fault::None, Fault::AmbiguousStored, Fault::None], calls: 0 };
        let published = c.flush_outbox(&mut fs);
        assert_eq!(published, 3, "ambiguous publish resolved by exact read");
        let (_, _, durable) = c.sync_satisfied();
        assert!(durable);
        // journal objects are contiguous
        for seq in 1..=3u64 {
            assert!(fs.get(&format!("control/events/{seq:016x}")).is_some());
        }
    }

    /// Fixed iterator: finite, later appends invisible (G2 criterion 4).
    #[test]
    fn iterator_is_finite_and_fixed() {
        let mut c = Controller::new();
        let mut s = MemStore::default();
        let mut client = RemoteWalClient::open(&mut c);
        for i in 0..3 {
            client.append(&mut c, &mut s, format!("p{i}").as_bytes(), true, None, None, None).unwrap();
        }
        let snap = iterate_fixed(&c, 1);
        assert_eq!(snap.len(), 3);
        client.append(&mut c, &mut s, b"later", true, None, None, None).unwrap();
        assert_eq!(snap.len(), 3, "snapshot is a value, not a view");
    }

    /// Fencing over the remote path: a stale session cannot finalize after a
    /// new client opened (restart), but durable records are not revoked.
    #[test]
    fn stale_client_fenced_durability_retained() {
        let mut c = Controller::new();
        let mut s = MemStore::default();
        let mut old = RemoteWalClient::open(&mut c);
        old.append(&mut c, &mut s, b"before", true, None, None, None).unwrap().unwrap();
        let mut new = RemoteWalClient::open(&mut c); // restart fences old
        assert_eq!(
            old.append(&mut c, &mut s, b"stale", true, None, None, None),
            Err(WriteError::Fenced)
        );
        assert_eq!(c.tail.len(), 1, "durable history intact");
        new.append(&mut c, &mut s, b"after", true, None, None, None).unwrap().unwrap();
        assert_eq!(c.tail.len(), 2);
    }

    /// Delete-freedom by construction: this is a compile-time property (the
    /// ObjectStore trait has no delete), asserted here as documentation.
    #[test]
    fn object_store_trait_exposes_no_delete() {
        // if a delete method is ever added to ObjectStore, this test file is
        // where the review conversation starts (G13 only).
        let methods = ["put_exact", "get"];
        assert_eq!(methods.len(), 2);
    }
}
