//! ADR-0012 **Candidate B** spike: publication firewall over STOCK SlateDB.
//!
//! Candidate A (measured in `docs/evidence/G3/slatedb-external-epoch-spike.json`)
//! patches the pinned crate so every manifest publication carries a
//! controller-issued epoch. Candidate B keeps crates.io SlateDB untouched
//! and enforces fencing OUTSIDE it, at the only channel the engine has to
//! storage: an `ObjectStore` wrapper that refuses manifest-path mutations
//! from any handle whose *credential domain* the controller has revoked.
//! "Fresh credential domain" models what a provider (R2 scoped API tokens,
//! IAM session credentials) enforces server-side in production; the spike
//! enforces it in-process so the semantics are measurable offline.
//!
//! What this spike is for: measuring, not deciding. It answers
//! - does a store-boundary firewall fence EVERY publication path, including
//!   the `Admin`/checkpoint paths the upstream crate leaves unfenced?
//! - what does a fenced stale writer observe, and when?
//! - what does Candidate B structurally FAIL to provide? (inv. 78-80's
//!   exact externally-issued epoch VALUES - see the doc on
//!   [`FirewalledStore`] - and first-write-wins CAS arbitration between two
//!   handles that are both still authorized.)
//!
//! ## Use-time enforcement, not check-time (S-P0-08)
//!
//! The original spike checked authority and THEN awaited the underlying
//! store operation — a TOCTOU: rotation could land between `admit()` and
//! the provider completing the PUT, so a "revoked" publication could still
//! become durable. The gate is now one atomic conditional operation:
//! authority is a reader/writer domain cell, every admitted publication
//! holds a read guard ACROSS the provider mutation, and rotation takes the
//! write guard — so rotation linearizes strictly after every in-flight
//! admitted publication has completed and strictly before any later one is
//! admitted. This also models the provider contract the production design
//! needs: "activation resolves every old in-flight grant". Raw multipart
//! uploads get the same treatment: parts are staged bytes, but `complete()`
//! — the operation that makes the object visible — re-runs the gate
//! atomically instead of trusting the initiation-time check.
//!
//! NON-PRODUCTION: nothing links this crate; the production lane stays on
//! crates.io SlateDB until the ADR-0012 decision is made with both
//! candidates on the table.

use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::BoxStream;
use slatedb::object_store::path::Path as ObjectPath;
use slatedb::object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt as _, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions,
    UploadPart,
};

/// The credential-domain space is exhausted (S-P0-09): rotation at
/// `u64::MAX` is a typed terminal refusal and the current domain is NOT
/// mutated — a wrapped counter would mint domain 0, which older handles
/// could collide with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialDomainExhausted;

impl std::fmt::Display for CredentialDomainExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "credential domain space exhausted; rotation refused without mutation"
        )
    }
}

impl std::error::Error for CredentialDomainExhausted {}

/// The controller stand-in: one reader/writer cell naming the currently
/// authorized credential domain. Production would rotate provider
/// credentials; the semantics under measurement are identical, INCLUDING
/// the drain property: [`Self::rotate`] takes the write side, so it cannot
/// return until every in-flight admitted publication (each holding the
/// read side across its provider mutation) has completed — and once it
/// returns, no publication under the old domain can be admitted or
/// complete.
#[derive(Debug)]
pub struct PublicationAuthority {
    authorized: tokio::sync::RwLock<u64>,
}

impl PublicationAuthority {
    pub fn new() -> Arc<Self> {
        Self::starting_at(1)
    }

    /// Start at an arbitrary domain — exists so the exhaustion boundary is
    /// testable without 2^64 rotations.
    pub fn starting_at(domain: u64) -> Arc<Self> {
        Arc::new(Self {
            authorized: tokio::sync::RwLock::new(domain),
        })
    }

    pub async fn current(&self) -> u64 {
        *self.authorized.read().await
    }

    /// Revoke every outstanding handle: mint the next domain.
    ///
    /// Blocks until in-flight admitted publications drain (see the type
    /// doc). Exhaustion at `u64::MAX` is a typed refusal with NO mutation:
    /// the incumbent domain simply remains the last authority forever,
    /// which is fail-secure (nothing new can be minted, nothing old is
    /// silently re-authorized by a wrap to zero).
    pub async fn rotate(&self) -> Result<u64, CredentialDomainExhausted> {
        let mut authorized = self.authorized.write().await;
        let next = authorized.checked_add(1).ok_or(CredentialDomainExhausted)?;
        *authorized = next;
        Ok(next)
    }
}

/// One observed mutation through the firewall - the spike's measurement
/// channel (which paths are publications, which were refused, for whom).
#[derive(Debug, Clone)]
pub struct MutationAttempt {
    pub path: String,
    pub operation: &'static str,
    pub credential_domain: u64,
    pub publication: bool,
    pub allowed: bool,
}

/// A store handle bound to one credential domain.
///
/// Gate: a MUTATION of a publication path (anything under `manifest/`) is
/// allowed iff this handle's domain is the currently authorized one, and
/// the authority read guard is held ACROSS the underlying mutation (see
/// the module doc on use-time enforcement). Reads always pass (a stale
/// reader is the read-contract's problem, not fencing's); data-path writes
/// (`compacted/`, `wal/`) always pass - a revoked writer can at worst
/// strand ORPHAN BYTES that no reachable manifest names, which is exactly
/// the containment the brief permits.
///
/// Structural limitation, measured and permanent for this candidate: the
/// firewall sees paths and opaque bytes. It can decide WHO may publish, but
/// the epoch NUMBERS inside the manifests remain internally allocated by
/// stock SlateDB - it cannot make publications carry `SlateWriterEpoch`
/// values minted by the controller (inv. 78-80), and adopting whatever
/// epoch the store picked is the prohibited observe-and-bind. Candidate A
/// provides exactly that; Candidate B cannot, at any wrapper thickness.
#[derive(Debug)]
pub struct FirewalledStore {
    inner: Arc<dyn ObjectStore>,
    authority: Arc<PublicationAuthority>,
    credential_domain: u64,
    log: Arc<Mutex<Vec<MutationAttempt>>>,
}

impl FirewalledStore {
    pub fn new(
        inner: Arc<dyn ObjectStore>,
        authority: Arc<PublicationAuthority>,
        credential_domain: u64,
        log: Arc<Mutex<Vec<MutationAttempt>>>,
    ) -> Self {
        Self {
            inner,
            authority,
            credential_domain,
            log,
        }
    }

    fn is_publication_path(path: &ObjectPath) -> bool {
        path.parts().any(|part| part.as_ref() == "manifest")
    }

    /// Gate one mutation and, when admitted, run it while still holding
    /// the authority read guard; records the attempt either way.
    async fn admit_and_run<T>(
        &self,
        operation: &'static str,
        path: &ObjectPath,
        mutation: impl Future<Output = slatedb::object_store::Result<T>>,
    ) -> slatedb::object_store::Result<T> {
        admit_and_run_gate(
            &self.authority,
            &self.log,
            self.credential_domain,
            operation,
            path,
            mutation,
        )
        .await
    }
}

impl std::fmt::Display for FirewalledStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FirewalledStore(domain={}, {})",
            self.credential_domain, self.inner
        )
    }
}

#[async_trait]
impl ObjectStore for FirewalledStore {
    async fn put_opts(
        &self,
        location: &ObjectPath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> slatedb::object_store::Result<PutResult> {
        self.admit_and_run(
            "put",
            location,
            self.inner.put_opts(location, payload, opts),
        )
        .await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjectPath,
        opts: PutMultipartOptions,
    ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
        // Initiation is gated for observability, but the ENFORCEMENT point
        // for a raw multipart handle is `complete()` — the mutation that
        // makes the object visible — which the returned wrapper re-gates
        // atomically (S-P0-08: authority can rotate between initiation and
        // completion).
        let inner = self
            .admit_and_run(
                "put_multipart",
                location,
                self.inner.put_multipart_opts(location, opts),
            )
            .await?;
        Ok(Box::new(GatedMultipartUpload {
            inner,
            authority: Arc::clone(&self.authority),
            log: Arc::clone(&self.log),
            credential_domain: self.credential_domain,
            path: location.clone(),
        }))
    }

    async fn get_opts(
        &self,
        location: &ObjectPath,
        options: GetOptions,
    ) -> slatedb::object_store::Result<GetResult> {
        self.inner.get_opts(location, options).await
    }

    fn list(
        &self,
        prefix: Option<&ObjectPath>,
    ) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(
        &self,
        prefix: Option<&ObjectPath>,
    ) -> slatedb::object_store::Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &ObjectPath,
        to: &ObjectPath,
        options: CopyOptions,
    ) -> slatedb::object_store::Result<()> {
        self.admit_and_run("copy", to, self.inner.copy_opts(from, to, options))
            .await
    }

    async fn rename_opts(
        &self,
        from: &ObjectPath,
        to: &ObjectPath,
        options: RenameOptions,
    ) -> slatedb::object_store::Result<()> {
        // both halves are mutations; gate on the destination (the copy) and
        // the source (the delete). Nested admit_and_run holds one read
        // guard inside the other — both are read acquisitions on the same
        // RwLock, which tokio permits concurrently, so this cannot
        // self-deadlock; rotation still waits for both to release.
        self.admit_and_run("rename", to, async {
            admit_and_run_gate(
                &self.authority,
                &self.log,
                self.credential_domain,
                "rename",
                from,
                self.inner.rename_opts(from, to, options),
            )
            .await
        })
        .await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, slatedb::object_store::Result<ObjectPath>>,
    ) -> BoxStream<'static, slatedb::object_store::Result<ObjectPath>> {
        use futures::StreamExt;
        let this_domain = self.credential_domain;
        let authority = self.authority.clone();
        let log = self.log.clone();
        let inner = self.inner.clone();
        locations
            .then(move |location| {
                let authority = authority.clone();
                let log = log.clone();
                let inner = inner.clone();
                async move {
                    let location = location?;
                    admit_and_run_gate(
                        &authority,
                        &log,
                        this_domain,
                        "delete",
                        &location,
                        inner.delete(&location),
                    )
                    .await
                    .map(|()| location)
                }
            })
            .boxed()
    }
}

/// A raw multipart handle whose `complete()` — the visibility-granting
/// mutation — re-runs the gate atomically (S-P0-08). Parts are staged,
/// never-visible bytes and pass through; `abort()` only removes staged
/// bytes and passes through too.
#[derive(Debug)]
struct GatedMultipartUpload {
    inner: Box<dyn MultipartUpload>,
    authority: Arc<PublicationAuthority>,
    log: Arc<Mutex<Vec<MutationAttempt>>>,
    credential_domain: u64,
    path: ObjectPath,
}

#[async_trait]
impl MultipartUpload for GatedMultipartUpload {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        self.inner.put_part(data)
    }

    async fn complete(&mut self) -> slatedb::object_store::Result<PutResult> {
        admit_and_run_gate(
            &self.authority,
            &self.log,
            self.credential_domain,
            "multipart_complete",
            &self.path,
            self.inner.complete(),
        )
        .await
    }

    async fn abort(&mut self) -> slatedb::object_store::Result<()> {
        self.inner.abort().await
    }
}

/// The one gate. Free function (not `&self`) so the `'static` delete stream
/// and the multipart wrapper share it with the ordinary methods - the gate
/// logic must never fork.
///
/// S-P0-08: check and use are ONE atomic conditional operation with respect
/// to rotation. The authority read guard is acquired, the domain compared,
/// and — when admitted — the guard is held until the underlying mutation
/// future completes. `rotate()` needs the write guard, so it cannot
/// interleave between this check and the mutation becoming durable.
async fn admit_and_run_gate<T>(
    authority: &PublicationAuthority,
    log: &Mutex<Vec<MutationAttempt>>,
    credential_domain: u64,
    operation: &'static str,
    path: &ObjectPath,
    mutation: impl Future<Output = slatedb::object_store::Result<T>>,
) -> slatedb::object_store::Result<T> {
    let publication = FirewalledStore::is_publication_path(path);
    if !publication {
        // data-path mutation: never fenced, and deliberately NOT holding
        // the authority guard — orphan bytes are permitted containment and
        // must not delay revocation.
        log.lock().unwrap().push(MutationAttempt {
            path: path.to_string(),
            operation,
            credential_domain,
            publication,
            allowed: true,
        });
        return mutation.await;
    }
    let authorized = authority.authorized.read().await;
    let allowed = credential_domain == *authorized;
    log.lock().unwrap().push(MutationAttempt {
        path: path.to_string(),
        operation,
        credential_domain,
        publication,
        allowed,
    });
    if !allowed {
        return Err(slatedb::object_store::Error::Generic {
            store: "PublicationFirewall",
            source: format!(
                "publication fenced: credential domain {credential_domain} is revoked (current {}); \
                 {operation} {path} refused",
                *authorized,
            )
            .into(),
        });
    }
    // the guard (`authorized`) is alive across this await: admitted means
    // admitted-to-completion, and rotation waits for it
    mutation.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use slatedb::config::{PutOptions, Settings, WriteOptions};
    use slatedb::object_store::memory::InMemory;
    use slatedb::object_store::PutOptions as StorePutOptions;
    use slatedb::Db;

    /// The U2 write posture (slate.rs `write_options()`): `await_durable:
    /// false` - with `flush_interval: None` and the WAL off, a durable
    /// await would wait forever; durability is `flush()`'s job.
    async fn put(db: &Db, key: &[u8], value: &[u8]) -> Result<(), slatedb::Error> {
        db.put_with_options(
            key,
            value,
            &PutOptions::default(),
            &WriteOptions {
                await_durable: false,
                ..Default::default()
            },
        )
        .await
        .map(|_| ())
    }

    /// The U2 posture (fork/typedb slate.rs `settings()`): SlateDB WAL off,
    /// no compactor, no GC - TypeDB's WAL is the durability authority.
    fn posture() -> Settings {
        let mut settings = Settings::default();
        settings.wal_enabled = false;
        settings.flush_interval = None;
        settings.compactor_options = None;
        settings.garbage_collector_options = None;
        settings.compression_codec = None;
        settings.l0_max_ssts = 1_000_000;
        settings.l0_max_ssts_per_key = 1_000_000;
        // Q-13, re-observed HERE: with the stock default (None = retry
        // transient errors indefinitely) the firewall's refusal put
        // `flush()` into an infinite retry loop - the fenced writer HUNG
        // instead of failing. A store-boundary candidate inherits this
        // hazard on every refusal path; Candidate A's typed Fenced error is
        // terminal by construction. Recorded in the comparison.
        settings.object_store_max_retries = Some(4);
        settings
    }

    struct Harness {
        remote: Arc<dyn ObjectStore>,
        authority: Arc<PublicationAuthority>,
        log: Arc<Mutex<Vec<MutationAttempt>>>,
    }

    impl Harness {
        fn new() -> Self {
            Self::over(Arc::new(InMemory::new()))
        }

        fn over(remote: Arc<dyn ObjectStore>) -> Self {
            Self {
                remote,
                authority: PublicationAuthority::new(),
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn handle(&self, credential_domain: u64) -> Arc<dyn ObjectStore> {
            Arc::new(FirewalledStore::new(
                self.remote.clone(),
                self.authority.clone(),
                credential_domain,
                self.log.clone(),
            ))
        }

        async fn open(&self, credential_domain: u64) -> Result<Db, slatedb::Error> {
            Db::builder("spike-db", self.handle(credential_domain))
                .with_settings(posture())
                .build()
                .await
        }

        fn attempts(&self) -> Vec<MutationAttempt> {
            self.log.lock().unwrap().clone()
        }
    }

    /// Coverage: every mutation of a full open -> put -> flush -> close
    /// cycle flows through the firewall, and the manifest publications among
    /// them are identifiable by path alone. This is the property that makes
    /// a store-boundary firewall a COMPLETE gate for a provider to enforce:
    /// the engine has no second channel - including the `Admin` checkpoint
    /// paths that bypass upstream's own fencing types.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_publication_path_flows_through_the_firewall() {
        let harness = Harness::new();
        let db = harness.open(1).await.expect("authorized open");
        put(&db, b"k1", b"v1").await.expect("put");
        db.flush().await.expect("flush");
        db.close().await.expect("close");

        let attempts = harness.attempts();
        let publications: Vec<&MutationAttempt> =
            attempts.iter().filter(|a| a.publication).collect();
        assert!(
            !publications.is_empty(),
            "an open/put/flush/close cycle must publish manifests; the firewall saw none"
        );
        assert!(publications
            .iter()
            .all(|a| a.allowed && a.credential_domain == 1));
        // and the cycle also wrote data-path objects that are NOT publications
        assert!(
            attempts.iter().any(|a| !a.publication),
            "expected non-publication data writes (SSTs) in the cycle"
        );
    }

    /// Pause-fence-resume, the SL-P1 shape: rotation alone (no replacement
    /// writer yet) fences the stale handle's next publication - the refusal
    /// comes from the firewall, not from upstream CAS arbitration. Data
    /// already durable stays readable; the stale writer's post-revocation
    /// residue is refused manifest writes and (at worst) orphan bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revoked_writer_cannot_publish_and_a_successor_can() {
        let harness = Harness::new();
        let stale = harness.open(1).await.expect("authorized open");
        put(&stale, b"k1", b"v1").await.expect("put");
        stale.flush().await.expect("flush under authority");

        // controller revokes domain 1 (credential rotation); nothing else
        let successor_domain = harness.authority.rotate().await.expect("rotate");
        assert_eq!(successor_domain, 2);

        // the stale writer's next publication dies at the store boundary
        put(&stale, b"k2", b"v2")
            .await
            .expect("memtable write is local");
        let refused = stale.flush().await;
        assert!(
            refused.is_err(),
            "a revoked domain must not publish a manifest"
        );
        let refusals: Vec<MutationAttempt> = harness
            .attempts()
            .into_iter()
            .filter(|a| !a.allowed)
            .collect();
        assert!(!refusals.is_empty());
        assert!(
            refusals
                .iter()
                .all(|a| a.publication && a.credential_domain == 1),
            "only domain-1 publication attempts may be refused: {refusals:?}"
        );
        drop(stale);

        // the successor opens under the fresh domain and proceeds; the
        // predecessor's durable prefix is intact
        let successor = harness
            .open(successor_domain)
            .await
            .expect("successor open");
        let durable = successor.get(b"k1").await.expect("read");
        assert_eq!(durable.as_deref(), Some(&b"v1"[..]));
        put(&successor, b"k3", b"v3").await.expect("put");
        successor.flush().await.expect("successor publishes");
        successor.close().await.expect("close");
    }

    /// Stale REOPEN (the directive's named case): opening a database is
    /// itself a publication (epoch bump), so a handle whose domain was
    /// revoked cannot even reach the point of holding a writer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stale_reopen_is_refused_at_open() {
        let harness = Harness::new();
        let first = harness.open(1).await.expect("authorized open");
        put(&first, b"k1", b"v1").await.expect("put");
        first.flush().await.expect("flush");
        first.close().await.expect("close");

        harness.authority.rotate().await.expect("rotate");
        let stale_open = harness.open(1).await;
        assert!(
            stale_open.is_err(),
            "open publishes; a revoked domain must fail to open"
        );
        // and the refusal was the firewall's, on a manifest path
        let refusals: Vec<MutationAttempt> = harness
            .attempts()
            .into_iter()
            .filter(|a| !a.allowed)
            .collect();
        assert!(refusals
            .iter()
            .any(|a| a.publication && a.credential_domain == 1));
    }

    /// The measured LIMIT of Candidate B, stated as an executable fact: the
    /// firewall observes paths and opaque bytes only. Nothing in this
    /// candidate can cause the manifests to carry controller-issued epoch
    /// VALUES - the attempts log (this candidate's entire vocabulary) has
    /// no epoch in it, and the stock builder API accepts none. inv. 78-80
    /// therefore cannot be satisfied by ANY wrapper of this shape; that is
    /// Candidate A's half of the comparison, not a bug here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_firewall_vocabulary_has_no_epoch_in_it() {
        let harness = Harness::new();
        let db = harness.open(1).await.expect("open");
        put(&db, b"k", b"v").await.expect("put");
        db.flush().await.expect("flush");
        db.close().await.expect("close");
        for attempt in harness.attempts() {
            // the whole observable record: path, operation, domain, verdict.
            // No field carries or could carry a SlateWriterEpoch value.
            let MutationAttempt {
                path: _,
                operation: _,
                credential_domain,
                publication: _,
                allowed,
            } = attempt;
            assert!(credential_domain == 1 && allowed);
        }
    }

    // ----------------------------------------------------------------
    // S-P0-08: the gate is use-time-atomic, not check-then-use.
    // ----------------------------------------------------------------

    /// An inner store whose puts can be held mid-flight: signals when a put
    /// has ENTERED the provider (i.e. is past any admission check) and
    /// waits for an explicit release before completing.
    #[derive(Debug)]
    struct HoldingStore {
        inner: Arc<dyn ObjectStore>,
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<tokio::sync::Notify>,
        hold: std::sync::atomic::AtomicBool,
    }

    impl std::fmt::Display for HoldingStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "HoldingStore({})", self.inner)
        }
    }

    #[async_trait]
    impl ObjectStore for HoldingStore {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            opts: StorePutOptions,
        ) -> slatedb::object_store::Result<PutResult> {
            if self.hold.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = self.entered.send(());
                self.release.notified().await;
            }
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjectPath,
            opts: PutMultipartOptions,
        ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> slatedb::object_store::Result<GetResult> {
            self.inner.get_opts(location, options).await
        }

        fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, slatedb::object_store::Result<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> slatedb::object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> slatedb::object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }

        async fn rename_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: RenameOptions,
        ) -> slatedb::object_store::Result<()> {
            self.inner.rename_opts(from, to, options).await
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, slatedb::object_store::Result<ObjectPath>>,
        ) -> BoxStream<'static, slatedb::object_store::Result<ObjectPath>> {
            self.inner.delete_stream(locations)
        }
    }

    /// The race the original spike had (S-P0-08): admit under domain 1,
    /// rotate while the provider PUT is still in flight, and the "revoked"
    /// publication lands anyway. With the atomic gate, rotation CANNOT take
    /// effect while an admitted publication is in flight - it drains first
    /// - so no publication ever completes under an authority that has
    /// already moved on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_cannot_interleave_between_admission_and_provider_completion() {
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let holding = Arc::new(HoldingStore {
            inner: Arc::new(InMemory::new()),
            entered: entered_tx,
            release: Arc::clone(&release),
            hold: std::sync::atomic::AtomicBool::new(true),
        });
        let harness = Harness::over(holding);
        let store = harness.handle(1);

        // an admitted publication, now held INSIDE the provider
        let manifest_path = ObjectPath::from("spike-db/manifest/00000000000000000001.manifest");
        let in_flight = tokio::spawn({
            let store = Arc::clone(&store);
            let manifest_path = manifest_path.clone();
            async move {
                store
                    .put_opts(
                        &manifest_path,
                        PutPayload::from_static(b"root"),
                        slatedb::object_store::PutOptions::default(),
                    )
                    .await
            }
        });
        entered_rx
            .recv()
            .await
            .expect("the put must enter the provider");

        // revocation while the admitted publication is in flight
        let mut rotation = tokio::spawn({
            let authority = Arc::clone(&harness.authority);
            async move { authority.rotate().await }
        });

        // the atomic property: rotation must NOT complete while the
        // admitted publication is still inside the provider. (Under the
        // old check-then-use gate this timeout observes rotation
        // completing immediately - the executable form of the TOCTOU.)
        let premature =
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut rotation).await;
        assert!(
            premature.is_err(),
            "rotation took effect while an admitted publication was still in flight: \
             the gate is check-then-use, not atomic"
        );

        // release the provider: the publication completes UNDER DOMAIN 1,
        // and only then does rotation land
        release.notify_waiters();
        in_flight
            .await
            .expect("join")
            .expect("the admitted publication completes under its admitting authority");
        let new_domain = rotation
            .await
            .expect("join")
            .expect("rotation proceeds after drain");
        assert_eq!(new_domain, 2);

        // and after rotation, domain 1 is refused at admission
        let refused = store
            .put_opts(
                &ObjectPath::from("spike-db/manifest/00000000000000000002.manifest"),
                PutPayload::from_static(b"stale"),
                slatedb::object_store::PutOptions::default(),
            )
            .await;
        assert!(
            refused.is_err(),
            "post-rotation domain-1 publication must be refused"
        );
    }

    /// S-P0-08, multipart half: initiation-time authority is NOT completion
    /// authority. A raw multipart upload admitted under domain 1 whose
    /// `complete()` arrives after rotation must be refused, and the object
    /// must not exist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_multipart_completion_after_rotation_is_refused_and_publishes_nothing() {
        let harness = Harness::new();
        let store = harness.handle(1);
        let manifest_path = ObjectPath::from("spike-db/manifest/00000000000000000009.manifest");

        // initiated (and admitted) under domain 1
        let mut upload = store
            .put_multipart_opts(&manifest_path, PutMultipartOptions::default())
            .await
            .expect("initiation under authority");
        upload
            .put_part(PutPayload::from_static(b"staged-part"))
            .await
            .expect("parts are staged bytes and pass");

        // authority rotates between initiation and completion
        harness.authority.rotate().await.expect("rotate");

        let refused = upload.complete().await;
        assert!(
            refused.is_err(),
            "multipart complete() must revalidate authority at use time"
        );
        let landed = store.get_opts(&manifest_path, GetOptions::default()).await;
        assert!(
            landed.is_err(),
            "a refused completion must leave no visible object"
        );
        // the refusal is recorded as a fenced publication attempt
        assert!(harness
            .attempts()
            .iter()
            .any(|a| { a.operation == "multipart_complete" && a.publication && !a.allowed }));

        // a successor handle CAN complete a fresh multipart on the same key
        let successor = harness.handle(2);
        let mut upload = successor
            .put_multipart_opts(&manifest_path, PutMultipartOptions::default())
            .await
            .expect("successor initiation");
        upload
            .put_part(PutPayload::from_static(b"successor-part"))
            .await
            .expect("part");
        upload.complete().await.expect("successor completion");
    }

    // ----------------------------------------------------------------
    // S-P0-09 (rotation counter): typed exhaustion, no mutation.
    // ----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn domain_rotation_is_exact_at_the_boundary_and_refuses_exhaustion() {
        // MAX-1 -> MAX is an ordinary rotation.
        let authority = PublicationAuthority::starting_at(u64::MAX - 1);
        assert_eq!(authority.rotate().await, Ok(u64::MAX));
        assert_eq!(authority.current().await, u64::MAX);

        // At MAX, rotation is a typed refusal and mutates NOTHING - twice,
        // to prove the refusal is stable rather than a one-shot.
        for _ in 0..2 {
            assert_eq!(authority.rotate().await, Err(CredentialDomainExhausted));
            assert_eq!(
                authority.current().await,
                u64::MAX,
                "a refused rotation must not mint or alter authority (a wrap would mint domain 0)"
            );
        }

        // and the incumbent MAX-domain handle is still the authority: a
        // failed rotation revokes nobody.
        let log = Arc::new(Mutex::new(Vec::new()));
        let store = FirewalledStore::new(
            Arc::new(InMemory::new()),
            authority,
            u64::MAX,
            Arc::clone(&log),
        );
        store
            .put_opts(
                &ObjectPath::from("spike-db/manifest/00000000000000000001.manifest"),
                PutPayload::from_static(b"root"),
                slatedb::object_store::PutOptions::default(),
            )
            .await
            .expect("the incumbent remains authorized after a refused rotation");
    }
}
