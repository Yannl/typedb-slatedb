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
//! NON-PRODUCTION: nothing links this crate; the production lane stays on
//! crates.io SlateDB until the ADR-0012 decision is made with both
//! candidates on the table.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::BoxStream;
use slatedb::object_store::path::Path as ObjectPath;
use slatedb::object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt as _, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions,
};

/// The controller stand-in: one atomic cell naming the currently authorized
/// credential domain. Production would rotate provider credentials; the
/// semantics under measurement are identical.
#[derive(Debug, Default)]
pub struct PublicationAuthority {
    authorized: AtomicU64,
}

impl PublicationAuthority {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            authorized: AtomicU64::new(1),
        })
    }

    pub fn current(&self) -> u64 {
        self.authorized.load(Ordering::SeqCst)
    }

    /// Revoke every outstanding handle: mint the next domain.
    pub fn rotate(&self) -> u64 {
        self.authorized.fetch_add(1, Ordering::SeqCst) + 1
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
/// allowed iff this handle's domain is the currently authorized one. Reads
/// always pass (a stale reader is the read-contract's problem, not
/// fencing's); data-path writes (`compacted/`, `wal/`) always pass - a
/// revoked writer can at worst strand ORPHAN BYTES that no reachable
/// manifest names, which is exactly the containment the brief permits.
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

    /// Gate one mutation; records the attempt either way.
    fn admit(
        &self,
        operation: &'static str,
        path: &ObjectPath,
    ) -> slatedb::object_store::Result<()> {
        let publication = Self::is_publication_path(path);
        let allowed = !publication || self.credential_domain == self.authority.current();
        self.log.lock().unwrap().push(MutationAttempt {
            path: path.to_string(),
            operation,
            credential_domain: self.credential_domain,
            publication,
            allowed,
        });
        if allowed {
            return Ok(());
        }
        Err(slatedb::object_store::Error::Generic {
            store: "PublicationFirewall",
            source: format!(
                "publication fenced: credential domain {} is revoked (current {}); \
                 {operation} {path} refused",
                self.credential_domain,
                self.authority.current(),
            )
            .into(),
        })
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
        self.admit("put", location)?;
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjectPath,
        opts: PutMultipartOptions,
    ) -> slatedb::object_store::Result<Box<dyn MultipartUpload>> {
        self.admit("put_multipart", location)?;
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
        self.admit("copy", to)?;
        self.inner.copy_opts(from, to, options).await
    }

    async fn rename_opts(
        &self,
        from: &ObjectPath,
        to: &ObjectPath,
        options: RenameOptions,
    ) -> slatedb::object_store::Result<()> {
        // both halves are mutations; gate on the destination (the copy) and
        // the source (the delete)
        self.admit("rename", to)?;
        self.admit("rename", from)?;
        self.inner.rename_opts(from, to, options).await
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
                    let publication = FirewalledStore::is_publication_path(&location);
                    let allowed = !publication || this_domain == authority.current();
                    log.lock().unwrap().push(MutationAttempt {
                        path: location.to_string(),
                        operation: "delete",
                        credential_domain: this_domain,
                        publication,
                        allowed,
                    });
                    if !allowed {
                        return Err(slatedb::object_store::Error::Generic {
                            store: "PublicationFirewall",
                            source: format!(
                                "publication fenced: credential domain {this_domain} is revoked; \
                                 delete {location} refused"
                            )
                            .into(),
                        });
                    }
                    inner.delete(&location).await.map(|()| location)
                }
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slatedb::config::{PutOptions, Settings, WriteOptions};
    use slatedb::object_store::memory::InMemory;
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
            Self {
                remote: Arc::new(InMemory::new()),
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
        let successor_domain = harness.authority.rotate();
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

        harness.authority.rotate();
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
}
