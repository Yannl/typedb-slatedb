//! Provider-neutral S3 certification corpus (round-4 §6.4, OD-009).
//!
//! Every test reads its target from the environment and refuses to run
//! (typed skip via panic-with-message under `#[ignore]`-less design:
//! tests are gated behind the S3_CERT_ENDPOINT variable — absent means
//! the whole corpus is a no-op pass with a loud message, so `cargo test`
//! in CI without a server is not a silent green over nothing: the runner
//! script `run-corpus.sh` sets the variables and asserts the executed
//! test COUNT).
//!
//! Environment:
//!   S3_CERT_ENDPOINT    http://127.0.0.1:<port>  (loopback only)
//!   S3_CERT_BUCKET      target bucket (created by the runner)
//!   S3_CERT_ACCESS_KEY / S3_CERT_SECRET_KEY
//!   S3_CERT_PHASE       "semantics" (default) | "post-restart"
//!
//! Phase protocol for the crash/restart invariant: phase "semantics"
//! writes the persistence witness objects; the RUNNER then kill -9s and
//! restarts the server; phase "post-restart" re-reads the witnesses and
//! requires byte-exact identity.

use std::sync::Arc;

use object_store::aws::AmazonS3Builder;
use object_store::ObjectStore;

/// The witness keys the restart phase re-reads (must be deterministic).
pub const PERSISTENCE_WITNESSES: &[(&str, &[u8])] = &[
    ("cert/persist/a", b"witness-a-bytes"),
    ("cert/persist/b", b"witness-b-0123456789"),
];

pub struct CertTarget {
    pub store: Arc<dyn ObjectStore>,
    pub phase: String,
}

/// Build the store from the environment; `None` when unconfigured (the
/// corpus then no-ops loudly — the runner asserts executed-test counts).
pub fn target_from_env() -> Option<CertTarget> {
    let endpoint = std::env::var("S3_CERT_ENDPOINT").ok()?;
    let bucket = std::env::var("S3_CERT_BUCKET").ok()?;
    let access = std::env::var("S3_CERT_ACCESS_KEY").ok()?;
    let secret = std::env::var("S3_CERT_SECRET_KEY").ok()?;
    assert!(
        endpoint.starts_with("http://127.0.0.1") || endpoint.starts_with("http://localhost"),
        "certification targets are LOOPBACK ONLY (got {endpoint})"
    );
    let store = AmazonS3Builder::new()
        .with_endpoint(&endpoint)
        .with_bucket_name(&bucket)
        .with_region("auto")
        .with_access_key_id(&access)
        .with_secret_access_key(&secret)
        .with_allow_http(true)
        .build()
        .expect("object_store builder");
    Some(CertTarget {
        store: Arc::new(store),
        phase: std::env::var("S3_CERT_PHASE").unwrap_or_else(|_| "semantics".into()),
    })
}

#[cfg(test)]
mod semantics {
    use super::*;
    use bytes::Bytes;
    use futures::stream::{FuturesUnordered, StreamExt, TryStreamExt};
    use object_store::path::Path as ObjectPath;
    use object_store::{
        Error as StoreError, GetOptions, GetRange, ObjectStoreExt, PutMode, PutOptions, PutPayload,
        UpdateVersion,
    };

    fn skip() -> bool {
        if std::env::var("S3_CERT_ENDPOINT").is_err() {
            eprintln!("s3-cert-corpus: S3_CERT_ENDPOINT unset — corpus NOT executed (use run-corpus.sh)");
            return true;
        }
        false
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap()
    }

    fn unique(prefix: &str) -> ObjectPath {
        ObjectPath::from(format!("cert/{prefix}/{}", rand::random::<u64>()))
    }

    /// §6.4: SigV4 + exact-byte PUT/GET/HEAD readback.
    #[test]
    fn put_get_head_byte_exact() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        rt().block_on(async {
            let key = unique("basic");
            let body = Bytes::from_static(b"exact-bytes-0123456789");
            t.store.put(&key, PutPayload::from(body.clone())).await.expect("put");
            let read = t.store.get(&key).await.expect("get").bytes().await.expect("bytes");
            assert_eq!(read, body, "readback must be byte-exact");
            let head = t.store.head(&key).await.expect("head");
            assert_eq!(head.size as usize, body.len(), "HEAD size must be exact");
        });
    }

    /// §6.4: range GET returns exactly the requested slice.
    #[test]
    fn range_get_exact_slice() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        rt().block_on(async {
            let key = unique("range");
            t.store.put(&key, PutPayload::from_static(b"0123456789abcdef")).await.expect("put");
            let opts = GetOptions { range: Some(GetRange::Bounded(4..10)), ..Default::default() };
            let part = t.store.get_opts(&key, opts).await.expect("range get").bytes().await.unwrap();
            assert_eq!(&part[..], b"456789");
        });
    }

    /// §6.4: absent key is a TYPED NotFound, never an empty success.
    #[test]
    fn missing_key_is_typed_not_found() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        rt().block_on(async {
            let err = t.store.get(&unique("absent")).await.expect_err("absent key must error");
            assert!(matches!(err, StoreError::NotFound { .. }), "got {err:?}");
        });
    }

    /// §6.4 THE decisive SlateDB invariant: PutMode::Create
    /// (If-None-Match:*) under 12 concurrent changed-body writers admits
    /// EXACTLY ONE winner; every loser gets the typed AlreadyExists
    /// precondition. (This is the exact race that disqualified VersityGW:
    /// all twelve returned 200.)
    #[test]
    fn conditional_create_exactly_one_winner() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        rt().block_on(async {
            let key = unique("cas-create");
            let mut attempts = FuturesUnordered::new();
            for i in 0..12u32 {
                let store = Arc::clone(&t.store);
                let key = key.clone();
                attempts.push(tokio::spawn(async move {
                    let body = Bytes::from(format!("writer-{i}-distinct-body"));
                    let opts = PutOptions { mode: PutMode::Create, ..Default::default() };
                    store.put_opts(&key, PutPayload::from(body.clone()), opts).await.map(|_| body)
                }));
            }
            let mut winners: Vec<Bytes> = Vec::new();
            let mut losers = 0u32;
            while let Some(joined) = attempts.next().await {
                match joined.expect("task join") {
                    Ok(body) => winners.push(body),
                    Err(StoreError::AlreadyExists { .. }) => losers += 1,
                    Err(other) => panic!("loser must be the TYPED AlreadyExists, got {other:?}"),
                }
            }
            assert_eq!(winners.len(), 1, "exactly one conditional-create winner (got {})", winners.len());
            assert_eq!(losers, 11, "eleven typed losers");
            // the stored bytes are exactly the single winner's bytes
            let stored = t.store.get(&key).await.unwrap().bytes().await.unwrap();
            assert_eq!(stored, winners[0], "stored bytes must be exactly the winner's");
        });
    }

    /// §6.4: PutMode::Update with the CURRENT version succeeds; a stale or
    /// fabricated expected version is the typed Precondition failure and
    /// mutates nothing.
    #[test]
    fn conditional_update_exact_etag() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        rt().block_on(async {
            let key = unique("cas-update");
            let create = PutOptions { mode: PutMode::Create, ..Default::default() };
            let v1 = t.store.put_opts(&key, PutPayload::from_static(b"v1"), create).await.expect("create");
            let current = UpdateVersion { e_tag: v1.e_tag.clone(), version: v1.version.clone() };
            // correct expected version: succeeds
            let update = PutOptions { mode: PutMode::Update(current), ..Default::default() };
            let v2 = t.store.put_opts(&key, PutPayload::from_static(b"v2"), update).await.expect("update@v1");
            assert_ne!(v1.e_tag, v2.e_tag, "the version must move");
            // STALE expected version (v1 again): typed precondition, no mutation
            let stale = PutOptions {
                mode: PutMode::Update(UpdateVersion { e_tag: v1.e_tag, version: v1.version }),
                ..Default::default()
            };
            let err = t.store.put_opts(&key, PutPayload::from_static(b"vX"), stale).await
                .expect_err("stale expected version must fail");
            assert!(matches!(err, StoreError::Precondition { .. }), "typed precondition, got {err:?}");
            let bytes = t.store.get(&key).await.unwrap().bytes().await.unwrap();
            assert_eq!(&bytes[..], b"v2", "a failed conditional update mutates nothing");
        });
    }

    /// §6.4: ListObjectsV2 prefix/pagination — every written key is listed
    /// exactly once (no missing, no duplicate) across page boundaries.
    #[test]
    fn list_pagination_no_missing_no_duplicate() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        rt().block_on(async {
            let prefix = format!("cert/list/{}", rand::random::<u64>());
            let mut expected = std::collections::BTreeSet::new();
            for i in 0..25u32 {
                let key = ObjectPath::from(format!("{prefix}/k{i:04}"));
                t.store.put(&key, PutPayload::from_static(b"x")).await.expect("put");
                expected.insert(key.to_string());
            }
            let listed: Vec<_> = t.store
                .list(Some(&ObjectPath::from(prefix.clone())))
                .try_collect::<Vec<_>>()
                .await
                .expect("list");
            let got: Vec<String> = listed.iter().map(|m| m.location.to_string()).collect();
            let got_set: std::collections::BTreeSet<String> = got.iter().cloned().collect();
            assert_eq!(got.len(), got_set.len(), "no duplicate keys in listing");
            assert_eq!(got_set, expected, "no missing/extra keys in listing");
        });
    }

    /// §6.4: multipart create/complete round-trips the exact bytes;
    /// abort leaves the key absent.
    #[test]
    fn multipart_complete_and_abort() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        rt().block_on(async {
            // complete path: two 5 MiB parts + tail (S3 minimum part size)
            let key = unique("mpu-complete");
            let part = vec![0xabu8; 5 * 1024 * 1024];
            let tail = b"tail-bytes".to_vec();
            let mut upload = t.store.put_multipart(&key).await.expect("initiate");
            upload.put_part(PutPayload::from(Bytes::from(part.clone()))).await.expect("part1");
            upload.put_part(PutPayload::from(Bytes::from(part.clone()))).await.expect("part2");
            upload.put_part(PutPayload::from(Bytes::from(tail.clone()))).await.expect("part3");
            upload.complete().await.expect("complete");
            let read = t.store.get(&key).await.expect("get").bytes().await.expect("bytes");
            assert_eq!(read.len(), part.len() * 2 + tail.len(), "completed length exact");
            assert_eq!(&read[..part.len()], &part[..], "part 1 bytes exact");
            assert_eq!(&read[read.len() - tail.len()..], &tail[..], "tail bytes exact");

            // abort path: nothing becomes visible
            let key2 = unique("mpu-abort");
            let mut upload2 = t.store.put_multipart(&key2).await.expect("initiate2");
            upload2.put_part(PutPayload::from(Bytes::from(part))).await.expect("part");
            upload2.abort().await.expect("abort");
            let err = t.store.get(&key2).await.expect_err("aborted upload must publish nothing");
            assert!(matches!(err, StoreError::NotFound { .. }));
        });
    }

    /// Phase 1 of the crash/restart invariant: write the deterministic
    /// witnesses the post-restart phase re-reads.
    #[test]
    fn write_persistence_witnesses() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        if t.phase != "semantics" { return; }
        rt().block_on(async {
            for (key, body) in PERSISTENCE_WITNESSES {
                t.store
                    .put(&ObjectPath::from(*key), PutPayload::from_static(body))
                    .await
                    .expect("witness put");
            }
        });
    }

    /// Phase 2 (S3_CERT_PHASE=post-restart, after the runner kill -9s and
    /// restarts the server): the witnesses survive byte-exact.
    #[test]
    fn persisted_objects_survive_server_crash_restart() {
        if skip() { return; }
        let t = target_from_env().unwrap();
        if t.phase != "post-restart" { return; }
        rt().block_on(async {
            for (key, body) in PERSISTENCE_WITNESSES {
                let read = t.store
                    .get(&ObjectPath::from(*key))
                    .await
                    .expect("witness must survive the crash")
                    .bytes()
                    .await
                    .unwrap();
                assert_eq!(&read[..], *body, "witness {key} must be byte-exact after restart");
            }
        });
    }
}
