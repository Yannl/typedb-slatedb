/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Fail-closed enforcement of the pre-G13 posture, and the attestation that proves it held.
//!
//! # Why enforcement lives in the process, not only in IAM
//!
//! Brief §I-11 and §I-96 require that pre-G13 runtime principals hold no delete-capable
//! credential, and §I-84 requires that no *reachable call path* can delete an authoritative
//! object. Those are two different obligations. A correct IAM policy satisfies the first and
//! says nothing about the second: code that attempts a delete against a delete-less credential
//! fails at the network boundary, late, with a permission error that reads like a
//! misconfiguration rather than like a violated invariant.
//!
//! [`DeleteGuard`] closes that gap by making the attempt itself impossible and legible. A
//! delete reaching this wrapper is a bug in the layer above, and it is reported as one.
//!
//! It is deliberately *not* a substitute for the credential restriction. It is the second of
//! two independent controls, and the one that also holds when the credential is wrong.

use std::sync::Arc;

use futures::StreamExt;
use object_store::{
    path::Path, CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
    ObjectStore, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions,
    Result as ObjectStoreResult,
};

/// An object store that refuses every deletion.
///
/// Wraps the real store and passes everything else through untouched.
///
/// `delete_stream` is the single choke point and that is why the guard is cheap to trust: it is
/// a *required* method of `ObjectStore`, and `ObjectStoreExt::delete` — the single-object form
/// every caller actually writes — is a provided method that routes through it. Blocking one
/// method therefore blocks both the bulk and the singular path, with no second route to keep in
/// sync.
#[derive(Debug)]
pub struct DeleteGuard {
    inner: Arc<dyn ObjectStore>,
}

impl DeleteGuard {
    pub fn new(inner: Arc<dyn ObjectStore>) -> Arc<dyn ObjectStore> {
        Arc::new(Self { inner })
    }

    fn refuse(path: &str) -> object_store::Error {
        object_store::Error::PermissionDenied {
            path: path.to_string(),
            source: Box::<dyn std::error::Error + Send + Sync>::from(
                "pre-G13 invariant: no reachable path may delete an authoritative object \
                 (brief I-84, I-96). This process holds a delete-free posture; a deletion \
                 reaching the object store is a defect in the caller, not a storage failure.",
            ),
        }
    }
}

impl std::fmt::Display for DeleteGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeleteGuard({})", self.inner)
    }
}

#[async_trait::async_trait]
impl ObjectStore for DeleteGuard {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> ObjectStoreResult<PutResult> {
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> ObjectStoreResult<Box<dyn MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> ObjectStoreResult<GetResult> {
        self.inner.get_opts(location, options).await
    }

    /// Refused. Every delete in the crate routes here.
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, ObjectStoreResult<Path>>,
    ) -> futures::stream::BoxStream<'static, ObjectStoreResult<Path>> {
        locations
            .map(|location| {
                let path = location.map(|p| p.to_string()).unwrap_or_else(|_| "<unknown>".into());
                Err(Self::refuse(&path))
            })
            .boxed()
    }

    fn list(
        &self,
        prefix: Option<&Path>,
    ) -> futures::stream::BoxStream<'static, ObjectStoreResult<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> ObjectStoreResult<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &Path,
        to: &Path,
        options: CopyOptions,
    ) -> ObjectStoreResult<()> {
        // Copy is permitted pre-G13 (brief I-96 allows put, multipart, read and copy).
        self.inner.copy_opts(from, to, options).await
    }

    /// Refused before the copy, rather than after it.
    ///
    /// The provided implementation is copy-then-delete. Left alone it would reach
    /// `delete_stream` and be refused correctly — but only once the copy had already happened,
    /// leaving a duplicate object behind and the store changed by an operation that failed.
    async fn rename_opts(
        &self,
        _from: &Path,
        to: &Path,
        _options: RenameOptions,
    ) -> ObjectStoreResult<()> {
        Err(Self::refuse(to.as_ref()))
    }
}

/// The resolved storage posture, recorded at startup.
///
/// Brief §I-84 requires proof rather than assertion, and the shape of that proof matters: it has
/// to be the *resolved* values the engine is actually running with, read back after every
/// default, override and feature gate has been applied. A constant restating the intended
/// posture would attest to the intent and not to the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureAttestation {
    pub wal_enabled: bool,
    pub garbage_collector_enabled: bool,
    pub compactor_enabled: bool,
    pub reads_committed_only: bool,
    pub delete_guard_installed: bool,
    pub durability_filter: &'static str,
}

impl PostureAttestation {
    /// Whether every pre-G13 requirement holds.
    pub fn is_compliant(&self) -> bool {
        !self.wal_enabled
            && !self.garbage_collector_enabled
            && !self.compactor_enabled
            && self.reads_committed_only
            && self.delete_guard_installed
    }

    /// The reasons it does not, in a form suitable for an error message.
    pub fn violations(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.wal_enabled {
            out.push("SlateDB WAL is enabled; TypeDB's durability crate is the sole WAL authority");
        }
        if self.garbage_collector_enabled {
            out.push("garbage collector is enabled; pre-G13 GC is report-only (brief I-77)");
        }
        if self.compactor_enabled {
            out.push(
                "in-process compactor is enabled; compaction is a reachability mutation and must \
                 be externally epoch-fenced (brief I-110)",
            );
        }
        if !self.reads_committed_only {
            out.push(
                "reads admit dirty (uncommitted) data; correctness reads must use resolved \
                 committed/non-dirty options (brief I-74)",
            );
        }
        if !self.delete_guard_installed {
            out.push("no delete guard installed; a reachable path could delete an authoritative object");
        }
        out
    }
}

impl std::fmt::Display for PostureAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "wal={} gc={} compactor={} reads={} delete_guard={} durability={}",
            self.wal_enabled,
            self.garbage_collector_enabled,
            self.compactor_enabled,
            if self.reads_committed_only { "committed" } else { "DIRTY" },
            if self.delete_guard_installed { "installed" } else { "ABSENT" },
            self.durability_filter,
        )
    }
}
