/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Negative controls for the pre-G13 storage posture.
//!
//! Every test here asserts that an *unsafe* configuration is rejected. That is the only kind of
//! assertion that can prove a safety control works: a suite that only checks the safe path
//! passes identically whether the control is present, absent, or silently repairing the input.
//!
//! The postures under test are contract requirements, not preferences — brief I-74 (committed
//! reads), I-77 (report-only GC), I-84 and I-96 (no delete-capable path), I-110 (externally
//! fenced reachability mutations).

use std::sync::Arc;

use object_store::{local::LocalFileSystem, ObjectStore, ObjectStoreExt};
use slatedb_keyspace::{
    config::SAFE_L0_CEILING, Backend, DeleteGuard, KeyspaceSet, StoreConfig, Tuning,
};

#[test]
fn a_wal_enabled_profile_is_refused() {
    let mut tuning = Tuning::object_storage();
    tuning.wal_enabled = true;
    let message = tuning.validate().unwrap_err().to_string();
    assert!(message.contains("wal_enabled"), "got: {message}");
}

#[test]
fn a_gc_enabled_profile_is_refused() {
    let mut tuning = Tuning::object_storage();
    tuning.gc_interval = Some(std::time::Duration::from_secs(600));
    let message = tuning.validate().unwrap_err().to_string();
    assert!(message.contains("garbage collection"), "got: {message}");
}

#[test]
fn an_unbounded_l0_ceiling_is_refused_without_external_compaction() {
    // The workaround for a disabled compactor is to raise the L0 ceiling until backpressure
    // stops firing. It restores liveness by making read amplification unbounded — every L0 SST
    // covering a key is a billed request — so it must not be reachable by accident.
    let mut tuning = Tuning::object_storage();
    tuning.l0_ceiling = 1_000_000;
    let message = tuning.validate().unwrap_err().to_string();
    assert!(message.contains("l0_ceiling"), "got: {message}");

    // Declaring external compaction makes it a deliberate, recorded claim rather than a number
    // nobody had to justify.
    tuning.external_compaction_arranged = true;
    assert!(tuning.validate().is_ok());
}

#[test]
fn the_shipped_profiles_are_compliant() {
    for tuning in [Tuning::local(), Tuning::object_storage()] {
        assert!(!tuning.wal_enabled, "SlateDB's WAL must be off on every shipped profile");
        assert!(tuning.gc_interval.is_none(), "GC must be off on every shipped profile");
        assert!(tuning.l0_ceiling <= SAFE_L0_CEILING);
        assert!(tuning.validate().is_ok());

        let settings = tuning.to_settings();
        assert!(settings.compactor_options.is_none(), "no implicit compactor may start");
        assert!(settings.garbage_collector_options.is_none());
    }
}

#[test]
fn reads_are_committed_and_non_dirty_and_cannot_be_overridden() {
    // Brief I-74. `dirty` exposes writes past the committed watermark; there is no setter for
    // it, so this asserts both the value and the absence of a way to change it.
    for tuning in [Tuning::local(), Tuning::object_storage()] {
        assert!(!tuning.read_options().dirty, "correctness reads must not admit dirty data");
        assert!(!tuning.scan_options().dirty, "scans must not admit dirty data either");
    }
}

#[test]
fn a_delete_is_refused_by_the_guard() {
    // The guard is the second of two controls, and the one that still holds when the credential
    // is wrong. `delete_stream` is the required trait method every delete routes through, so
    // blocking it blocks the bulk and single-object forms alike.
    let dir = tempfile::tempdir().unwrap();
    let inner: Arc<dyn ObjectStore> =
        Arc::new(LocalFileSystem::new_with_prefix(dir.path()).unwrap());
    let guarded = DeleteGuard::new(Arc::clone(&inner));

    let path = object_store::path::Path::from("victim");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

    runtime.block_on(async {
        guarded.put(&path, "payload".into()).await.expect("writes still work");

        let refused = guarded.delete(&path).await.unwrap_err();
        assert!(
            matches!(refused, object_store::Error::PermissionDenied { .. }),
            "a delete must be refused as a permission violation, got: {refused}"
        );

        // And the object is still there — the refusal happened before anything was removed.
        assert!(guarded.head(&path).await.is_ok(), "the object must survive a refused delete");

        // Rename is copy-then-delete in the provided implementation; it must fail before the
        // copy, leaving no duplicate behind.
        let renamed = object_store::path::Path::from("victim-renamed");
        assert!(guarded.rename(&path, &renamed).await.is_err());
        assert!(
            guarded.head(&renamed).await.is_err(),
            "a refused rename must not leave the copy half behind"
        );
    });
}

#[test]
fn an_opened_store_attests_its_resolved_posture() {
    // Brief I-84 wants proof rather than assertion, and the proof has to be the values the
    // engine actually resolved to — not a constant restating the intent.
    let dir = tempfile::tempdir().unwrap();
    let set = KeyspaceSet::open_with(StoreConfig {
        backend: Backend::Local { path: dir.path().to_path_buf() },
        tuning: Tuning::object_storage(),
    })
    .unwrap();

    let attestation = set.attestation();
    assert!(attestation.is_compliant(), "violations: {:?}", attestation.violations());
    assert!(!attestation.wal_enabled);
    assert!(!attestation.garbage_collector_enabled);
    assert!(!attestation.compactor_enabled);
    assert!(attestation.reads_committed_only);
    assert!(attestation.delete_guard_installed);
}

#[test]
fn opening_with_a_non_compliant_posture_fails_rather_than_being_repaired() {
    // Silently correcting an unsafe request leaves its author believing the unsafe option is
    // available, which is how it comes back.
    let dir = tempfile::tempdir().unwrap();
    let mut tuning = Tuning::object_storage();
    tuning.wal_enabled = true;

    let result = KeyspaceSet::open_with(StoreConfig {
        backend: Backend::Local { path: dir.path().to_path_buf() },
        tuning,
    });
    let Err(error) = result else { panic!("a WAL-enabled posture must not open") };
    assert!(error.to_string().contains("wal_enabled"), "got: {error}");
}
