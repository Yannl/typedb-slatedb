/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![allow(const_item_mutation, reason = "`&mut CommitProfile::DISABLED` is a dummy")]

use std::fs;

use diagnostics::metrics::FsyncMetrics;
use durability::wal::WAL;
use resource::{
    constants::snapshot::BUFFER_KEY_INLINE,
    profile::{CommitProfile, StorageCounters},
};
use storage::{
    MVCCStorage, StorageOpenError,
    durability_client::WALClient,
    key_value::{StorageKeyArray, StorageKeyReference},
    snapshot::{CommittableSnapshot, ReadableSnapshot, WritableSnapshot},
};
use test_utils::{create_tmp_storage_dir, init_logging};
use test_utils_storage::{checkpoint_storage, create_storage, load_storage, test_keyspace_set};

#[test]
fn wal_and_checkpoint_ok() {
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));

    let storage_path = create_tmp_storage_dir();
    let (checkpoint, watermark) = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        (checkpoint_storage(&storage), storage.snapshot_watermark())
    };

    {
        let storage = load_storage::<TestKeyspaceSet>(
            &storage_path,
            WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
            Some(checkpoint),
        )
        .unwrap();
        assert_eq!(watermark, storage.snapshot_watermark());
        let snapshot = storage.open_snapshot_read();
        assert!(
            snapshot
                .get_mapped(StorageKeyReference::from(&key_hello), |_| true, StorageCounters::DISABLED)
                .unwrap()
                .is_some()
        );
    };
}

/// Splice every v1 frame whose header carries `target` out of the WAL files
/// under `storage_path`, leaving the framing of all other records intact —
/// the surgical "records are missing" corruption R-01's parser must refuse.
fn splice_out_sequence(storage_path: &std::path::Path, target: u64) {
    // v1 frame layout (durability/wal.rs module header): magic(4) version(1)
    // type(1) sequence(8 BE) encoded_len(4 BE) decoded_len(4 BE) crc(4)
    const MAGIC: [u8; 4] = [0xF7, b'T', b'W', b'F'];
    const HEADER_LEN: usize = 26;
    let wal_dir = storage_path.join(WAL::WAL_DIR_NAME);
    let mut spliced_any = false;
    for entry in fs::read_dir(&wal_dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.file_name().unwrap().to_str().unwrap().starts_with("wal-") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let mut kept = Vec::with_capacity(bytes.len());
        let mut offset = 0usize;
        while offset < bytes.len() {
            assert_eq!(&bytes[offset..offset + 4], &MAGIC, "test splicer only understands v1 frames");
            let sequence = u64::from_be_bytes(bytes[offset + 6..offset + 14].try_into().unwrap());
            let encoded_len = u32::from_be_bytes(bytes[offset + 14..offset + 18].try_into().unwrap()) as usize;
            let frame_end = offset + HEADER_LEN + encoded_len;
            if sequence == target {
                spliced_any = true;
            } else {
                kept.extend_from_slice(&bytes[offset..frame_end]);
            }
            offset = frame_end;
        }
        fs::write(&path, kept).unwrap();
    }
    assert!(spliced_any, "the target sequence number {target} was not found in the WAL");
}

/// Byte-exact snapshot of a directory tree: relative path -> content bytes.
/// Used to prove recovery refusals leave the live storage tree untouched
/// (R-05/R4-STOR-10).
fn snapshot_tree(root: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    walk(root, root, &mut out);
    out
}

#[test]
fn wal_missing_records_for_checkpoint_replay_fails() {
    // R-01 + R4-STOR-10: commit records between the checkpoint watermark and
    // the WAL head are spliced out. The candidate fails pre-restore
    // validation (the strict loader proves the hole), and the full-WAL-replay
    // fallback fails its own coverage proof on the SAME hole — so recovery
    // refuses with the typed exhaustion error that names the candidate's
    // failure, and the live storage tree is byte-identical.
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));
    let key_again = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"again"));

    let storage_path = create_tmp_storage_dir();
    let checkpoint = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
        let checkpoint = checkpoint_storage(&storage);

        // two commits AFTER the checkpoint; replay from the checkpoint needs both
        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_again.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        checkpoint
    };

    // commit 2 is the first record the checkpoint replay needs: remove it
    splice_out_sequence(&storage_path, 2);

    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let live_before = snapshot_tree(&storage_dir);

    let result = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        Some(checkpoint),
    );
    match result {
        Err(StorageOpenError::RecoveryFallbackExhausted { candidate_failures, .. }) => {
            assert!(
                !candidate_failures.is_empty(),
                "the exhaustion error must name the failed candidate's reason, got empty failures"
            );
        }
        Err(other) => panic!("expected the typed RecoveryFallbackExhausted refusal, got: {other:?}"),
        Ok(_) => panic!("recovery over a WAL with missing checkpoint-replay records must fail, not open"),
    }

    // R4-STOR-10: a refused recovery (rejected candidate + unprovable WAL
    // coverage) must leave the live storage tree byte-identical.
    assert_eq!(
        snapshot_tree(&storage_dir),
        live_before,
        "the live storage tree must be byte-identical after the typed recovery refusal"
    );
}

#[test]
fn wal_missing_records_entire_replay_fails() {
    // R-01: a commit record is spliced out of the middle of the WAL; a full
    // replay from scratch must refuse with a typed error — the parser proves
    // every sequence in start..=head, so the hole cannot pass.
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));
    let key_again = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"again"));

    let storage_path = create_tmp_storage_dir();
    {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();
        for key in [&key_hello, &key_world, &key_again] {
            let mut snapshot = storage.clone().open_snapshot_write();
            snapshot.put(key.clone());
            snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
        }
    }

    // remove the middle commit (sequence number 2) from the log
    splice_out_sequence(&storage_path, 2);

    let result = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        None,
    );
    match result {
        Err(StorageOpenError::RecoverFromDurability { .. }) => (),
        Err(other) => panic!("expected the typed RecoverFromDurability refusal, got: {other:?}"),
        Ok(_) => panic!("full WAL replay with a missing record must fail, not open"),
    }
}

#[test]
fn wal_and_no_checkpoint_ok() {
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));

    let storage_path = create_tmp_storage_dir();
    let watermark = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        storage.snapshot_watermark()
    };

    {
        let storage = load_storage::<TestKeyspaceSet>(
            &storage_path,
            WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(watermark, storage.snapshot_watermark());
        let snapshot = storage.open_snapshot_read();
        assert!(
            snapshot
                .get_mapped(StorageKeyReference::from(&key_hello), |_| true, StorageCounters::DISABLED)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn newest_unverifiable_checkpoint_falls_back_to_the_older_valid_one() {
    // R4-STOR-10/R4-STOR-08: two published cuts; the newer one is corrupted
    // after publish (its digest-bound COMPLETE no longer verifies). Selection
    // must fall back to the older verified cut, and recovery from it (plus
    // WAL replay) must surface every commit.
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));

    fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    let storage_path = create_tmp_storage_dir();
    let (older_checkpoint_dir, newer_checkpoint_dir) = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
        let older = checkpoint_storage(&storage);

        // recency-aware retention (R4-STOR-08) reclaims the strictly older
        // cut when the newer one publishes; stash a copy so this test can
        // model "two published cuts" (e.g. retention kept N > 1, or cleanup
        // failed benignly) and restore it after the newer cut lands.
        let stash = storage_path.join("older-cut-stash");
        copy_tree(&older.directory, &stash);

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
        let newer = checkpoint_storage(&storage);

        assert!(!older.directory.exists(), "recency-aware retention reclaims the strictly older cut");
        copy_tree(&stash, &older.directory);
        fs::remove_dir_all(&stash).unwrap();

        (older.directory, newer.directory)
    };
    assert!(newer_checkpoint_dir.exists(), "the newer cut must be published");
    // corrupt the newer cut AFTER publish: its bytes no longer match the
    // digest bound into COMPLETE, so it must not be selectable
    fs::write(newer_checkpoint_dir.join("STORAGE_METADATA"), b"999999").unwrap();

    let selected = storage::recovery::checkpoint::CheckpointReader::open_latest::<TestKeyspaceSet>(&storage_path)
        .unwrap()
        .expect("an older verified checkpoint candidate must be selected");
    assert_eq!(
        selected.directory, older_checkpoint_dir,
        "selection must fall back to the older verified cut, not the corrupt newer one"
    );

    let storage = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        Some(selected),
    )
    .unwrap();
    let snapshot = storage.open_snapshot_read();
    for key in [&key_hello, &key_world] {
        assert!(
            snapshot
                .get_mapped(StorageKeyReference::from(key), |_| true, StorageCounters::DISABLED)
                .unwrap()
                .is_some(),
            "every commit must be recovered from the older cut + WAL replay"
        );
    }
}

#[test]
fn ahead_of_durability_checkpoint_falls_back_to_full_wal_replay() {
    // R4-STOR-10: the only checkpoint's watermark is AHEAD of the retained
    // WAL (the WAL tail was truncated after the cut). The candidate fails
    // pre-restore validation with the typed ahead-of-durability refusal, and
    // recovery falls back to full WAL replay — which the strict loader proves
    // contiguous — instead of failing the whole open.
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));

    let storage_path = create_tmp_storage_dir();
    let checkpoint = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        // watermark 2: both commits are inside the cut
        checkpoint_storage(&storage)
    };

    // truncate the WAL tail: every frame for sequence 2 disappears, so the
    // durability head regresses to 1 and the checkpoint (watermark 2) is now
    // ahead of the retained WAL.
    splice_out_sequence(&storage_path, 2);

    let storage = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        Some(checkpoint),
    )
    .expect("an ahead checkpoint with a fully-covering retained WAL must fall back to full WAL replay");

    // full WAL replay recovered exactly the retained history: commit 1 is
    // present, the truncated commit 2 is not.
    let snapshot = storage.clone().open_snapshot_read();
    assert!(
        snapshot
            .get_mapped(StorageKeyReference::from(&key_hello), |_| true, StorageCounters::DISABLED)
            .unwrap()
            .is_some(),
        "the retained commit must be recovered by the full WAL replay fallback"
    );
    assert!(
        snapshot
            .get_mapped(StorageKeyReference::from(&key_world), |_| true, StorageCounters::DISABLED)
            .unwrap()
            .is_none(),
        "the truncated commit is not in the retained WAL and must not resurface from the rejected checkpoint"
    );
}

#[test]
fn no_wal_and_checkpoint_illegal() {
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));

    let storage_path = create_tmp_storage_dir();
    let (_checkpoint, directory) = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        (checkpoint_storage(&storage), storage.path().parent().unwrap().to_owned())
    };

    // delete wal
    fs::remove_dir_all(directory.join(WAL::WAL_DIR_NAME)).unwrap();

    {
        let wal_result = WAL::load(&storage_path, FsyncMetrics::disabled());
        assert!(wal_result.is_err());
    }
}

#[test]
fn no_wal_and_no_checkpoint_and_keyspaces_illegal() {
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));

    let storage_path = create_tmp_storage_dir();
    {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
    };

    // delete wal
    fs::remove_dir_all(storage_path.join(WAL::WAL_DIR_NAME)).unwrap();

    {
        let wal_result = WAL::load(&storage_path, FsyncMetrics::disabled());
        assert!(wal_result.is_err());
    }
}

#[test]
fn no_wal_and_no_checkpoint_and_no_keyspaces_illegal() {
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let key_world = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"world"));

    let storage_path = create_tmp_storage_dir();
    {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();

        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.put(key_world.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
    };

    // delete wal
    fs::remove_dir_all(storage_path.join(WAL::WAL_DIR_NAME)).unwrap();
    // delete keyspaces
    fs::remove_dir_all(storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME)).unwrap();

    {
        let wal_result = WAL::load(&storage_path, FsyncMetrics::disabled());
        assert!(wal_result.is_err());
    }
}

#[test]
fn a_checkpoint_bound_to_a_different_backend_identity_refuses_restore() {
    // R4-STOR-01: a cut created under backend identity A must refuse restore
    // under identity B — a checkpoint-level refusal, pre-mutation, never a
    // silent fallback that rebuilds under B and discards the presented cut.
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));

    let storage_path = create_tmp_storage_dir();
    // the identity THIS test environment resolves (identity B, the opener)...
    let context = storage::factory::BackendContext::resolve_from_env().unwrap();
    // ...and a FOREIGN identity A: same cut format, different backend config.
    let foreign_spec = match context.spec() {
        storage::factory::BackendSpec::Classic => storage::factory::BackendSpec::from_profile(
            storage::factory::StorageBackendProfile::U2S3SlateS3FileWal,
        )
        .unwrap(),
        storage::factory::BackendSpec::SlateDbR2(_) => storage::factory::BackendSpec::Classic,
    };
    let foreign_identity = storage::factory::BackendIdentity::from_spec(&foreign_spec);
    assert_ne!(
        foreign_identity.config_digest(),
        context.identity().config_digest(),
        "the two identities must genuinely differ"
    );

    let checkpoint = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();
        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        // a cut sealed under the FOREIGN identity A (as if copied in from a
        // database bound to another configuration)
        let writer =
            storage::recovery::checkpoint::CheckpointWriter::new(storage.path().parent().unwrap()).unwrap();
        storage.checkpoint(&writer).unwrap();
        writer.add_identity(&foreign_identity).unwrap();
        writer.finish().unwrap()
    };

    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let live_before = snapshot_tree(&storage_dir);

    let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();
    let resources = test_utils_storage::create_rocks_resources();
    let result = MVCCStorage::load_with_recovery_fallback::<TestKeyspaceSet>(
        "storage",
        &storage_path,
        WALClient::new(wal),
        vec![checkpoint],
        &resources,
        &context,
    );
    let error = result.err().expect("a cross-identity cut must refuse the load");
    assert!(
        matches!(error, StorageOpenError::CheckpointIdentityRefused { .. }),
        "a cross-identity cut must be the typed CheckpointIdentityRefused, got: {error:?}",
    );
    assert_eq!(
        live_before,
        snapshot_tree(&storage_dir),
        "the identity refusal must leave the live storage tree byte-identical"
    );
}

#[test]
fn a_checkpoint_bound_to_the_same_backend_identity_restores() {
    // positive control for the R4-STOR-01 binding: a cut sealed under the SAME
    // identity the opener resolves restores exactly like an unbound cut.
    test_keyspace_set! { Keyspace => 0: "keyspace" }

    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));

    let storage_path = create_tmp_storage_dir();
    let context = storage::factory::BackendContext::resolve_from_env().unwrap();

    let (checkpoint, watermark) = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();
        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        let writer =
            storage::recovery::checkpoint::CheckpointWriter::new(storage.path().parent().unwrap()).unwrap();
        storage.checkpoint(&writer).unwrap();
        writer.add_identity(context.identity()).unwrap();
        (writer.finish().unwrap(), storage.snapshot_watermark())
    };

    let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();
    let resources = test_utils_storage::create_rocks_resources();
    let (storage, restored) = MVCCStorage::load_with_recovery_fallback::<TestKeyspaceSet>(
        "storage",
        &storage_path,
        WALClient::new(wal),
        vec![checkpoint],
        &resources,
        &context,
    )
    .expect("a same-identity cut must restore");
    assert_eq!(restored, Some(watermark), "the identity-bound cut itself must have been restored");
    let storage = std::sync::Arc::new(storage);
    let snapshot = storage.open_snapshot_read();
    assert!(
        snapshot
            .get_mapped(StorageKeyReference::from(&key_hello), |_| true, StorageCounters::DISABLED)
            .unwrap()
            .is_some(),
        "the restored cut must serve the committed data"
    );
}
