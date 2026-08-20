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
            snapshot.get_mapped(StorageKeyReference::from(key), |_| true, StorageCounters::DISABLED).unwrap().is_some(),
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
        storage::factory::BackendSpec::Classic => {
            storage::factory::BackendSpec::from_profile(storage::factory::StorageBackendProfile::U2S3SlateS3FileWal)
                .unwrap()
        }
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
        let writer = storage::recovery::checkpoint::CheckpointWriter::new(storage.path().parent().unwrap()).unwrap();
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

        let writer = storage::recovery::checkpoint::CheckpointWriter::new(storage.path().parent().unwrap()).unwrap();
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

// ---------------------------------------------------------------------------
// R5-STOR-06: scratch-restore kill-point matrix. A restore materialises,
// digest-verifies, opens, and replays the cut in a SCRATCH directory and only
// then atomically activates it (rename-swap). Each test below fabricates the
// exact on-disk state a crash at one boundary leaves behind and proves the
// restart converges: predecessor intact + active for every pre-activation
// failure, successor active after activation.
// ---------------------------------------------------------------------------

/// Recursively copy a directory tree (used to fabricate crash states).
fn copy_dir_tree(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Common fixture: a storage tree with one committed key and a published,
/// identity-bound checkpoint. Returns the checkpoint reader.
fn storage_with_checkpoint(
    storage_path: &std::path::Path,
    key: &StorageKeyArray<BUFFER_KEY_INLINE>,
) -> storage::recovery::checkpoint::CheckpointReader {
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    let storage = create_storage::<TestKeyspaceSet>(storage_path).unwrap();
    let mut snapshot = storage.clone().open_snapshot_write();
    snapshot.put(key.clone());
    snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
    checkpoint_storage(&storage)
}

fn assert_recovers_with_key(
    storage_path: &std::path::Path,
    checkpoint: storage::recovery::checkpoint::CheckpointReader,
    key: &StorageKeyArray<BUFFER_KEY_INLINE>,
) {
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    let storage = load_storage::<TestKeyspaceSet>(
        storage_path,
        WAL::load(storage_path, FsyncMetrics::disabled()).unwrap(),
        Some(checkpoint),
    )
    .expect("recovery must converge");
    let snapshot = storage.open_snapshot_read();
    assert!(
        snapshot.get_mapped(StorageKeyReference::from(key), |_| true, StorageCounters::DISABLED).unwrap().is_some(),
        "the committed key must be present after convergence"
    );
}

fn assert_no_restore_residue(storage_path: &std::path::Path) {
    for entry in fs::read_dir(storage_path).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !name.starts_with("restore-scratch-") && !name.starts_with("restore-retired-"),
            "no restore residue may remain after convergence, found: {name}"
        );
    }
}

#[test]
fn restore_leaves_no_scratch_residue_on_success() {
    // positive control for the scratch protocol: a normal checkpoint
    // recovery goes through scratch + activation and leaves a clean tree.
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    init_logging();
    let key = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let storage_path = create_tmp_storage_dir();
    let checkpoint = storage_with_checkpoint(&storage_path, &key);
    assert_recovers_with_key(&storage_path, checkpoint, &key);
    assert_no_restore_residue(&storage_path);
}

#[test]
fn restart_after_crash_before_activation_converges_with_predecessor_intact() {
    // Kill points "after copy", "after open", "after replay", "after
    // digest": every pre-activation crash leaves (only) a scratch directory
    // — here fabricated as a full copy of the cut, the state right after
    // replay. Restart must reclaim it and recover normally, with the
    // predecessor having been intact throughout.
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    init_logging();
    let key = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let storage_path = create_tmp_storage_dir();
    let checkpoint = storage_with_checkpoint(&storage_path, &key);

    // fabricate the mid-restore crash state
    let scratch =
        storage_path.join(format!("restore-scratch-{}", checkpoint.directory.file_name().unwrap().to_str().unwrap()));
    copy_dir_tree(&checkpoint.directory, &scratch);

    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let live_before = snapshot_tree(&storage_dir);

    assert_recovers_with_key(&storage_path, checkpoint, &key);
    assert_no_restore_residue(&storage_path);
    drop(live_before); // the successful restore legitimately replaces live afterwards
}

#[test]
fn restart_after_crash_between_activation_renames_converges() {
    // Kill point "mid-activation": live -> retired happened, scratch -> live
    // did not. The predecessor sits under the retired name and the live
    // directory is missing. Restart must roll the predecessor back and then
    // recover normally to the successor.
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    init_logging();
    let key = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let storage_path = create_tmp_storage_dir();
    let checkpoint = storage_with_checkpoint(&storage_path, &key);

    let attempt = checkpoint.directory.file_name().unwrap().to_str().unwrap().to_owned();
    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let scratch = storage_path.join(format!("restore-scratch-{attempt}"));
    let retired = storage_path.join(format!("restore-retired-{attempt}"));

    // fabricate the torn swap: predecessor renamed away, successor-in-progress in scratch
    copy_dir_tree(&checkpoint.directory, &scratch);
    fs::rename(&storage_dir, &retired).unwrap();
    assert!(!storage_dir.exists(), "precondition: the live directory is missing mid-swap");

    assert_recovers_with_key(&storage_path, checkpoint, &key);
    assert_no_restore_residue(&storage_path);
    assert!(storage_dir.exists(), "the live directory is active again after convergence");
}

#[test]
fn restart_after_crash_after_activation_converges_with_successor_active() {
    // Kill point "post-activation": both renames happened; only the retired
    // predecessor's reclaim was lost. Restart must keep the successor active
    // and reclaim the residue.
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    init_logging();
    let key = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let storage_path = create_tmp_storage_dir();
    let checkpoint = storage_with_checkpoint(&storage_path, &key);

    let attempt = checkpoint.directory.file_name().unwrap().to_str().unwrap().to_owned();
    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let retired = storage_path.join(format!("restore-retired-{attempt}"));
    // fabricate: the predecessor's bytes linger under the retired name
    copy_dir_tree(&storage_dir, &retired);

    assert_recovers_with_key(&storage_path, checkpoint, &key);
    assert_no_restore_residue(&storage_path);
}

#[test]
fn a_corrupt_cut_fails_in_scratch_and_leaves_the_predecessor_byte_identical() {
    // R5-STOR-06 core + R5-STOR-09 mutant "nested file byte flip": the cut
    // passes pre-restore validation (watermark/WAL), but a data byte was
    // flipped after sealing. The scratch digest verification refuses it with
    // a typed error BEFORE the live tree is touched — the predecessor is
    // byte-identical afterwards. Under the pre-R5 protocol this mirrored
    // over live first and destroyed the predecessor.
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    init_logging();
    let key = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let storage_path = create_tmp_storage_dir();
    let checkpoint = storage_with_checkpoint(&storage_path, &key);

    // flip bytes in one sealed keyspace data file (keep the length)
    let keyspace_dir = checkpoint.directory.join("keyspace");
    let victim = fs::read_dir(&keyspace_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_file() && fs::metadata(path).unwrap().len() > 0)
        .expect("the cut contains at least one non-empty keyspace file");
    let mut bytes = fs::read(&victim).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&victim, bytes).unwrap();

    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let live_before = snapshot_tree(&storage_dir);

    let result = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        Some(checkpoint),
    );
    match result {
        Err(StorageOpenError::RecoverFromCheckpoint { typedb_source, .. }) => {
            assert!(
                matches!(
                    typedb_source,
                    storage::recovery::checkpoint::CheckpointLoadError::RestoreScratchDigestMismatch { .. }
                ),
                "expected the typed scratch digest refusal, got: {typedb_source:?}"
            );
        }
        other => panic!("expected the typed RecoverFromCheckpoint(RestoreScratchDigestMismatch), got: {other:?}"),
    }
    assert_eq!(
        snapshot_tree(&storage_dir),
        live_before,
        "R5-STOR-06: a cut refused in scratch must leave the predecessor byte-identical"
    );
    assert_no_restore_residue(&storage_path);
}

#[test]
fn a_hash_consistent_but_unopenable_cut_fails_in_scratch_not_on_live() {
    // R5-STOR-06 core mutant: the cut is digest-CONSISTENT (sealed over the
    // garbage it contains) but semantically invalid — the engine cannot open
    // it. The failure must happen in scratch, with the predecessor
    // byte-identical and still openable afterwards.
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    init_logging();
    let key = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));
    let storage_path = create_tmp_storage_dir();
    {
        // a live predecessor tree with one committed key (no checkpoint —
        // the only candidate will be the garbage cut below)
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();
        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();
    }

    // seal a semantically invalid cut: a keyspace whose CURRENT file is
    // garbage (the engine refuses to open it), digest-consistent because the
    // manifest is computed over exactly these bytes. Watermark 1 == the WAL
    // head, so pre-restore validation passes.
    let context = storage::factory::BackendContext::resolve_from_env().unwrap();
    let writer = storage::recovery::checkpoint::CheckpointWriter::new(&storage_path).unwrap();
    let temp = writer.temporary_directory.clone();
    fs::create_dir_all(temp.join("keyspace")).unwrap();
    fs::write(temp.join("keyspace").join("CURRENT"), b"not-a-real-manifest-pointer\n").unwrap();
    fs::write(temp.join("STORAGE_METADATA"), b"1").unwrap();
    writer.add_identity(context.identity()).unwrap();
    let garbage_cut = writer.finish().unwrap();

    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let live_before = snapshot_tree(&storage_dir);

    let result = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        Some(garbage_cut),
    );
    match result {
        Err(StorageOpenError::RecoverFromCheckpoint { typedb_source, .. }) => {
            assert!(
                matches!(typedb_source, storage::recovery::checkpoint::CheckpointLoadError::KeyspaceOpen { .. }),
                "the semantically invalid cut must fail at the scratch engine open, got: {typedb_source:?}"
            );
        }
        other => panic!("expected the typed RecoverFromCheckpoint(KeyspaceOpen) refusal, got: {other:?}"),
    }
    assert_eq!(
        snapshot_tree(&storage_dir),
        live_before,
        "R5-STOR-06: a cut that fails its scratch engine open must leave the predecessor byte-identical"
    );
    assert_no_restore_residue(&storage_path);

    // and the predecessor still RECOVERS: it is not just byte-identical, it
    // is active and serves the committed data (via full WAL replay here).
    let recovered = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        None,
    )
    .expect("the predecessor tree must still recover after the refused cut");
    let snapshot = recovered.open_snapshot_read();
    assert!(
        snapshot.get_mapped(StorageKeyReference::from(&key), |_| true, StorageCounters::DISABLED).unwrap().is_some()
    );
}

// ---------------------------------------------------------------------------
// R5-STOR-10 (checkpoint half): a legacy cut with no bound identity is a
// typed refusal on ordinary recovery, and the explicit operator import (with
// provenance) is the only way in.
// ---------------------------------------------------------------------------

#[test]
fn a_legacy_cut_without_identity_refuses_recovery_until_explicitly_imported() {
    test_keyspace_set! { Keyspace => 0: "keyspace" }
    init_logging();
    let key_hello = StorageKeyArray::<BUFFER_KEY_INLINE>::from((TestKeyspaceSet::Keyspace, b"hello"));

    let storage_path = create_tmp_storage_dir();
    let context = storage::factory::BackendContext::resolve_from_env().unwrap();

    let (legacy_cut, watermark) = {
        let storage = create_storage::<TestKeyspaceSet>(&storage_path).unwrap();
        let mut snapshot = storage.clone().open_snapshot_write();
        snapshot.put(key_hello.clone());
        snapshot.commit(&mut CommitProfile::DISABLED).unwrap();

        // a cut sealed WITHOUT an identity — the legacy shape
        let writer = storage::recovery::checkpoint::CheckpointWriter::new(storage.path().parent().unwrap()).unwrap();
        storage.checkpoint(&writer).unwrap();
        (writer.finish().unwrap(), storage.snapshot_watermark())
    };

    let storage_dir = storage_path.join(MVCCStorage::<WALClient>::STORAGE_DIR_NAME);
    let live_before = snapshot_tree(&storage_dir);

    // 1. ordinary recovery: the typed legacy refusal, live tree untouched
    let resources = test_utils_storage::create_rocks_resources();
    let result = MVCCStorage::load_with_recovery_fallback::<TestKeyspaceSet>(
        "storage",
        &storage_path,
        WALClient::new(WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap()),
        vec![storage::recovery::checkpoint::CheckpointReader { directory: legacy_cut.directory.clone() }],
        &resources,
        &context,
    );
    let error = result.err().expect("a legacy identity-less cut must refuse ordinary recovery");
    assert!(
        matches!(error, StorageOpenError::CheckpointLegacyIdentityRefused { .. }),
        "expected the typed CheckpointLegacyIdentityRefused, got: {error:?}"
    );
    assert_eq!(
        snapshot_tree(&storage_dir),
        live_before,
        "R5-STOR-10: the legacy refusal must leave the live storage tree byte-identical"
    );

    // 2. the explicit import: operator acknowledgement stamps the identity +
    //    provenance and reseals the cut
    let imported = storage::recovery::checkpoint::import_legacy_checkpoint_identity(
        &legacy_cut.directory,
        context.identity(),
        "operator acknowledges: cut exported before identity binding; source inventory verified",
    )
    .expect("the explicit import must succeed");

    // 3. recovery from the imported cut now succeeds and serves the data
    let (recovered, restored) = MVCCStorage::load_with_recovery_fallback::<TestKeyspaceSet>(
        "storage",
        &storage_path,
        WALClient::new(WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap()),
        vec![imported],
        &resources,
        &context,
    )
    .expect("recovery from the imported cut must succeed");
    assert_eq!(restored, Some(watermark), "the imported cut itself must have been restored");
    let recovered = std::sync::Arc::new(recovered);
    let snapshot = recovered.open_snapshot_read();
    assert!(
        snapshot
            .get_mapped(StorageKeyReference::from(&key_hello), |_| true, StorageCounters::DISABLED)
            .unwrap()
            .is_some(),
        "the imported cut must serve the committed data"
    );
}
