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

#[test]
fn wal_missing_records_for_checkpoint_replay_fails() {
    // R-01: commit records between the checkpoint watermark and the WAL head
    // are spliced out; recovery from the checkpoint must refuse with a typed
    // error instead of silently replaying a WAL with holes.
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

    let result = load_storage::<TestKeyspaceSet>(
        &storage_path,
        WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),
        Some(checkpoint),
    );
    match result {
        Err(StorageOpenError::RecoverFromCheckpoint { .. }) => (),
        Err(other) => panic!("expected the typed RecoverFromCheckpoint refusal, got: {other:?}"),
        Ok(_) => panic!("recovery over a WAL with missing checkpoint-replay records must fail, not open"),
    }
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
