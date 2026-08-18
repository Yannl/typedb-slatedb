/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![deny(unused_must_use)]
#![deny(rust_2018_idioms)]

use std::{
    fs::{self, OpenOptions, read_dir},
    io::{Seek, Write},
};

use durability::DurabilityService;
use durability_test_common::{TestRecord, create_wal, load_wal, try_load_wal};
use itertools::Itertools;
use rand::prelude::*;
use tempdir::TempDir;

#[test]
fn basic() {
    let directory = TempDir::new("wal-test").unwrap();

    let message = TestRecord { bytes: b"hello world".to_vec() };

    let wal = create_wal(&directory);
    let written_entry_id = wal.sequenced_write(TestRecord::RECORD_TYPE, message.bytes()).unwrap();
    drop(wal);

    let wal = load_wal(&directory);
    let raw_record = wal.iter_any_from(written_entry_id).unwrap().next().unwrap().unwrap();
    let read_record = TestRecord::new(Vec::from(raw_record.bytes));
    assert_eq!(read_record, message);
}

#[test]
fn added_zeros() {
    // R-01b: a zero-filled tail reaching physical EOF is the crash artifact
    // of page-zero-filling filesystems — the ONE non-prefix shape that is
    // still a torn terminal append. It is repaired to the authenticated
    // prefix, with the damaged original preserved in a forensic sidecar.
    const ADDED_LEN: usize = 120;

    let directory = TempDir::new("wal-test").unwrap();

    let message = TestRecord { bytes: b"hello world".to_vec() };

    let wal = create_wal(&directory);
    let written_entry_id = wal.sequenced_write(TestRecord::RECORD_TYPE, message.bytes()).unwrap();
    drop(wal);

    let wal_file = &read_dir(directory.path().join("wal")).unwrap().exactly_one().unwrap().unwrap().path();
    let len = fs::metadata(wal_file).unwrap().len();
    let mut file = OpenOptions::new().read(true).append(true).open(wal_file).unwrap();
    file.write_all(&[0; ADDED_LEN]).unwrap();
    file.sync_all().unwrap();
    assert_eq!(fs::metadata(wal_file).unwrap().len(), len + ADDED_LEN as u64);

    let wal = load_wal(&directory);
    let mut wal_iterator = wal.iter_any_from(written_entry_id).unwrap();
    let raw_record = wal_iterator.next().unwrap().unwrap();
    let read_record = TestRecord::new(Vec::from(raw_record.bytes));
    assert_eq!(read_record, message);
    assert!(wal_iterator.next().is_none());
    assert_eq!(fs::metadata(wal_file).unwrap().len(), len);
    let sidecars = forensic_sidecars(&directory);
    assert_eq!(sidecars.len(), 1, "tail repair must preserve the damaged original in a forensic sidecar");
}

#[test]
fn added_junk() {
    // R-01b: non-zero garbage after the final valid frame is NOT a torn
    // append (the writer only ever leaves a valid-frame prefix or zero
    // fill), so it is a typed quarantine with the original bytes untouched
    // — never a silent truncation that erases the evidence.
    const ADDED_LEN: usize = 32; // Maximum number of bytes rand will generate in one go.

    let directory = TempDir::new("wal-test").unwrap();

    let message = TestRecord { bytes: b"hello world".to_vec() };

    let wal = create_wal(&directory);
    wal.sequenced_write(TestRecord::RECORD_TYPE, message.bytes()).unwrap();
    drop(wal);

    let wal_file = &read_dir(directory.path().join("wal")).unwrap().exactly_one().unwrap().unwrap().path();
    let len = fs::metadata(wal_file).unwrap().len();
    let mut file = OpenOptions::new().read(true).append(true).open(wal_file).unwrap();
    let mut junk = thread_rng().r#gen::<[u8; ADDED_LEN]>();
    junk[0] |= 1; // never all-zero, and never a valid v1 magic prefix
    junk[0] &= !0xF0;
    file.write_all(&junk).unwrap();
    file.sync_all().unwrap();
    assert_eq!(fs::metadata(wal_file).unwrap().len(), len + ADDED_LEN as u64);

    let result = try_load_wal(&directory);
    assert!(result.is_err(), "trailing garbage after a valid frame must quarantine the load");
    assert_eq!(
        fs::metadata(wal_file).unwrap().len(),
        len + ADDED_LEN as u64,
        "quarantine must leave the original bytes untouched"
    );
    assert!(forensic_sidecars(&directory).is_empty(), "quarantine must not attempt a repair");
}

#[test]
fn corrupted_record_zeros() {
    // R-01b: overwriting bytes INSIDE the final record is stable
    // corruption (the frame is complete but fails its checksum), not a torn
    // append: the load quarantines with a typed error and the original
    // bytes stay untouched — the pre-audit behaviour silently truncated the
    // whole file to zero, erasing the evidence.
    let message = TestRecord { bytes: b"hello world".to_vec() };

    for corrupt_size in 1..=16 {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);
        wal.sequenced_write(TestRecord::RECORD_TYPE, message.bytes()).unwrap();
        drop(wal);

        let wal_file = &read_dir(directory.path().join("wal")).unwrap().exactly_one().unwrap().unwrap().path();
        let len = fs::metadata(wal_file).unwrap().len();
        let original = fs::read(wal_file).unwrap();
        let mut file = OpenOptions::new().read(true).write(true).open(wal_file).unwrap();
        file.seek(std::io::SeekFrom::End(-16)).unwrap();
        file.write_all(&vec![0; corrupt_size]).unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::metadata(wal_file).unwrap().len(), len);
        let damaged = fs::read(wal_file).unwrap();
        if damaged == original {
            continue; // these bytes were already zero: nothing was corrupted
        }

        let result = try_load_wal(&directory);
        assert!(result.is_err(), "corruption inside the final record must quarantine (size {corrupt_size})");
        assert_eq!(fs::read(wal_file).unwrap(), damaged, "quarantine must leave the original bytes untouched");
        assert!(forensic_sidecars(&directory).is_empty(), "quarantine must not attempt a repair");
    }
}

#[test]
fn corrupted_record_junk() {
    // R-01b: same contract as corrupted_record_zeros for random damage.
    let message = TestRecord { bytes: b"hello world".to_vec() };

    for corrupt_size in 1..=16 {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);
        wal.sequenced_write(TestRecord::RECORD_TYPE, message.bytes()).unwrap();
        drop(wal);

        let wal_file = &read_dir(directory.path().join("wal")).unwrap().exactly_one().unwrap().unwrap().path();
        let len = fs::metadata(wal_file).unwrap().len();
        let original = fs::read(wal_file).unwrap();
        let mut file = OpenOptions::new().read(true).write(true).open(wal_file).unwrap();
        file.seek(std::io::SeekFrom::End(-16)).unwrap();
        let mut buf = vec![0; corrupt_size];
        while buf == original[len as usize - 16..len as usize - 16 + corrupt_size] {
            thread_rng().fill_bytes(&mut buf);
        }
        file.write_all(&buf).unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::metadata(wal_file).unwrap().len(), len);
        let damaged = fs::read(wal_file).unwrap();

        let result = try_load_wal(&directory);
        assert!(result.is_err(), "corruption inside the final record must quarantine (size {corrupt_size})");
        assert_eq!(fs::read(wal_file).unwrap(), damaged, "quarantine must leave the original bytes untouched");
        assert!(forensic_sidecars(&directory).is_empty(), "quarantine must not attempt a repair");
    }
}

/// Forensic sidecar files (`torn-*`) left by a permitted tail repair.
fn forensic_sidecars(directory: &TempDir) -> Vec<std::path::PathBuf> {
    read_dir(directory.path().join("wal"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_str().unwrap().starts_with("torn-"))
        .collect()
}
