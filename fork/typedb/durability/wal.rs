/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! # WAL on-disk frame format (R-01b)
//!
//! Two frame encodings coexist in one WAL directory; the reader dispatches
//! per record on a 4-byte magic, so old directories keep loading while every
//! new append is authenticated.
//!
//! **v1 (written by all new appends)** — 26-byte header + payload:
//!
//! | offset | size | field                                    |
//! |--------|------|------------------------------------------|
//! | 0      | 4    | magic `0xF7 'T' 'W' 'F'`                 |
//! | 4      | 1    | format version (`1`)                     |
//! | 5      | 1    | record type                              |
//! | 6      | 8    | sequence number (BE)                     |
//! | 14     | 4    | encoded (lz4) payload length (BE u32)    |
//! | 18     | 4    | decoded payload length (BE u32)          |
//! | 22     | 4    | CRC-32/IEEE over bytes 0..22 + payload   |
//! | 26     | n    | lz4 payload (`encoded_len` bytes)        |
//!
//! Both declared lengths are bounded by [`MAX_FRAME_PAYLOAD_LEN`] on write
//! AND on read (allocation/decompression budget), and the CRC covers the
//! whole header and the compressed payload, so a bit flip anywhere in the
//! frame is a typed [`WALError::CorruptFrame`] quarantine.
//!
//! **v0 (legacy, read-only)** — 17-byte header (sequence u64 BE, encoded
//! length u64 BE, record type u8) + lz4 payload. v0 carries no checksum;
//! it is accepted with a documented WEAKER guarantee, hardened as far as the
//! format allows: declared lengths are budget-checked, decompression is
//! budget-capped, and per-file sequence regression is refused. This was the
//! smallest sound design: the old header has no spare bytes to extend in
//! place, so old frames stay readable as-is and integrity is added only to
//! frames written from now on.
//!
//! **Tail repair.** Only the torn-terminal-append class is auto-repaired,
//! and only in the newest (unsealed) file: a syntactically incomplete FINAL
//! frame reaching physical end-of-file (the writer emits a frame prefix
//! first, so a torn append is always a valid-frame prefix), or a tail that
//! is zero-filled from the failed frame's start to physical EOF (the
//! crash artifact of page-zero-filling filesystems). Before
//! truncating, the damaged original is copied to a forensic sidecar
//! (`torn-<file>-at-<offset>` — the name does not match the `wal-` scan
//! prefix), and the truncation fsyncs the repaired file and its directory.
//! Every other defect — bad checksum, nonterminal damage, garbage between
//! frames, oversized declared lengths, zero-length legacy frame not at EOF,
//! damage in a sealed file, a file whose first record contradicts its
//! filename — is a typed quarantine that leaves the original bytes
//! untouched.

use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    ffi::OsStr,
    fmt,
    fs::{self, File as StdFile, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock, RwLockReadGuard,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle, sleep},
    time::{Duration, Instant},
};

use diagnostics::metrics::FsyncMetrics;
use fail_point::{
    WAL_EMPTY_WAL_DIR, WAL_PARTIAL_HEADER_SEQ, WAL_PARTIAL_HEADER_SEQ_LEN, WAL_RECORD_ONLY_HEADER,
    WAL_RECORD_UNFLUSHED, fail_point,
};
use itertools::Itertools;
use logger::result::ResultExt;
use resource::constants::storage::WAL_SYNC_INTERVAL_MICROSECONDS;
use tracing::{debug, warn};

use crate::{DurabilityRecordType, DurabilitySequenceNumber, DurabilityService, DurabilityServiceError, RawRecord};

const MAX_WAL_FILE_SIZE: u64 = 16 * 1024 * 1024;

const FILE_PREFIX: &str = "wal-";

/// Prefix of the forensic sidecar written before a permitted tail repair.
/// Deliberately does NOT start with [`FILE_PREFIX`], so sidecars are never
/// picked up by the WAL file scan.
const FORENSIC_PREFIX: &str = "torn-";

/// v1 frame magic. The first byte is outside 7-bit ASCII so that no v0
/// header whose sequence number was allocated by this WAL (allocation
/// refuses at `u64::MAX`, and real sequence numbers put zeros here) can
/// alias it.
const FRAME_MAGIC: [u8; 4] = [0xF7, b'T', b'W', b'F'];
const FRAME_VERSION_1: u8 = 1;
const V1_HEADER_LEN: u64 = 26;
const V0_HEADER_LEN: u64 = 17;

/// Single strict allocation/decompression budget for one frame's DECODED
/// payload, enforced on write (typed refusal before a sequence number is
/// allocated or any byte is written) and on read (declared decoded length
/// and the actual decompressed size). A containment default, not an
/// owner-approved SLO: it exists so a corrupt or hostile length field
/// cannot make recovery allocate or inflate unbounded memory. Write-side
/// enforcement guarantees the read-side check never rejects a legitimately
/// written record.
const MAX_FRAME_PAYLOAD_LEN: u64 = 256 * 1024 * 1024;

/// Budget for a frame's ENCODED (lz4) payload: the lz4 worst-case expansion
/// of [`MAX_FRAME_PAYLOAD_LEN`] input (`n + n/255 + 16`, rounded up), so a
/// payload passing the decoded budget can never be refused for its encoding.
const MAX_FRAME_ENCODED_LEN: u64 = MAX_FRAME_PAYLOAD_LEN + MAX_FRAME_PAYLOAD_LEN / 255 + 64;

/// R-01b decoded-payload budget refusal, shared by the sequenced and
/// unsequenced write entry points: a refused write allocates no sequence
/// number and mutates nothing. (`write_record` keeps its own defence-in-depth
/// copy at the frame boundary — a distinct, deliberate second gate.)
fn check_payload_budget(len: usize) -> Result<(), WALError> {
    if len as u64 > MAX_FRAME_PAYLOAD_LEN {
        return Err(WALError::RecordTooLarge { len: len as u64, budget: MAX_FRAME_PAYLOAD_LEN });
    }
    Ok(())
}

/// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) — implemented locally so
/// the frame checksum adds no new dependency to the locked workspace.
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn crc32(chunks: &[&[u8]]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for chunk in chunks {
        for &byte in *chunk {
            crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ byte as u32) & 0xFF) as usize];
        }
    }
    !crc
}

#[derive(Debug)]
pub struct WAL {
    registered_types: HashMap<DurabilityRecordType, String>,
    next_sequence_number: AtomicU64,
    files: Arc<RwLock<Files>>,
    fsync_thread: FsyncThread,
    metrics: FsyncMetrics,
}

impl WAL {
    pub const WAL_DIR_NAME: &'static str = "wal";

    pub fn create(directory: impl AsRef<Path>, metrics: FsyncMetrics) -> Result<Self, DurabilityServiceError> {
        let directory = directory.as_ref().to_owned();
        let wal_dir = directory.join(Self::WAL_DIR_NAME);
        if wal_dir.exists() {
            Err(WALError::CreateDirectoryExists { directory: wal_dir.clone() })?
        } else {
            fs::create_dir_all(wal_dir.clone()).map_err(|err| WALError::Create { source: Arc::new(err) })?;
            fail_point!(WAL_EMPTY_WAL_DIR);
        }

        let files = Files::open(wal_dir.clone())?;

        let files = Arc::new(RwLock::new(files));
        let mut next = DurabilitySequenceNumber::MIN.next();
        for record in RecordIterator::new(files.read().unwrap(), DurabilitySequenceNumber::MIN)? {
            // R-07: a recovered sequence number with no successor is typed
            // exhaustion, never a debug-panic/release-wrap.
            next = record?.sequence_number.try_next().ok_or(WALError::SequenceExhausted)?;
        }
        let mut fsync_thread = FsyncThread::new(files.clone(), metrics.clone());
        FsyncThread::start(&mut fsync_thread.handle, fsync_thread.context.clone());
        Ok(Self {
            registered_types: HashMap::new(),
            next_sequence_number: AtomicU64::new(next.number()),
            files,
            fsync_thread,
            metrics,
        })
    }

    pub fn load(directory: impl AsRef<Path>, metrics: FsyncMetrics) -> Result<Self, DurabilityServiceError> {
        let directory = directory.as_ref().to_owned();
        let wal_dir = directory.join(Self::WAL_DIR_NAME);
        if !wal_dir.exists() {
            Err(WALError::LoadDirectoryMissing { directory: wal_dir.clone() })?
        }
        let files = Files::open(wal_dir.clone())?;

        let start_seq_nr = files.files.iter().map(|f| f.start).max().unwrap_or(DurabilitySequenceNumber::MIN);

        let files = Arc::new(RwLock::new(files));
        let mut next = DurabilitySequenceNumber::MIN.next();
        for record in RecordIterator::new(files.read().unwrap(), start_seq_nr)? {
            // R-07: typed exhaustion instead of raw `.next()` on recovered input
            next = record?.sequence_number.try_next().ok_or(WALError::SequenceExhausted)?;
        }

        let mut fsync_thread = FsyncThread::new(files.clone(), metrics.clone());
        FsyncThread::start(&mut fsync_thread.handle, fsync_thread.context.clone());
        Ok(Self {
            registered_types: HashMap::new(),
            next_sequence_number: AtomicU64::new(next.number()),
            files,
            fsync_thread,
            metrics,
        })
    }

    /// Allocate the next sequence number, refusing exhaustion (S-P0-09).
    ///
    /// `u64::MAX` is never allocated: the previous `fetch_add` handed it out
    /// AND wrapped the counter to zero in release builds, so the write after
    /// exhaustion would silently reuse the identity of the first record ever
    /// written. Allocation at the top of the space is now a typed terminal
    /// error and the counter is NOT advanced, so repeated attempts fail
    /// identically instead of corrupting the sequence space.
    fn increment(&self) -> Result<DurabilitySequenceNumber, WALError> {
        let mut current = self.next_sequence_number.load(Ordering::Relaxed);
        loop {
            if current == u64::MAX {
                return Err(WALError::SequenceExhausted);
            }
            match self.next_sequence_number.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(DurabilitySequenceNumber::from(current)),
                Err(observed) => current = observed,
            }
        }
    }

    pub fn current(&self) -> DurabilitySequenceNumber {
        DurabilitySequenceNumber::from(self.next_sequence_number.load(Ordering::Relaxed))
    }

    pub fn previous(&self) -> DurabilitySequenceNumber {
        // R-07: checked, not raw `- 1`. The counter is initialised at
        // `MIN.next()` and only ever stores allocated or recovered sequence
        // numbers >= 1, so the predecessor always exists; checked arithmetic
        // keeps a violated assumption a loud fault in every build profile
        // instead of a silent release-mode wrap to u64::MAX.
        DurabilitySequenceNumber::from(self.next_sequence_number.load(Ordering::Relaxed))
            .try_previous()
            .expect("WAL sequence counter below MIN.next(): no previous sequence number exists")
    }

    pub fn request_sync(&self, ack_waits_for_sync: bool) -> mpsc::Receiver<Result<(), DurabilityServiceError>> {
        self.fsync_thread.schedule_next_sync_may_subscribe(ack_waits_for_sync)
    }
}

impl DurabilityService for WAL {
    fn register_record_type(&mut self, durability_record_type: DurabilityRecordType, record_name: &str) {
        if self.registered_types.get(&durability_record_type).is_some_and(|name| name != record_name) {
            panic!("Illegal state: two types of WAL records registered with same type id and different names.")
        }
        self.registered_types.insert(durability_record_type, record_name.to_string());
    }

    fn sequenced_write(
        &self,
        record_type: DurabilityRecordType,
        bytes: &[u8],
    ) -> Result<DurabilitySequenceNumber, DurabilityServiceError> {
        debug_assert!(self.registered_types.contains_key(&record_type));
        // R-01b: the payload budget is refused BEFORE a sequence number is
        // allocated — a refused write mutates nothing at all
        check_payload_budget(bytes.len())?;
        let mut files = self.files.write().unwrap();
        // exhaustion is refused BEFORE any bytes are written: no record, no
        // counter movement, no partial state (S-P0-09)
        let sequence_number = self.increment()?;
        debug!("Writing unsequenced record with {sequence_number}");
        let raw_record = RawRecord { sequence_number, record_type, bytes: Cow::Borrowed(bytes) };
        files.write_record(raw_record)?;
        self.metrics.record_bytes_written(bytes.len() as u64);
        Ok(sequence_number)
    }

    fn unsequenced_write(&self, record_type: DurabilityRecordType, bytes: &[u8]) -> Result<(), DurabilityServiceError> {
        debug_assert!(self.registered_types.contains_key(&record_type));
        // R-01b: same budget refusal as the sequenced path, before any state
        check_payload_budget(bytes.len())?;
        let mut files = self.files.write().unwrap();
        let sequence_number = self.previous();
        debug!("Writing unsequenced record with {sequence_number}");
        let raw_record = RawRecord { sequence_number, record_type, bytes: Cow::Borrowed(bytes) };
        files.write_record(raw_record)?;
        self.metrics.record_bytes_written(bytes.len() as u64);
        Ok(())
    }

    fn iter_any_from(
        &self,
        sequence_number: DurabilitySequenceNumber,
    ) -> Result<impl Iterator<Item = Result<RawRecord<'static>, DurabilityServiceError>>, DurabilityServiceError> {
        RecordIterator::new(self.files.read().unwrap(), sequence_number)
    }

    fn iter_type_from(
        &self,
        sequence_number: DurabilitySequenceNumber,
        record_type: DurabilityRecordType,
    ) -> Result<impl Iterator<Item = Result<RawRecord<'static>, DurabilityServiceError>>, DurabilityServiceError> {
        Ok(self.iter_any_from(sequence_number)?.filter(move |res| {
            match res {
                Ok(raw) => raw.record_type == record_type,
                Err(_) => true, // Let the error filter through
            }
        }))
    }

    fn find_last_type(
        &self,
        record_type: DurabilityRecordType,
    ) -> Result<Option<RawRecord<'static>>, DurabilityServiceError> {
        let files = self.files.read().unwrap();
        let files_newest_first = files.iter().rev();
        for file in files_newest_first {
            let iterator = FileRecordIterator::new(file, DurabilitySequenceNumber::MIN)?;

            let mut found_record = None;
            for record_result in iterator {
                let record = record_result?;
                if record.record_type == record_type {
                    found_record = Some(record)
                }
            }

            if let Some(record) = found_record {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    fn truncate_from(&self, sequence_number: DurabilitySequenceNumber) -> Result<(), DurabilityServiceError> {
        let mut files = self.files.write().unwrap();
        let truncated = files.truncate_from(sequence_number)?;
        if truncated {
            files.sync_all()?;
            self.next_sequence_number.store(sequence_number.number(), Ordering::SeqCst);
        }
        Ok(())
    }

    fn delete_durability(self) -> Result<(), DurabilityServiceError> {
        drop(self.fsync_thread);
        let files = Arc::into_inner(self.files)
            .expect("cannot get exclusive ownership of WAL's Arc<Files>")
            .into_inner()
            .unwrap();
        files.delete()
    }

    fn reset(&mut self) -> Result<(), DurabilityServiceError> {
        self.next_sequence_number.store(DurabilitySequenceNumber::MIN.next().number(), Ordering::SeqCst);
        self.files.write().unwrap().reset()
    }
}

#[derive(Debug, Clone)]
pub enum WALError {
    Create {
        source: Arc<io::Error>,
    },
    CreateDirectoryExists {
        directory: PathBuf,
    },
    Load {
        source: Arc<io::Error>,
    },
    LoadDirectoryMissing {
        directory: PathBuf,
    },
    Compression {
        source: Arc<io::Error>,
    },
    Decompression {
        source: Arc<io::Error>,
    },
    Sync {
        source: Arc<io::Error>,
    },
    UnrecognizedWalFilename {
        path: PathBuf,
    },
    SyncAcknowledgementLost,
    /// The sync worker is alive but has not acknowledged within the bounded
    /// commit-path wait (S-P0-02): the outcome of the requested fsync is
    /// unknown, which is ambiguity, never success.
    SyncAcknowledgementTimeout {
        waited_secs: u64,
    },
    /// The u64 sequence space is exhausted (S-P0-09): allocation refuses,
    /// with the counter left unmutated, rather than wrapping to zero and
    /// re-issuing the identity of the first record ever written.
    SequenceExhausted,
    /// A frame in a WAL file is damaged in a way that is NOT the torn
    /// terminal append of the unsealed file (R-01b): bad checksum, garbage
    /// between frames, oversized declared lengths, sequence regression,
    /// nonterminal or sealed-file damage. Quarantine: the original bytes are
    /// left untouched and loading refuses.
    CorruptFrame {
        path: PathBuf,
        offset: u64,
        defect: FrameDefect,
    },
    /// A record submitted for writing exceeds the frame payload budget
    /// (R-01b): typed refusal before any bytes are written.
    RecordTooLarge {
        len: u64,
        budget: u64,
    },
    /// A WAL file's first record contradicts the sequence number declared in
    /// its filename (R-01b): the file/sequence layout is not the one the
    /// writer produced (rename, splice, or mixup). Quarantine.
    FileStartMismatch {
        path: PathBuf,
        declared: u64,
        found: u64,
    },
}

/// The precise defect found while parsing a frame (R-01b). Only
/// [`FrameDefect::is_torn_terminal_append`] classes may ever be repaired,
/// and only in the unsealed final file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameDefect {
    /// The frame header runs past the end of the file.
    TruncatedHeader { available: u64 },
    /// The declared payload runs past the end of the file.
    TruncatedPayload { declared: u64, available: u64 },
    /// The CRC-32 over header+payload does not match (v1).
    ChecksumMismatch { declared: u32, computed: u32 },
    /// A v1-magic frame with an unknown version byte.
    UnsupportedVersion { version: u8 },
    /// Declared encoded/decoded length exceeds the allocation budget.
    LengthOverBudget { declared: u64, budget: u64 },
    /// A frame's sequence number is lower than its predecessor's in the same
    /// file — the append-only grammar never produces this.
    SequenceRegression { previous: u64, found: u64 },
    /// A v0 frame declaring a zero-length payload. At physical EOF this is
    /// the legacy torn-append signature; anywhere else it is corruption.
    ZeroLengthLegacyFrame { at_eof: bool },
    /// The payload does not decompress to the declared length (v0: any lz4
    /// failure; v1: a defect the CRC could not catch is impossible, so this
    /// indicates an internal error or budget breach mid-stream).
    PayloadDecode { detail: String },
}

impl FrameDefect {
    /// True exactly for the damage classes a torn terminal append can
    /// produce: the frame is syntactically incomplete because the file ends
    /// mid-frame (or, for legacy v0, a zero-length frame terminates the
    /// file). Everything else is stable corruption and must quarantine.
    fn is_torn_terminal_append(&self) -> bool {
        match self {
            FrameDefect::TruncatedHeader { .. } | FrameDefect::TruncatedPayload { .. } => true,
            FrameDefect::ZeroLengthLegacyFrame { at_eof } => *at_eof,
            FrameDefect::ChecksumMismatch { .. }
            | FrameDefect::UnsupportedVersion { .. }
            | FrameDefect::LengthOverBudget { .. }
            | FrameDefect::SequenceRegression { .. }
            | FrameDefect::PayloadDecode { .. } => false,
        }
    }
}

impl fmt::Display for WALError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        error::todo_display_for_error!(f, self)
    }
}

impl Error for WALError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Create { source, .. } => Some(source),
            Self::CreateDirectoryExists { .. } => None,
            Self::Load { source, .. } => Some(source),
            Self::LoadDirectoryMissing { .. } => None,
            Self::Compression { source, .. } => Some(source),
            Self::Decompression { source, .. } => Some(source),
            Self::Sync { source, .. } => Some(source),
            Self::UnrecognizedWalFilename { .. } => None,
            Self::SyncAcknowledgementLost => None,
            Self::SyncAcknowledgementTimeout { .. } => None,
            Self::SequenceExhausted => None,
            Self::CorruptFrame { .. } => None,
            Self::RecordTooLarge { .. } => None,
            Self::FileStartMismatch { .. } => None,
        }
    }
}

#[derive(Debug)]
struct Files {
    directory: PathBuf,
    writer: Option<BufWriter<StdFile>>,
    files: Vec<File>,
}

impl Files {
    fn open(directory: PathBuf) -> Result<Self, DurabilityServiceError> {
        let (files, writer) = Self::init_files_writer(&directory)?;
        Ok(Self { directory, writer, files })
    }

    fn init_files_writer(directory: &Path) -> Result<(Vec<File>, Option<BufWriter<StdFile>>), DurabilityServiceError> {
        let mut files: Vec<File> = directory
            .read_dir()?
            .map_ok(|entry| entry.path())
            .filter_ok(|path| {
                path.file_name().and_then(OsStr::to_str).is_some_and(|name| name.starts_with(FILE_PREFIX))
            })
            .map(|path| File::open(path?))
            .try_collect()?;
        files.sort_unstable_by(|lhs, rhs| lhs.path.cmp(&rhs.path));

        // R-01b: the sorted+concatenated layout is not assumed, it is
        // checked — every non-empty file's first frame must carry exactly
        // the sequence number its filename declares. A renamed, spliced or
        // misplaced file is a typed quarantine before any repair decision.
        for file in &files {
            file.check_first_record_matches_name()?;
        }

        let last = files.last_mut();
        let writer = if let Some(last) = last {
            last.recover_unsealed_tail()?;
            Some(File::writer(last)?)
        } else {
            None
        };
        Ok((files, writer))
    }

    fn open_new_file_at(&mut self, start: DurabilitySequenceNumber) -> io::Result<()> {
        let file = File::open_at(self.directory.clone(), start)?;
        self.writer = Some(file.writer()?);
        self.files.push(file);
        Ok(())
    }

    fn write_record(&mut self, record: RawRecord<'_>) -> Result<(), DurabilityServiceError> {
        // defense in depth: the callers refuse over-budget payloads before
        // allocating a sequence number (R-01b)
        if record.bytes.len() as u64 > MAX_FRAME_PAYLOAD_LEN {
            return Err(
                WALError::RecordTooLarge { len: record.bytes.len() as u64, budget: MAX_FRAME_PAYLOAD_LEN }.into()
            );
        }

        let mut compressed_bytes = Vec::new();
        let mut encoder = lz4::EncoderBuilder::new()
            .build(&mut compressed_bytes)
            .map_err(|err| WALError::Compression { source: Arc::new(err) })?;
        encoder.write_all(&record.bytes).map_err(|err| WALError::Compression { source: Arc::new(err) })?;
        encoder.finish().1.map_err(|err| WALError::Compression { source: Arc::new(err) })?;
        if compressed_bytes.len() as u64 > MAX_FRAME_ENCODED_LEN {
            // unreachable when the decoded budget held (lz4 worst-case bound)
            return Err(
                WALError::RecordTooLarge { len: compressed_bytes.len() as u64, budget: MAX_FRAME_ENCODED_LEN }.into()
            );
        }

        if self.files.is_empty() || self.files.last().unwrap().len >= MAX_WAL_FILE_SIZE {
            self.open_new_file_at(record.sequence_number)?;
        }

        // v1 authenticated frame (see module header): the CRC covers the
        // whole header and the compressed payload.
        let mut header = [0u8; V1_HEADER_LEN as usize];
        header[0..4].copy_from_slice(&FRAME_MAGIC);
        header[4] = FRAME_VERSION_1;
        header[5] = record.record_type;
        header[6..14].copy_from_slice(&record.sequence_number.to_be_bytes());
        header[14..18].copy_from_slice(&(compressed_bytes.len() as u32).to_be_bytes());
        header[18..22].copy_from_slice(&(record.bytes.len() as u32).to_be_bytes());
        let crc = crc32(&[&header[0..22], &compressed_bytes]);
        header[22..26].copy_from_slice(&crc.to_be_bytes());

        let writer = self.writer.as_mut().unwrap();
        writer.write_all(&header[0..14])?; // magic, version, type, sequence
        fail_point!(WAL_PARTIAL_HEADER_SEQ);
        writer.write_all(&header[14..22])?; // encoded + decoded lengths
        fail_point!(WAL_PARTIAL_HEADER_SEQ_LEN);
        writer.write_all(&header[22..26])?; // checksum
        fail_point!(WAL_RECORD_ONLY_HEADER);

        writer.write_all(&compressed_bytes)?;
        fail_point!(WAL_RECORD_UNFLUSHED);
        writer.flush()?;

        self.files.last_mut().unwrap().len = writer.stream_position()?;
        Ok(())
    }

    pub(crate) fn sync_all(&mut self) -> Result<(), DurabilityServiceError> {
        let Some(last) = self.files.last_mut() else {
            // nothing has been written yet: no file data to sync, but the (new)
            // directory entry may still need it
            return self.sync_directory_best_effort();
        };
        last.writer()
            .map_err(|err| WALError::Sync { source: Arc::new(err) })?
            .get_mut()
            .sync_all()
            .map_err(|err| WALError::Sync { source: Arc::new(err) })?;
        self.sync_directory_best_effort()
    }

    fn sync_directory_best_effort(&mut self) -> Result<(), DurabilityServiceError> {
        #[cfg(unix)]
        {
            StdFile::open(&self.directory)
                .map_err(|err| WALError::Sync { source: Arc::new(err) })?
                .sync_all()
                .map_err(|err| WALError::Sync { source: Arc::new(err) }.into())
        }

        #[cfg(windows)]
        {
            // On Windows, FlushFileBuffers doesn't support directory handles, so it's likely
            // a noop or an error (which is ignored), but we try it for symmetry.
            // TODO: This requires additional testing and probably a separate OS-specific impl.
            if let Ok(dir) = StdFile::open(&self.directory) {
                let _ = dir.sync_all();
            }
            Ok(())
        }
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = &File> {
        self.files.iter()
    }

    fn file_index_containing(&self, sequence_number: DurabilitySequenceNumber) -> Option<usize> {
        self.files.iter().rposition(|f| f.start.number() <= sequence_number.number())
    }

    /// Truncates all records with sequence number >= the given value.
    /// Returns true if truncation was performed, false if the sequence number was not found.
    fn truncate_from(&mut self, sequence_number: DurabilitySequenceNumber) -> Result<bool, DurabilityServiceError> {
        let Some(file_index) = self.file_index_containing(sequence_number) else {
            return Ok(false);
        };

        // Call this before file deletion so we don't delete files in case of an error.
        let Some(truncate_position) = self.files[file_index].offset_of(sequence_number)? else {
            return Ok(false);
        };

        while self.files.len() > file_index + 1 {
            fs::remove_file(&self.files.pop().unwrap().path)?;
        }

        let last = &mut self.files[file_index];
        last.truncate_from_position(truncate_position)?;
        self.writer = Some(last.writer()?);
        Ok(true)
    }

    fn delete(self) -> Result<(), DurabilityServiceError> {
        drop(self.files);
        fs::remove_dir_all(&self.directory).map_err(|source| source.into())
    }

    fn reset(&mut self) -> Result<(), DurabilityServiceError> {
        fs::remove_dir_all(&self.directory)?;
        fs::create_dir(&self.directory)?;
        self.files.clear();
        let (files, writer) = Self::init_files_writer(&self.directory)?;
        self.files = files;
        self.writer = writer;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct File {
    start: DurabilitySequenceNumber,
    len: u64,
    path: PathBuf,
}

impl File {
    fn format_file_name(seq: DurabilitySequenceNumber) -> String {
        format!("{}{:025}", FILE_PREFIX, seq.number())
    }

    fn open_at(directory: PathBuf, start: DurabilitySequenceNumber) -> io::Result<Self> {
        let path = directory.join(Self::format_file_name(start));
        let len = fs::metadata(&path).map(|md| md.len()).unwrap_or(0);
        Ok(Self { start, len, path })
    }

    fn open(path: PathBuf) -> Result<Self, DurabilityServiceError> {
        let num: u64 = path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.split('-').nth(1))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| WALError::UnrecognizedWalFilename { path: path.clone() })?;
        let len = fs::metadata(&path).map(|md| md.len()).unwrap_or(0);
        Ok(Self { start: DurabilitySequenceNumber::from(num), len, path })
    }

    /// R-01b: verify that a non-empty file's first frame carries exactly the
    /// sequence number its filename declares. A torn-terminal defect is left
    /// for [`Self::recover_unsealed_tail`] (last file) or for the reader's
    /// quarantine (sealed file) — this check never repairs anything.
    fn check_first_record_matches_name(&self) -> Result<(), DurabilityServiceError> {
        if self.len == 0 {
            return Ok(());
        }
        let mut reader = FileReader::new(self.clone())?;
        match reader.peek_sequence_number() {
            Ok(Some(sequence_number)) if sequence_number == self.start => Ok(()),
            Ok(Some(sequence_number)) => Err(WALError::FileStartMismatch {
                path: self.path.clone(),
                declared: self.start.number(),
                found: sequence_number.number(),
            }
            .into()),
            Ok(None) => Ok(()),
            Err(DurabilityServiceError::WAL { source: WALError::CorruptFrame { defect, .. } })
                if defect.is_torn_terminal_append() =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// R-01b tail recovery for the newest (unsealed) file. Exactly one
    /// damage class is repaired — a torn terminal append (a syntactically
    /// incomplete final frame reaching physical EOF): the original file is
    /// first copied to a forensic sidecar, then truncated to the last
    /// authenticated prefix, and the truncation is fsynced (file + parent
    /// directory). Every other defect is a typed quarantine with the
    /// original bytes untouched.
    fn recover_unsealed_tail(&mut self) -> Result<(), DurabilityServiceError> {
        let mut reader = FileReader::new(self.clone())?;
        let mut last_good_position_end = 0;
        loop {
            match reader.read_one_record() {
                Ok(None) => return Ok(()), // clean end of file
                Ok(Some(_)) => last_good_position_end = reader.reader.stream_position()?,
                Err(error) => {
                    let is_torn_terminal_append = matches!(
                        &error,
                        DurabilityServiceError::WAL { source: WALError::CorruptFrame { defect, .. } }
                            if defect.is_torn_terminal_append()
                    ) || self.is_zero_filled_to_eof(last_good_position_end)?;
                    if !is_torn_terminal_append {
                        return Err(error); // quarantine: stable corruption, bytes untouched
                    }
                    let forensic = self.copy_to_forensic_sidecar(last_good_position_end)?;
                    warn!(
                        "Torn terminal append in WAL file {:?}: truncating to the last authenticated prefix at \
                         offset {} (original bytes preserved in {:?}). Defect: {}",
                        self.path, last_good_position_end, forensic, error,
                    );
                    self.truncate_from_position(last_good_position_end)?;
                    self.fsync_file_and_parent()?;
                    return Ok(());
                }
            }
        }
    }

    /// The second (and last) permitted torn-append signature: every byte
    /// from the failed frame's start to physical EOF is zero. Filesystems
    /// that zero-fill pages on crash produce exactly this; our writer emits
    /// a frame prefix first, so any other byte pattern at the tail is
    /// stable corruption, not a torn append.
    fn is_zero_filled_to_eof(&self, frame_start: u64) -> Result<bool, DurabilityServiceError> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut file = StdFile::open(&self.path)?;
        file.seek(SeekFrom::Start(frame_start))?;
        let mut tail = Vec::new();
        file.take(self.len - frame_start).read_to_end(&mut tail)?;
        Ok(!tail.is_empty() && tail.iter().all(|&byte| byte == 0))
    }

    fn copy_to_forensic_sidecar(&self, offset: u64) -> Result<PathBuf, DurabilityServiceError> {
        let file_name = self.path.file_name().and_then(OsStr::to_str).unwrap_or("wal-unnamed");
        let parent = self.path.parent().ok_or_else(|| DurabilityServiceError::IO {
            source: Arc::new(io::Error::other("WAL file has no parent directory")),
        })?;
        let sidecar = parent.join(format!("{FORENSIC_PREFIX}{file_name}-at-{offset}"));
        fs::copy(&self.path, &sidecar)?;
        StdFile::open(&sidecar)?.sync_all()?;
        Ok(sidecar)
    }

    fn fsync_file_and_parent(&self) -> Result<(), DurabilityServiceError> {
        OpenOptions::new().write(true).open(&self.path)?.sync_all()?;
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            StdFile::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn offset_of(&self, sequence_number: DurabilitySequenceNumber) -> Result<Option<u64>, DurabilityServiceError> {
        let mut reader = FileReader::new(self.clone())?;
        let mut current_record_offset = 0;

        while let Some(record) = reader.read_one_record()? {
            if record.sequence_number.number() == sequence_number.number() {
                return Ok(Some(current_record_offset));
            }
            // Points to the beginning of the next record
            current_record_offset = reader.reader.stream_position()?;
        }

        Ok(None)
    }

    fn truncate_from_position(&mut self, position: u64) -> Result<(), DurabilityServiceError> {
        OpenOptions::new().write(true).open(&self.path)?.set_len(position)?;
        self.len = position;
        Ok(())
    }

    fn writer(&self) -> io::Result<BufWriter<StdFile>> {
        Ok(BufWriter::new(OpenOptions::new().read(true).append(true).create(true).open(&self.path)?))
    }
}

#[derive(Debug)]
struct FileReader {
    file: File,
    reader: BufReader<StdFile>,
    /// Last sequence number successfully read or skipped in this file:
    /// frames must be non-decreasing (unsequenced records repeat their
    /// predecessor's number), so a regression is a typed quarantine (R-01b).
    last_sequence_number: Option<u64>,
}

/// One parsed frame header — v1 (authenticated) or v0 (legacy, weaker
/// guarantee). See the module header for both layouts.
#[derive(Debug)]
struct ParsedHeader {
    sequence_number: DurabilitySequenceNumber,
    record_type: DurabilityRecordType,
    encoded_len: u64,
    header_len: u64,
    /// v1 only: declared decompressed length, declared CRC, and the raw
    /// header bytes the CRC covers.
    v1: Option<(u64, u32, [u8; V1_HEADER_LEN as usize])>,
}

impl FileReader {
    fn new(file: File) -> io::Result<Self> {
        Ok(Self { reader: BufReader::new(StdFile::open(&file.path)?), file, last_sequence_number: None })
    }

    fn defect(&self, offset: u64, defect: FrameDefect) -> DurabilityServiceError {
        WALError::CorruptFrame { path: self.file.path.clone(), offset, defect }.into()
    }

    /// Bytes available for the frame's payload after its header at `offset`,
    /// or the typed `TruncatedPayload` defect when the declared encoded length
    /// runs past the end of file. The shared availability check for both the
    /// skip and the read record paths.
    fn payload_available(&self, offset: u64, header: &ParsedHeader) -> Result<u64, DurabilityServiceError> {
        let available = self.file.len - offset - header.header_len;
        if header.encoded_len > available {
            return Err(self.defect(offset, FrameDefect::TruncatedPayload { declared: header.encoded_len, available }));
        }
        Ok(available)
    }

    fn peek_sequence_number(&mut self) -> Result<Option<DurabilitySequenceNumber>, DurabilityServiceError> {
        let offset = self.reader.stream_position()?;
        if offset == self.file.len {
            return Ok(None);
        }
        let header = self.read_header(offset)?;
        self.reader.seek_relative(-(header.header_len as i64))?;
        Ok(Some(header.sequence_number))
    }

    fn skip_one_record(&mut self) -> Result<(), DurabilityServiceError> {
        let offset = self.reader.stream_position()?;
        if offset == self.file.len {
            return Ok(());
        }
        let header = self.read_header(offset)?;
        self.check_sequence_progression(offset, &header)?;
        self.payload_available(offset, &header)?;
        self.reader.seek_relative(header.encoded_len as i64)?;
        Ok(())
    }

    /// Advance the reader to the first record whose sequence number is `start`,
    /// skipping records from `from` (this file's first sequence number). Stops
    /// early at end of file or once a peeked number reaches `start`. The shared
    /// seek used by both the multi-file and single-file record iterators.
    fn seek_to(
        &mut self,
        start: DurabilitySequenceNumber,
        from: DurabilitySequenceNumber,
    ) -> Result<(), DurabilityServiceError> {
        let mut current = from;
        while current < start {
            match self.peek_sequence_number()? {
                None => break, // sequence number is past the end of this file.
                Some(sequence_number) if sequence_number == start => break,
                Some(sequence_number) => {
                    current = sequence_number;
                    self.skip_one_record()?;
                }
            }
        }
        Ok(())
    }

    fn check_sequence_progression(&mut self, offset: u64, header: &ParsedHeader) -> Result<(), DurabilityServiceError> {
        if let Some(previous) = self.last_sequence_number
            && header.sequence_number.number() < previous
        {
            return Err(self
                .defect(offset, FrameDefect::SequenceRegression { previous, found: header.sequence_number.number() }));
        }
        self.last_sequence_number = Some(header.sequence_number.number());
        Ok(())
    }

    fn read_one_record(&mut self) -> Result<Option<RawRecord<'static>>, DurabilityServiceError> {
        let offset = self.reader.stream_position()?;
        if offset == self.file.len {
            return Ok(None);
        }
        let header = self.read_header(offset)?;
        self.check_sequence_progression(offset, &header)?;
        self.payload_available(offset, &header)?;
        let mut compressed = vec![0u8; header.encoded_len as usize];
        self.reader.read_exact(&mut compressed)?;

        let decompressed = match header.v1 {
            Some((decoded_len, declared_crc, raw_header)) => {
                let computed = crc32(&[&raw_header[0..22], &compressed]);
                if computed != declared_crc {
                    return Err(self.defect(offset, FrameDefect::ChecksumMismatch { declared: declared_crc, computed }));
                }
                let mut decompressed = Vec::new();
                lz4::Decoder::new(&compressed[..])
                    .and_then(|decoder| decoder.take(decoded_len + 1).read_to_end(&mut decompressed))
                    .map_err(|error| self.defect(offset, FrameDefect::PayloadDecode { detail: error.to_string() }))?;
                if decompressed.len() as u64 != decoded_len {
                    return Err(self.defect(
                        offset,
                        FrameDefect::PayloadDecode {
                            detail: format!("declared decoded length {decoded_len}, got {}", decompressed.len()),
                        },
                    ));
                }
                decompressed
            }
            None => {
                // v0 legacy: no checksum to verify (documented weaker
                // guarantee); the decompression itself is budget-capped and
                // any lz4 failure is a typed quarantine.
                let mut decompressed = Vec::new();
                lz4::Decoder::new(&compressed[..])
                    .and_then(|decoder| decoder.take(MAX_FRAME_PAYLOAD_LEN + 1).read_to_end(&mut decompressed))
                    .map_err(|error| self.defect(offset, FrameDefect::PayloadDecode { detail: error.to_string() }))?;
                if decompressed.len() as u64 > MAX_FRAME_PAYLOAD_LEN {
                    return Err(self.defect(
                        offset,
                        FrameDefect::LengthOverBudget {
                            declared: decompressed.len() as u64,
                            budget: MAX_FRAME_PAYLOAD_LEN,
                        },
                    ));
                }
                decompressed
            }
        };

        Ok(Some(RawRecord {
            sequence_number: header.sequence_number,
            record_type: header.record_type,
            bytes: Cow::Owned(decompressed),
        }))
    }

    /// Parse one frame header at `offset`, consuming exactly
    /// `ParsedHeader::header_len` bytes. All defects are typed
    /// [`WALError::CorruptFrame`]s carrying the offset.
    fn read_header(&mut self, offset: u64) -> Result<ParsedHeader, DurabilityServiceError> {
        let available = self.file.len - offset;
        if available < FRAME_MAGIC.len() as u64 {
            return Err(self.defect(offset, FrameDefect::TruncatedHeader { available }));
        }
        let mut prefix = [0u8; 4];
        self.reader.read_exact(&mut prefix)?;

        if prefix == FRAME_MAGIC {
            if available < V1_HEADER_LEN {
                self.reader.seek_relative(-(prefix.len() as i64))?;
                return Err(self.defect(offset, FrameDefect::TruncatedHeader { available }));
            }
            let mut raw = [0u8; V1_HEADER_LEN as usize];
            raw[0..4].copy_from_slice(&prefix);
            self.reader.read_exact(&mut raw[4..])?;
            let version = raw[4];
            if version != FRAME_VERSION_1 {
                return Err(self.defect(offset, FrameDefect::UnsupportedVersion { version }));
            }
            let record_type = raw[5];
            let sequence_number = DurabilitySequenceNumber::from_be_bytes(&raw[6..14]);
            let encoded_len = u32::from_be_bytes(raw[14..18].try_into().unwrap()) as u64;
            let decoded_len = u32::from_be_bytes(raw[18..22].try_into().unwrap()) as u64;
            for (declared, budget) in [(encoded_len, MAX_FRAME_ENCODED_LEN), (decoded_len, MAX_FRAME_PAYLOAD_LEN)] {
                if declared > budget {
                    return Err(self.defect(offset, FrameDefect::LengthOverBudget { declared, budget }));
                }
            }
            let crc = u32::from_be_bytes(raw[22..26].try_into().unwrap());
            Ok(ParsedHeader {
                sequence_number,
                record_type,
                encoded_len,
                header_len: V1_HEADER_LEN,
                v1: Some((decoded_len, crc, raw)),
            })
        } else {
            if available < V0_HEADER_LEN {
                self.reader.seek_relative(-(prefix.len() as i64))?;
                return Err(self.defect(offset, FrameDefect::TruncatedHeader { available }));
            }
            let mut rest = [0u8; (V0_HEADER_LEN - 4) as usize];
            self.reader.read_exact(&mut rest)?;
            let mut sequence_bytes = [0u8; 8];
            sequence_bytes[0..4].copy_from_slice(&prefix);
            sequence_bytes[4..8].copy_from_slice(&rest[0..4]);
            let sequence_number = DurabilitySequenceNumber::from_be_bytes(&sequence_bytes);
            let encoded_len = u64::from_be_bytes(rest[4..12].try_into().unwrap());
            let record_type = rest[12];
            if encoded_len == 0 {
                let at_eof = offset + V0_HEADER_LEN == self.file.len;
                return Err(self.defect(offset, FrameDefect::ZeroLengthLegacyFrame { at_eof }));
            }
            if encoded_len > MAX_FRAME_ENCODED_LEN {
                return Err(self.defect(
                    offset,
                    FrameDefect::LengthOverBudget { declared: encoded_len, budget: MAX_FRAME_ENCODED_LEN },
                ));
            }
            Ok(ParsedHeader { sequence_number, record_type, encoded_len, header_len: V0_HEADER_LEN, v1: None })
        }
    }
}

#[derive(Debug)]
struct RecordIterator<'a> {
    files: RwLockReadGuard<'a, Files>,
    current: usize,
    reader: Option<FileReader>,
}

impl<'a> RecordIterator<'a> {
    fn new(files: RwLockReadGuard<'a, Files>, start: DurabilitySequenceNumber) -> Result<Self, DurabilityServiceError> {
        if files.files.is_empty() {
            return Ok(Self { files, current: 0, reader: None });
        }

        let (current, current_start) = files
            .iter()
            .map_while(|file| (file.start < start).then_some(file.start))
            .enumerate()
            .last()
            .unwrap_or((0, files.files[0].start));
        let mut reader = FileReader::new(files.files[current].clone())?;
        reader.seek_to(start, current_start)?;
        Ok(Self { files, current, reader: Some(reader) })
    }

    fn advance_file(&mut self) -> io::Result<Option<()>> {
        self.current += 1;
        if self.current < self.files.files.len() {
            self.reader = Some(FileReader::new(self.files.files[self.current].clone())?);
            Ok(Some(()))
        } else {
            self.reader.take();
            Ok(None)
        }
    }
}

impl Iterator for RecordIterator<'_> {
    type Item = Result<RawRecord<'static>, DurabilityServiceError>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        match reader.read_one_record().transpose() {
            Some(item) => Some(item),
            None => match self.advance_file().transpose()? {
                Ok(()) => self.next(),
                Err(error) => {
                    self.reader = None;
                    Some(Err(DurabilityServiceError::IO { source: Arc::new(error) }))
                }
            },
        }
    }
}

#[derive(Debug)]
struct FileRecordIterator<'a> {
    reader: Option<FileReader>,
    file_ref: PhantomData<&'a File>,
}

impl<'a> FileRecordIterator<'a> {
    fn new(file: &'a File, start: DurabilitySequenceNumber) -> Result<Self, DurabilityServiceError> {
        let mut reader = FileReader::new(file.clone())?;
        reader.seek_to(start, file.start)?;
        Ok(Self { reader: Some(reader), file_ref: PhantomData })
    }
}

impl Iterator for FileRecordIterator<'_> {
    type Item = Result<RawRecord<'static>, DurabilityServiceError>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        reader.read_one_record().transpose()
    }
}

/// One waiter's acknowledgement channel for a completed fsync.
type SyncAck = mpsc::Sender<Result<(), DurabilityServiceError>>;

#[derive(Debug)]
pub struct FsyncThreadContext {
    files: Arc<RwLock<Files>>,
    shutting_down: AtomicBool,
    signalling: [Mutex<Vec<Option<SyncAck>>>; 2],
    current_signal: AtomicU8,
    metrics: FsyncMetrics,
}

#[derive(Debug)]
pub struct FsyncThread {
    handle: Option<JoinHandle<()>>,
    context: Arc<FsyncThreadContext>,
}

impl FsyncThread {
    fn new(files: Arc<RwLock<Files>>, metrics: FsyncMetrics) -> Self {
        let context = FsyncThreadContext {
            files,
            shutting_down: AtomicBool::new(false),
            signalling: [Mutex::new(Vec::new()), Mutex::new(Vec::new())],
            current_signal: AtomicU8::new(0),
            metrics,
        };
        Self { handle: None, context: Arc::new(context) }
    }

    fn schedule_next_sync_may_subscribe(&self, subscribe: bool) -> mpsc::Receiver<Result<(), DurabilityServiceError>> {
        let (sender, recv) = mpsc::channel();
        let mut vec = self
            .context
            .signalling
            .get(self.context.current_signal.load(Ordering::Relaxed) as usize)
            .unwrap()
            .lock()
            .unwrap();
        if subscribe {
            vec.push(Some(sender));
        } else {
            vec.push(None);
            // the receiver is still held by this function's caller, so this cannot fail;
            // stay lenient anyway - an unsubscribed caller may drop the receiver at any time
            let _ = sender.send(Ok(()));
        }
        recv
    }

    fn start(handle: &mut Option<JoinHandle<()>>, context: Arc<FsyncThreadContext>) {
        if handle.is_none() {
            let mut context = context;
            let jh = thread::spawn(move || {
                let mut last_sync = Instant::now();
                while !context.shutting_down.load(Ordering::Relaxed) {
                    let micros_since_last_sync = (Instant::now() - last_sync).as_micros() as u64;
                    if micros_since_last_sync < WAL_SYNC_INTERVAL_MICROSECONDS {
                        sleep(Duration::from_micros(WAL_SYNC_INTERVAL_MICROSECONDS - micros_since_last_sync));
                    }
                    last_sync = Instant::now(); // Should we reset the timer before or after the sync completes?
                    Self::may_sync_and_update_state(&mut context);
                }
            });
            *handle = Some(jh);
        }
    }

    fn may_sync_and_update_state(context: &mut Arc<FsyncThreadContext>) {
        let current_signal = context.current_signal.load(Ordering::Relaxed);
        context.current_signal.store(1 - current_signal, Ordering::Relaxed);
        let vec_lock = context.signalling.get(current_signal as usize).unwrap().lock();
        let mut vec = vec_lock.unwrap();
        if !vec.is_empty() {
            let started = Instant::now();
            let sync_result = context.files.write().unwrap().sync_all();
            match &sync_result {
                Ok(()) => context.metrics.record_fsync_duration(started.elapsed()),
                Err(error) => {
                    // surface the typed error to every waiting subscriber instead of
                    // panicking the fsync thread; the thread stays alive so later
                    // syncs can succeed if the environment recovers
                    warn!("WAL fsync failed; reporting the error to all sync subscribers: {error}");
                }
            }
            while let Some(sender_opt) = vec.pop() {
                if let Some(sender) = sender_opt {
                    // a subscriber that gave up and dropped its receiver must not
                    // bring down the fsync thread
                    let _ = sender.send(sync_result.clone());
                }
            }
        }
    }
}

impl Drop for FsyncThread {
    fn drop(&mut self) {
        self.context.shutting_down.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap_or_log();
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert as assert_true;
    use diagnostics::metrics::FsyncMetrics;
    use itertools::Itertools;
    use tempdir::TempDir;

    use super::{MAX_WAL_FILE_SIZE, WAL, WALError};
    use crate::{DurabilityRecordType, DurabilitySequenceNumber, DurabilityService, DurabilityServiceError, RawRecord};
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    struct TestRecord {
        bytes: [u8; 4],
    }

    impl TestRecord {
        const RECORD_TYPE: DurabilityRecordType = 0;
        const RECORD_NAME: &'static str = "TEST";

        fn new(bytes: &[u8]) -> Self {
            Self { bytes: bytes.try_into().unwrap() }
        }

        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    struct UnsequencedTestRecord {
        bytes: [u8; 4],
    }

    impl UnsequencedTestRecord {
        const RECORD_TYPE: DurabilityRecordType = 1;
        const RECORD_NAME: &'static str = "UNSEQUENCED_TEST";

        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    fn create_wal(directory: &TempDir) -> WAL {
        let mut wal = WAL::create(directory, FsyncMetrics::disabled()).unwrap();
        wal.register_record_type(TestRecord::RECORD_TYPE, TestRecord::RECORD_NAME);
        wal.register_record_type(UnsequencedTestRecord::RECORD_TYPE, UnsequencedTestRecord::RECORD_NAME);
        wal
    }

    fn load_wal(directory: &TempDir) -> WAL {
        let mut wal = WAL::load(directory, FsyncMetrics::disabled()).unwrap();
        wal.register_record_type(TestRecord::RECORD_TYPE, TestRecord::RECORD_NAME);
        wal.register_record_type(UnsequencedTestRecord::RECORD_TYPE, UnsequencedTestRecord::RECORD_NAME);
        wal
    }

    fn read_all_records(wal: &WAL) -> impl Iterator<Item = RawRecord<'_>> {
        wal.iter_any_from(DurabilitySequenceNumber::MIN).unwrap().map(|res| res.unwrap())
    }

    fn read_all_records_tupled(wal: &WAL) -> Vec<(DurabilitySequenceNumber, DurabilityRecordType, Vec<u8>)> {
        read_all_records(wal)
            .map(|res| {
                let RawRecord { sequence_number, record_type, bytes } = res;
                (sequence_number, record_type, bytes.into_owned())
            })
            .collect_vec()
    }

    #[test]
    fn test_wal_write_read() {
        let directory = TempDir::new("wal-test").unwrap();

        let record = TestRecord { bytes: *b"test" };

        let wal = create_wal(&directory);
        wal.sequenced_write(TestRecord::RECORD_TYPE, record.bytes()).unwrap();

        let RawRecord { record_type, bytes, .. } =
            wal.iter_any_from(DurabilitySequenceNumber::MIN).unwrap().next().unwrap().unwrap();
        assert_eq!(record_type, TestRecord::RECORD_TYPE);

        let read_record = TestRecord::new(&bytes);
        assert_eq!(record, read_record);
    }

    #[test]
    fn test_wal_write_read_lots() {
        let directory = TempDir::new("wal-test").unwrap();

        let records = [TestRecord { bytes: *b"test" }; 1024];

        let wal = create_wal(&directory);
        records
            .iter()
            .try_for_each(|record| wal.sequenced_write(TestRecord::RECORD_TYPE, record.bytes()).map(|_| ()))
            .unwrap();

        let read_records = wal
            .iter_any_from(DurabilitySequenceNumber::MIN)
            .unwrap()
            .map(|res| {
                let RawRecord { record_type, bytes, .. } = res.unwrap();
                assert_eq!(record_type, TestRecord::RECORD_TYPE);
                TestRecord::new(&bytes)
            })
            .collect_vec();

        assert_eq!(records.len(), read_records.len());
        assert_eq!(records, &*read_records);
    }

    #[test]
    fn test_wal_load() {
        let directory = TempDir::new("wal-test").unwrap();

        let record = TestRecord { bytes: *b"test" };

        let wal = create_wal(&directory);
        wal.sequenced_write(TestRecord::RECORD_TYPE, record.bytes()).unwrap();
        drop(wal);

        let wal = load_wal(&directory);
        let RawRecord { record_type, bytes, .. } =
            wal.iter_any_from(DurabilitySequenceNumber::MIN).unwrap().next().unwrap().unwrap();
        assert_eq!(record_type, TestRecord::RECORD_TYPE);

        let read_record = TestRecord::new(&bytes);
        assert_eq!(record, read_record);
    }

    #[test]
    fn test_wal_open_multiple() {
        let directory = TempDir::new("wal-test").unwrap();

        let records = [TestRecord { bytes: *b"test" }, TestRecord { bytes: *b"abcd" }];

        let wal = create_wal(&directory);
        records
            .iter()
            .try_for_each(|record| wal.sequenced_write(TestRecord::RECORD_TYPE, record.bytes()).map(|_| ()))
            .unwrap();
        drop(wal);

        let wal = load_wal(&directory);
        let read_records = wal
            .iter_any_from(DurabilitySequenceNumber::MIN)
            .unwrap()
            .map(|res| {
                let RawRecord { record_type, bytes, .. } = res.unwrap();
                assert_eq!(record_type, TestRecord::RECORD_TYPE);
                TestRecord::new(&bytes)
            })
            .collect_vec();

        assert_eq!(records, &*read_records);
    }

    #[test]
    fn test_wal_iterate_from() {
        let directory = TempDir::new("wal-test").unwrap();

        let records = [TestRecord { bytes: *b"test" }, TestRecord { bytes: *b"abcd" }];

        let wal = create_wal(&directory);
        let sequence_numbers: Vec<_> = records
            .iter()
            .map(|record| wal.sequenced_write(TestRecord::RECORD_TYPE, record.bytes()))
            .try_collect()
            .unwrap();
        let iter_start = sequence_numbers[1];

        let read_records: Vec<TestRecord> = wal
            .iter_any_from(iter_start)
            .unwrap()
            .map(|res| {
                let RawRecord { record_type, bytes, .. } = res.unwrap();
                assert_eq!(record_type, TestRecord::RECORD_TYPE);
                TestRecord::new(&bytes)
            })
            .collect_vec();
        assert_eq!(&records[1..], &*read_records);

        drop(wal);

        let wal = load_wal(&directory);
        let read_records = wal
            .iter_any_from(iter_start)
            .unwrap()
            .map(|res| {
                let RawRecord { record_type, bytes, .. } = res.unwrap();
                assert_eq!(record_type, TestRecord::RECORD_TYPE);
                TestRecord::new(&bytes)
            })
            .collect_vec();
        assert_eq!(&records[1..], &*read_records);

        let wal = load_wal(&directory);
        let read_records =
            wal.iter_any_from(DurabilitySequenceNumber::MAX).unwrap().map(|res| res.unwrap()).collect_vec();
        assert_true!(read_records.is_empty());
    }

    #[test]
    fn test_wal_find_last() {
        let directory = TempDir::new("wal-test").unwrap();

        let sequenced_1 = TestRecord { bytes: *b"test" };
        let sequenced_2 = TestRecord { bytes: *b"abcd" };
        let unsequenced_1 = UnsequencedTestRecord { bytes: *b"unsq" };
        let unsequenced_2 = UnsequencedTestRecord { bytes: *b"xyzp" };

        let wal = create_wal(&directory);
        wal.sequenced_write(TestRecord::RECORD_TYPE, sequenced_1.bytes()).unwrap();
        wal.unsequenced_write(UnsequencedTestRecord::RECORD_TYPE, unsequenced_1.bytes()).unwrap();
        wal.unsequenced_write(UnsequencedTestRecord::RECORD_TYPE, unsequenced_2.bytes()).unwrap();
        wal.sequenced_write(TestRecord::RECORD_TYPE, sequenced_2.bytes()).unwrap();

        let found = wal.find_last_type(UnsequencedTestRecord::RECORD_TYPE).unwrap().unwrap();
        assert_true!(
            matches!(found, RawRecord { bytes, record_type: UnsequencedTestRecord::RECORD_TYPE, .. } if bytes == unsequenced_2.bytes())
        );

        drop(wal);

        let wal = load_wal(&directory);

        let found = wal.find_last_type(UnsequencedTestRecord::RECORD_TYPE).unwrap().unwrap();
        assert_true!(
            matches!(found, RawRecord { bytes, record_type: UnsequencedTestRecord::RECORD_TYPE, .. } if bytes == unsequenced_2.bytes())
        );
    }

    #[test]
    fn test_wal_truncate_from_middle_of_single_file_and_continue() {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);

        let records = [b"a000", b"b111", b"c222", b"d333", b"e444"];
        let seqs: Vec<_> = records
            .iter()
            .map(|record| wal.sequenced_write(TestRecord::RECORD_TYPE, record.as_ref()))
            .try_collect()
            .unwrap();

        let reads_before_cut = read_all_records_tupled(&wal);
        assert_eq!(reads_before_cut.len(), 5);

        let cut = seqs[2];
        wal.truncate_from(cut).expect("Expected to truncate everything starting from seqs[2] (including itself)");

        assert_eq!(wal.current(), seqs[2], "Expected to have the current seq equal to the cut seq");

        let reads_after_cut = read_all_records_tupled(&wal);

        assert_eq!(
            reads_after_cut,
            reads_before_cut[..2].to_vec(),
            "Expected only two records after the cut, without the truncated and following records"
        );

        assert_eq!(wal.current(), cut);
        let new_seq1 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"x555").unwrap();
        assert_eq!(new_seq1, cut, "Expected to have the next seq equal to the cut seq");

        let new_seq2 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"y666").unwrap();
        assert_eq!(new_seq2, cut.next(), "Expected to have the next next seq equal to the cut's next seq");

        let reads_after_new_writes = read_all_records_tupled(&wal);
        assert_eq!(
            reads_after_new_writes,
            vec![
                reads_before_cut[0].clone(),
                reads_before_cut[1].clone(),
                (new_seq1, TestRecord::RECORD_TYPE, b"x555".to_vec()),
                (new_seq2, TestRecord::RECORD_TYPE, b"y666".to_vec()),
            ]
        );

        // Verify the same after reload.
        drop(wal);
        let wal = load_wal(&directory);
        let reads_reloaded = read_all_records_tupled(&wal);
        assert_eq!(reads_reloaded, reads_after_new_writes);

        let new_seq3 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"z777").unwrap();
        assert_eq!(new_seq3, cut.next().next(), "Expected the final seq to be the cut's next next one");

        let reads_final = read_all_records_tupled(&wal);
        assert_eq!(
            reads_final,
            reads_after_new_writes
                .into_iter()
                .chain(std::iter::once((new_seq3, TestRecord::RECORD_TYPE, b"z777".to_vec())))
                .collect_vec()
        );
    }

    #[test]
    fn test_wal_truncate_from_across_multiple_files_deletes_newer_files() {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);

        let mut seqs = Vec::new();
        // Should be enough for 3 files
        let records_num = MAX_WAL_FILE_SIZE.div_ceil(16) as usize;
        for i in 0..records_num {
            let payload = format!("r{:04}", i);
            seqs.push(wal.sequenced_write(TestRecord::RECORD_TYPE, payload.as_bytes()).unwrap());
        }

        let cut = seqs[records_num.div_ceil(2)];
        wal.truncate_from(cut).unwrap();

        let reads_before = read_all_records(&wal).map(|record| record.sequence_number).collect_vec();
        assert!(!reads_before.is_empty());
        assert!(reads_before.iter().all(|s| s.number() < cut.number()));
        assert_eq!(wal.current(), cut);

        drop(wal);
        let wal = load_wal(&directory);
        let reads_after_reload = read_all_records(&wal).map(|record| record.sequence_number).collect_vec();
        assert_eq!(reads_before, reads_after_reload);
        assert_eq!(wal.current(), cut);
    }

    #[test]
    fn test_wal_truncate_from_beginning_clears_everything() {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);

        let s1 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"one!").unwrap();
        let _s2 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"two!").unwrap();

        wal.truncate_from(s1).unwrap();

        let read_records = read_all_records(&wal).collect_vec();
        assert!(read_records.is_empty(), "expected no records after truncate_from(first)");
        assert_eq!(wal.current(), s1);
    }

    #[test]
    fn test_wal_truncate_from_is_idempotent_for_same_cut() {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);

        let _s1 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"one!").unwrap();
        let s2 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"two!").unwrap();

        wal.truncate_from(s2).unwrap();
        wal.truncate_from(s2).unwrap();

        let read_records = read_all_records(&wal).map(|record| record.bytes.into_owned()).collect_vec();
        assert_eq!(read_records, vec![b"one!".to_vec()]);
        assert_eq!(wal.current(), s2);
    }

    #[test]
    fn truncate_from_keeps_prior_unsequenced_records_with_same_seq() {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);

        let s1 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"S111").unwrap();
        wal.unsequenced_write(UnsequencedTestRecord::RECORD_TYPE, b"UXXX").unwrap();
        wal.unsequenced_write(UnsequencedTestRecord::RECORD_TYPE, b"UYYY").unwrap();
        let s2 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"S222").unwrap();
        wal.unsequenced_write(UnsequencedTestRecord::RECORD_TYPE, b"UZZZ").unwrap();

        let reads_before_cut = read_all_records_tupled(&wal);
        assert_eq!(reads_before_cut.len(), 5, "Expected 5 records before truncation");

        wal.truncate_from(s2).expect("Expected to cut at s2 to remove S222 and UZZZ");
        assert_eq!(wal.current(), s2, "Expected current to be equal to the cut seq");

        let reads_after_cut = read_all_records_tupled(&wal);
        assert_eq!(
            reads_after_cut,
            vec![
                (s1, TestRecord::RECORD_TYPE, b"S111".to_vec()),
                (s1, UnsequencedTestRecord::RECORD_TYPE, b"UXXX".to_vec()),
                (s1, UnsequencedTestRecord::RECORD_TYPE, b"UYYY".to_vec()),
            ]
        );

        let found_last_unseq = wal.find_last_type(UnsequencedTestRecord::RECORD_TYPE).unwrap().unwrap();
        assert_eq!(found_last_unseq.bytes.into_owned(), b"UYYY");
    }

    #[test]
    fn truncate_from_beyond_end_does_not_skip_sequence_numbers() {
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);

        let _s1 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"one!").unwrap();
        let s2 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"two!").unwrap();
        let next_before = wal.current();

        // Truncate at a sequence number far beyond the WAL's end
        let beyond = DurabilitySequenceNumber::new(next_before.number() + 100);
        wal.truncate_from(beyond).unwrap();

        // The next sequence number must NOT have jumped forward
        assert_eq!(wal.current(), next_before, "truncate_from beyond end must not advance the sequence counter");

        // All existing records must still be present
        let records: Vec<_> = read_all_records(&wal).map(|r| r.bytes.into_owned()).collect();
        assert_eq!(records, vec![b"one!".to_vec(), b"two!".to_vec()]);

        // Writing after the no-op truncate must continue from the correct sequence
        let s3 = wal.sequenced_write(TestRecord::RECORD_TYPE, b"tre!").unwrap();
        assert_eq!(s3, s2.next(), "next write must follow the last existing sequence number");
    }

    #[test]
    fn record_over_the_frame_budget_is_a_typed_refusal_with_no_mutation() {
        // R-01b write-side budget: the refusal happens before compression,
        // rollover or any byte reaches the file.
        use super::MAX_FRAME_PAYLOAD_LEN;
        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);
        wal.sequenced_write(TestRecord::RECORD_TYPE, b"okay").unwrap();
        let counter_before = wal.current();
        let records_before = read_all_records_tupled(&wal);

        let oversized = vec![0u8; MAX_FRAME_PAYLOAD_LEN as usize + 1];
        let refused = wal.sequenced_write(TestRecord::RECORD_TYPE, &oversized);
        assert_true!(matches!(refused, Err(DurabilityServiceError::WAL { source: WALError::RecordTooLarge { .. } })));
        // the refusal precedes sequence allocation: no counter movement,
        // no frame written, reads unaffected
        assert_eq!(wal.current(), counter_before);
        assert_eq!(read_all_records_tupled(&wal), records_before);
    }

    #[test]
    fn sequence_exhaustion_is_a_typed_terminal_error_with_no_mutation() {
        // S-P0-09 boundary: the last representable sequence number is
        // allocatable; the one past it is a typed refusal that mutates
        // NOTHING — no record written, counter not advanced — and repeats
        // identically, instead of the previous fetch_add which handed out
        // u64::MAX and wrapped the counter to zero in release builds.
        use std::sync::atomic::Ordering;

        let directory = TempDir::new("wal-test").unwrap();
        let wal = create_wal(&directory);
        let records_before_boundary = read_all_records(&wal).count();

        wal.next_sequence_number.store(u64::MAX - 1, Ordering::SeqCst);
        let last = wal.sequenced_write(TestRecord::RECORD_TYPE, b"last").unwrap();
        assert_eq!(last, DurabilitySequenceNumber::new(u64::MAX - 1), "MAX-1 is still allocatable");

        for _ in 0..2 {
            let refused = wal.sequenced_write(TestRecord::RECORD_TYPE, b"over");
            assert!(
                matches!(refused, Err(DurabilityServiceError::WAL { source: WALError::SequenceExhausted })),
                "allocation of u64::MAX must be the typed exhaustion error"
            );
            assert_eq!(
                wal.next_sequence_number.load(Ordering::SeqCst),
                u64::MAX,
                "a refused allocation must not move the counter (no wrap, no partial state)"
            );
        }
        assert_eq!(
            read_all_records(&wal).count(),
            records_before_boundary + 1,
            "only the pre-exhaustion record may exist; a refused allocation writes nothing"
        );
    }
}

#[cfg(test)]
mod frame_integrity_tests {
    //! R-01b corruption matrix, executed over real temp WAL directories.
    //! One damage class converges (torn terminal append of the unsealed
    //! file, with a forensic copy); every other class is a typed
    //! [`WALError::CorruptFrame`] / [`WALError::FileStartMismatch`]
    //! quarantine that leaves the original bytes untouched. Legacy v0
    //! frames (no checksum) must still load, and new appends after them are
    //! v1-authenticated.

    use std::{fs, io::Write, path::PathBuf};

    use diagnostics::metrics::FsyncMetrics;
    use tempdir::TempDir;

    use super::{FILE_PREFIX, FORENSIC_PREFIX, FrameDefect, V1_HEADER_LEN, WAL, WALError};
    use crate::{DurabilitySequenceNumber, DurabilityService, DurabilityServiceError};

    const TEST_TYPE: u8 = 0;

    fn create_wal(directory: &TempDir) -> WAL {
        let mut wal = WAL::create(directory, FsyncMetrics::disabled()).unwrap();
        wal.register_record_type(TEST_TYPE, "TEST");
        wal
    }

    fn load_wal(directory: &TempDir) -> Result<WAL, DurabilityServiceError> {
        WAL::load(directory, FsyncMetrics::disabled()).map(|mut wal| {
            wal.register_record_type(TEST_TYPE, "TEST");
            wal
        })
    }

    fn read_all(wal: &WAL) -> Result<Vec<(u64, Vec<u8>)>, DurabilityServiceError> {
        wal.iter_any_from(DurabilitySequenceNumber::MIN)
            .unwrap()
            .map(|res| res.map(|r| (r.sequence_number.number(), r.bytes.into_owned())))
            .collect()
    }

    fn try_first_wal_file(directory: &TempDir) -> Option<PathBuf> {
        let wal_dir = directory.path().join(WAL::WAL_DIR_NAME);
        let mut files: Vec<_> = fs::read_dir(&wal_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with(FILE_PREFIX))
            .collect();
        files.sort();
        files.into_iter().next()
    }

    fn first_wal_file(directory: &TempDir) -> PathBuf {
        try_first_wal_file(directory).expect("no wal file")
    }

    fn forensic_sidecars(directory: &TempDir) -> Vec<PathBuf> {
        let wal_dir = directory.path().join(WAL::WAL_DIR_NAME);
        fs::read_dir(&wal_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with(FORENSIC_PREFIX))
            .collect()
    }

    fn expect_corrupt_frame(error: DurabilityServiceError) -> FrameDefect {
        match error {
            DurabilityServiceError::WAL { source: WALError::CorruptFrame { defect, .. } } => defect,
            other => panic!("expected the typed CorruptFrame quarantine, got: {other:?}"),
        }
    }

    /// A directory with three small v1 records; returns the record byte
    /// offsets [0, end_of_1, end_of_2] and the total file length.
    fn three_record_wal() -> (TempDir, Vec<u64>, u64) {
        let directory = TempDir::new("wal-corruption").unwrap();
        let wal = create_wal(&directory);
        let mut offsets = Vec::new();
        for payload in [b"one!", b"two!", b"tre!"] {
            let current_len = try_first_wal_file(&directory).map(|path| fs::metadata(path).unwrap().len()).unwrap_or(0);
            offsets.push(current_len);
            wal.sequenced_write(TEST_TYPE, payload).unwrap();
        }
        let total = fs::metadata(first_wal_file(&directory)).unwrap().len();
        drop(wal);
        (directory, offsets, total)
    }

    #[test]
    fn a_flipped_payload_bit_mid_file_is_a_checksum_quarantine_not_a_repair() {
        let (directory, offsets, _) = three_record_wal();
        let path = first_wal_file(&directory);
        let mut bytes = fs::read(&path).unwrap();
        // flip one bit inside the FIRST record's payload (nonterminal damage)
        let target = offsets[0] as usize + V1_HEADER_LEN as usize + 1;
        bytes[target] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let error = load_wal(&directory).expect_err("nonterminal payload damage must quarantine the load");
        let defect = expect_corrupt_frame(error);
        assert!(matches!(defect, FrameDefect::ChecksumMismatch { .. }), "expected ChecksumMismatch, got {defect:?}");
        assert_eq!(fs::read(&path).unwrap(), bytes, "quarantine must leave the original bytes untouched");
        assert!(forensic_sidecars(&directory).is_empty(), "quarantine must not produce a repair sidecar");
    }

    #[test]
    fn a_flipped_header_bit_mid_file_is_a_typed_quarantine() {
        let (directory, offsets, _) = three_record_wal();
        let path = first_wal_file(&directory);
        let mut bytes = fs::read(&path).unwrap();
        // flip a bit in record 2's declared decoded length (header damage)
        let target = offsets[1] as usize + 18;
        bytes[target + 3] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let error = load_wal(&directory).expect_err("header damage must quarantine the load");
        expect_corrupt_frame(error);
        assert_eq!(fs::read(&path).unwrap(), bytes, "quarantine must leave the original bytes untouched");
    }

    #[test]
    fn truncation_at_several_offsets_in_the_final_record_repairs_to_the_authenticated_prefix() {
        // several torn points inside the FINAL record: mid-magic, mid-header
        // and mid-payload — every one converges to the last authenticated
        // prefix, with the damaged original preserved in a forensic sidecar
        for delta in [1u64, 5, 13, V1_HEADER_LEN - 1, V1_HEADER_LEN + 1, V1_HEADER_LEN + 3] {
            let (directory, offsets, total) = three_record_wal();
            let path = first_wal_file(&directory);
            let cut = offsets[2] + delta;
            assert!(cut < total);
            let damaged = {
                let bytes = fs::read(&path).unwrap();
                fs::write(&path, &bytes[..cut as usize]).unwrap();
                bytes[..cut as usize].to_vec()
            };

            let wal = load_wal(&directory)
                .unwrap_or_else(|error| panic!("torn tail at +{delta} must be repaired, got: {error:?}"));
            let records = read_all(&wal).unwrap();
            assert_eq!(
                records.iter().map(|(_, bytes)| bytes.as_slice()).collect::<Vec<_>>(),
                vec![b"one!", b"two!"],
                "repair must keep exactly the authenticated prefix (cut at +{delta})"
            );
            let sidecars = forensic_sidecars(&directory);
            assert_eq!(sidecars.len(), 1, "exactly one forensic sidecar for the torn tail (cut at +{delta})");
            assert_eq!(fs::read(&sidecars[0]).unwrap(), damaged, "the sidecar must hold the damaged original bytes");

            // and the repaired WAL accepts new appends that survive reload
            wal.sequenced_write(TEST_TYPE, b"new!").unwrap();
            drop(wal);
            let wal = load_wal(&directory).unwrap();
            assert_eq!(read_all(&wal).unwrap().len(), 3);
        }
    }

    #[test]
    fn garbage_between_frames_is_a_typed_quarantine() {
        let (directory, offsets, _) = three_record_wal();
        let path = first_wal_file(&directory);
        let bytes = fs::read(&path).unwrap();
        let mut spliced = bytes[..offsets[1] as usize].to_vec();
        spliced.extend(std::iter::repeat_n(0xABu8, 32)); // garbage between record 1 and record 2
        spliced.extend_from_slice(&bytes[offsets[1] as usize..]);
        fs::write(&path, &spliced).unwrap();

        let error = load_wal(&directory).expect_err("garbage between frames must quarantine the load");
        expect_corrupt_frame(error);
        assert_eq!(fs::read(&path).unwrap(), spliced, "quarantine must leave the original bytes untouched");
        assert!(forensic_sidecars(&directory).is_empty());
    }

    #[test]
    fn a_lying_declared_length_is_a_typed_budget_refusal() {
        use super::{FRAME_MAGIC, FRAME_VERSION_1, MAX_FRAME_ENCODED_LEN, crc32};
        let (directory, _, _) = three_record_wal();
        let path = first_wal_file(&directory);
        let mut bytes = fs::read(&path).unwrap();
        // append a syntactically complete frame whose encoded length lies
        // far beyond the budget (and beyond the file), CRC self-consistent
        let mut header = [0u8; V1_HEADER_LEN as usize];
        header[0..4].copy_from_slice(&FRAME_MAGIC);
        header[4] = FRAME_VERSION_1;
        header[5] = TEST_TYPE;
        header[6..14].copy_from_slice(&4u64.to_be_bytes());
        header[14..18].copy_from_slice(&u32::MAX.to_be_bytes()); // encoded_len lie: 4 GiB
        header[18..22].copy_from_slice(&16u32.to_be_bytes());
        let crc = crc32(&[&header[0..22]]);
        header[22..26].copy_from_slice(&crc.to_be_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&[0u8; 64]); // some bytes follow, so the frame is not a bare torn header
        fs::write(&path, &bytes).unwrap();

        let error = load_wal(&directory).expect_err("an over-budget declared length must be refused");
        let defect = expect_corrupt_frame(error);
        match defect {
            FrameDefect::LengthOverBudget { declared, budget } => {
                assert_eq!(declared, u32::MAX as u64);
                assert_eq!(budget, MAX_FRAME_ENCODED_LEN);
            }
            other => panic!("expected LengthOverBudget, got {other:?}"),
        }
        assert_eq!(fs::read(&path).unwrap(), bytes, "refusal must leave the original bytes untouched");
    }

    #[test]
    fn a_damaged_sealed_file_is_a_quarantine_never_a_repair() {
        // roll to a second file with one large incompressible record, then
        // damage the SEALED first file: the tail-repair path must not touch
        // it, and reading it must quarantine
        let directory = TempDir::new("wal-corruption").unwrap();
        let wal = create_wal(&directory);
        let mut big = vec![0u8; (super::MAX_WAL_FILE_SIZE + 4096) as usize];
        let mut state = 0x9E3779B97F4A7C15u64; // deterministic incompressible filler
        for byte in big.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }
        wal.sequenced_write(TEST_TYPE, &big).unwrap();
        wal.sequenced_write(TEST_TYPE, b"in-second-file").unwrap();
        drop(wal);

        let wal_dir = directory.path().join(WAL::WAL_DIR_NAME);
        let mut files: Vec<_> = fs::read_dir(&wal_dir).unwrap().map(|e| e.unwrap().path()).collect();
        files.sort();
        assert!(files.len() >= 2, "expected the WAL to have rolled to a second file");
        let sealed = &files[0];
        let mut sealed_bytes = fs::read(sealed).unwrap();
        let mid = sealed_bytes.len() / 2;
        sealed_bytes[mid] ^= 0x40;
        fs::write(sealed, &sealed_bytes).unwrap();

        // load succeeds (only the unsealed file is scanned at open) ...
        let wal = load_wal(&directory).expect("open must not scan-repair sealed files");
        // ... but reading through the sealed file is a typed quarantine
        let error = read_all(&wal).expect_err("a damaged sealed frame must surface as a typed error");
        expect_corrupt_frame(error);
        assert_eq!(fs::read(sealed).unwrap(), sealed_bytes, "the sealed file's bytes must stay untouched");
        assert!(forensic_sidecars(&directory).is_empty(), "no repair may be attempted on a sealed file");
    }

    #[test]
    fn a_file_renamed_to_the_wrong_range_is_a_typed_quarantine() {
        let (directory, _, _) = three_record_wal();
        let path = first_wal_file(&directory);
        let renamed = path.with_file_name(format!("{}{:025}", FILE_PREFIX, 9u64));
        fs::rename(&path, &renamed).unwrap();

        let error = load_wal(&directory).expect_err("a file whose name contradicts its first record must quarantine");
        match error {
            DurabilityServiceError::WAL { source: WALError::FileStartMismatch { declared, found, .. } } => {
                assert_eq!(declared, 9);
                assert_eq!(found, 1);
            }
            other => panic!("expected the typed FileStartMismatch, got: {other:?}"),
        }
    }

    fn v0_record_bytes(sequence_number: u64, record_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::new();
        let mut encoder = lz4::EncoderBuilder::new().build(&mut compressed).unwrap();
        encoder.write_all(payload).unwrap();
        encoder.finish().1.unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&sequence_number.to_be_bytes());
        out.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
        out.push(record_type);
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn legacy_v0_frames_still_load_and_new_appends_are_authenticated_v1() {
        // hand-write a v0-format file (the pre-R-01b encoding), prove it
        // loads, then append through the WAL and prove the mixed file reads
        // back completely after another reload
        let directory = TempDir::new("wal-legacy").unwrap();
        let wal_dir = directory.path().join(WAL::WAL_DIR_NAME);
        fs::create_dir_all(&wal_dir).unwrap();
        let path = wal_dir.join(format!("{}{:025}", FILE_PREFIX, 1u64));
        let mut bytes = v0_record_bytes(1, TEST_TYPE, b"old1");
        bytes.extend(v0_record_bytes(2, TEST_TYPE, b"old2"));
        fs::write(&path, &bytes).unwrap();

        let wal = load_wal(&directory).expect("a legacy v0 file must still load");
        assert_eq!(
            read_all(&wal).unwrap(),
            vec![(1, b"old1".to_vec()), (2, b"old2".to_vec())],
            "v0 records must read back exactly"
        );
        let appended = wal.sequenced_write(TEST_TYPE, b"new3").unwrap();
        assert_eq!(appended.number(), 3);
        drop(wal);

        let wal = load_wal(&directory).unwrap();
        assert_eq!(
            read_all(&wal).unwrap(),
            vec![(1, b"old1".to_vec()), (2, b"old2".to_vec()), (3, b"new3".to_vec())],
            "mixed v0+v1 file must read back completely after reload"
        );
    }

    #[test]
    fn a_torn_v0_tail_is_repaired_but_a_nonterminal_v0_defect_quarantines() {
        // torn v0 header at physical EOF -> repaired (legacy torn signature)
        let directory = TempDir::new("wal-legacy").unwrap();
        let wal_dir = directory.path().join(WAL::WAL_DIR_NAME);
        fs::create_dir_all(&wal_dir).unwrap();
        let path = wal_dir.join(format!("{}{:025}", FILE_PREFIX, 1u64));
        let mut bytes = v0_record_bytes(1, TEST_TYPE, b"old1");
        bytes.extend_from_slice(&2u64.to_be_bytes()); // half a v0 header, then EOF
        fs::write(&path, &bytes).unwrap();
        let wal = load_wal(&directory).expect("a torn v0 tail must be repaired");
        assert_eq!(read_all(&wal).unwrap(), vec![(1, b"old1".to_vec())]);
        assert_eq!(forensic_sidecars(&directory).len(), 1);
        drop(wal);

        // zero-length v0 frame NOT at EOF -> quarantine
        let directory = TempDir::new("wal-legacy").unwrap();
        let wal_dir = directory.path().join(WAL::WAL_DIR_NAME);
        fs::create_dir_all(&wal_dir).unwrap();
        let path = wal_dir.join(format!("{}{:025}", FILE_PREFIX, 1u64));
        let mut bytes = v0_record_bytes(1, TEST_TYPE, b"old1");
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes()); // declared zero-length payload
        bytes.push(TEST_TYPE);
        bytes.extend(v0_record_bytes(2, TEST_TYPE, b"old2")); // valid data AFTER the defect
        fs::write(&path, &bytes).unwrap();
        let error = load_wal(&directory).expect_err("a nonterminal zero-length v0 frame must quarantine");
        let defect = expect_corrupt_frame(error);
        assert!(matches!(defect, FrameDefect::ZeroLengthLegacyFrame { at_eof: false }), "got {defect:?}");
        assert_eq!(fs::read(&path).unwrap(), bytes, "quarantine must leave the original bytes untouched");
    }

    #[test]
    fn a_sequence_regression_between_frames_is_a_typed_quarantine() {
        // splice a v0 frame with a LOWER sequence number after a valid one:
        // append-only allocation never produces this
        let directory = TempDir::new("wal-legacy").unwrap();
        let wal_dir = directory.path().join(WAL::WAL_DIR_NAME);
        fs::create_dir_all(&wal_dir).unwrap();
        let path = wal_dir.join(format!("{}{:025}", FILE_PREFIX, 1u64));
        let mut bytes = v0_record_bytes(1, TEST_TYPE, b"old1");
        bytes.extend(v0_record_bytes(5, TEST_TYPE, b"old5"));
        bytes.extend(v0_record_bytes(3, TEST_TYPE, b"old3")); // regression
        fs::write(&path, &bytes).unwrap();
        let error = load_wal(&directory).expect_err("a sequence regression must quarantine");
        let defect = expect_corrupt_frame(error);
        assert!(
            matches!(defect, FrameDefect::SequenceRegression { previous: 5, found: 3 }),
            "expected SequenceRegression, got {defect:?}"
        );
    }
}
