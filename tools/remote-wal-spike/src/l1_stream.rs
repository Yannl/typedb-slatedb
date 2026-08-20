//! R6-PERF-01: the streaming half of the L1 data path, plus the
//! VERIFY-BEFORE-APPLY machinery a WAL/recovery consumer needs before it is
//! allowed anywhere near the streaming route.
//!
//! The Worker has an opt-in exact-read variant selected by
//! `accept: application/octet-stream`
//! (`control-plane/src/controller/worker-entry.ts` `wantsPayloadStream` /
//! `streamedPayloadResponse`). It streams the R2 object straight into the
//! HTTP response and ERRORS the body when the trailing digest or the length
//! disagrees. The Worker documents the residual hazard plainly: the verdict
//! is only knowable after the last byte, so a consumer CAN observe a corrupt
//! prefix before the abort arrives.
//!
//! This module makes that hazard structurally unreachable on the client
//! side, rather than documenting it again:
//!
//!   - streamed bytes are only ever written into a `Spool`, which is
//!     write-only. It has no read accessor of any kind;
//!   - the ONLY way to obtain readable bytes is `Spool::commit`, which
//!     proves the full length AND the full SHA-256 first and otherwise
//!     destroys everything it wrote;
//!   - `commit` is the only constructor of `VerifiedPayload`, whose fields
//!     are private to this module. A consumer therefore cannot be handed
//!     unverified bytes: there is no value of that type which was not
//!     proven, and there is no other type carrying payload bytes out of the
//!     streaming path;
//!   - the on-disk spool is content-addressed and two-phase: bytes land in
//!     a `.partial-*` file that is `rename`d onto its `<digest>` name only
//!     after verification, so a crash mid-stream can never leave a
//!     committed-looking entry (and `SpoolDir::open` sweeps the partials).
//!     A cache entry adopted after a RESTART is re-hashed before it is
//!     handed back (`SpoolDir::adopt`) - a committed name is a claim, not a
//!     proof, once another process could have touched the file.
//!
//! The default read route is untouched and stays the buffered
//! verify-then-serve JSON shape (`L1Client::read_exact`). Streaming is a
//! separate, explicitly named method; nothing switches over implicitly.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};

use crate::hex;

// ---------------------------------------------------------------------------
// Bounds. Every one of these mirrors an enforced server-side constant; the
// client re-states them so an oversize record is REFUSED before anything is
// allocated, issued, or transferred, instead of discovered by the authority
// after the bytes are already in flight.
// ---------------------------------------------------------------------------

/// Maximum bytes in ONE data-path record. Mirrors the Worker's
/// `MAX_REQUEST_BODY_BYTES` / `MAX_PAYLOAD_OBJECT_BYTES` (8 MiB, contract
/// F9). A record above this is refused client-side, pre-issuance and
/// pre-allocation, in BOTH directions.
pub const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum records in one `/scan` page. Mirrors the Worker's
/// `Math.min(Math.max(rawLimit, 1), 1000)` clamp: the client refuses a
/// wider request instead of silently having it clamped, so a caller cannot
/// believe it asked for a page size it did not get.
pub const MAX_SCAN_PAGE_RECORDS: u32 = 1000;

/// Maximum payload bytes (pre-base64) in one `/scan` page. Mirrors
/// `SCAN_PAGE_BYTE_BUDGET`.
pub const MAX_SCAN_PAGE_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum members in one batch finalize (`MAX_BATCH_MEMBERS`).
pub const MAX_BATCH_MEMBERS: usize = 64;

/// Maximum declared payload bytes across one batch (`MAX_BATCH_BYTES`).
pub const MAX_BATCH_BYTES: u64 = 8 * 1024 * 1024;

/// Refuse an over-bound batch before it is built. This client does not yet
/// speak the batch-finalize route, but the bound is executable rather than
/// documentary so the day it does, the ceiling is already the one the
/// authority enforces (`BATCH_TOO_MANY_MEMBERS` / `BATCH_TOO_MANY_BYTES`)
/// and a caller learns it locally instead of after N payload uploads.
pub fn validate_batch(members: usize, declared_bytes: u64) -> Result<(), StreamError> {
    if members == 0 || members > MAX_BATCH_MEMBERS {
        return Err(StreamError::Oversize { declared: members as u64, limit: MAX_BATCH_MEMBERS as u64 });
    }
    if declared_bytes > MAX_BATCH_BYTES {
        return Err(StreamError::Oversize { declared: declared_bytes, limit: MAX_BATCH_BYTES });
    }
    Ok(())
}

/// Transfer chunk. The whole point of the streaming path is that this - not
/// the record size - is the resident working set.
pub const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// The media type that selects the Worker's streaming exact-read variant.
pub const PAYLOAD_STREAM_MEDIA_TYPE: &str = "application/octet-stream";

// ---------------------------------------------------------------------------
// Typed faults.
// ---------------------------------------------------------------------------

/// A proven integrity fault. Every variant means the same thing to a
/// consumer: NOTHING was applied, nothing was acknowledged, and the spool
/// that held the bytes was destroyed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityFault {
    /// full-length transfer whose SHA-256 is not the catalogued one
    /// (corrupt first, middle, or last chunk all land here - the verdict is
    /// deliberately position-independent)
    DigestMismatch { expected: String, observed: String, length: u64 },
    /// the transfer ended early or long against the declared length
    LengthMismatch { declared: u64, observed: u64 },
    /// the transfer died mid-body: the Worker's own
    /// `PAYLOAD_INTEGRITY_VIOLATION` abort of the response stream, a reset,
    /// or a server that closed early. Indistinguishable at the socket, and
    /// deliberately treated identically: short of the declared length is
    /// short, whoever caused it
    TransferAborted { declared: u64, observed: u64, detail: String },
    /// the server sent more than it declared; refused mid-transfer
    Overrun { declared: u64, observed: u64 },
    /// the response's own metadata does not agree with itself (or with the
    /// catalogue the caller asked about) - refused BEFORE reading a byte
    HeaderInconsistent(String),
    /// a two-pass upload's source changed between the digest pass and the
    /// transmit pass: the bytes on the wire are not the bytes that were
    /// fingerprinted, so the request is aborted rather than completed under
    /// a digest that no longer describes it
    SourceDrifted { expected: String, observed: String },
}

impl std::fmt::Display for IntegrityFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityFault::DigestMismatch { expected, observed, length } => {
                write!(f, "digest mismatch over {length} bytes: expected {expected}, observed {observed}")
            }
            IntegrityFault::LengthMismatch { declared, observed } => {
                write!(f, "length mismatch: declared {declared}, observed {observed}")
            }
            IntegrityFault::TransferAborted { declared, observed, detail } => {
                write!(f, "transfer aborted after {observed} of {declared} bytes: {detail}")
            }
            IntegrityFault::Overrun { declared, observed } => {
                write!(f, "overrun: declared {declared}, observed at least {observed}")
            }
            IntegrityFault::HeaderInconsistent(detail) => write!(f, "inconsistent response metadata: {detail}"),
            IntegrityFault::SourceDrifted { expected, observed } => {
                write!(f, "upload source drifted between passes: fingerprinted {expected}, transmitted {observed}")
            }
        }
    }
}

/// Everything the streaming path can refuse with. None of these can be
/// reached with bytes already applied: the consumer is only ever called
/// with a `VerifiedPayload`.
#[derive(Debug)]
pub enum StreamError {
    /// a declared or observed size exceeded a bound; refused before the
    /// bytes were allocated or (for a declared size) before they were read
    Oversize {
        declared: u64,
        limit: u64,
    },
    Integrity(IntegrityFault),
    /// the caller's progress hook asked to stop mid-transfer
    Cancelled {
        after_bytes: u64,
    },
    /// local spool I/O (or a source read) failed
    Io(String),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Oversize { declared, limit } => {
                write!(f, "record of {declared} bytes exceeds the {limit}-byte bound; refused before allocation")
            }
            StreamError::Integrity(fault) => write!(f, "{fault}"),
            StreamError::Cancelled { after_bytes } => {
                write!(f, "cancelled by the consumer after {after_bytes} streamed bytes; nothing applied")
            }
            StreamError::Io(detail) => write!(f, "spool io: {detail}"),
        }
    }
}

impl StreamError {
    fn io(error: io::Error) -> StreamError {
        StreamError::Io(error.to_string())
    }

    /// Same wrapping, for callers outside this module.
    pub fn io_public(error: io::Error) -> StreamError {
        StreamError::io(error)
    }
}

/// What a progress hook decides after each chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// stop now; the spool is destroyed and the transfer is abandoned
    Cancel,
}

// ---------------------------------------------------------------------------
// Verified payload: the ONLY readable product of the streaming path.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum VerifiedBody {
    /// bounded in-memory spool, proven before it became this value
    Memory(Vec<u8>),
    /// content-addressed cache entry, renamed into place after proof
    File(PathBuf),
}

/// Bytes whose FULL length and FULL SHA-256 have been proven against the
/// catalogue. Fields are private and the only constructors are
/// `Spool::commit` and `SpoolDir::adopt` (which re-hashes) - so a value of
/// this type cannot exist over unverified bytes, and a consumer that only
/// accepts this type cannot be fed a corrupt prefix.
#[derive(Debug)]
pub struct VerifiedPayload {
    digest: String,
    length: u64,
    body: VerifiedBody,
}

impl VerifiedPayload {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// True when these bytes live in a content-addressed cache entry rather
    /// than in memory.
    pub fn is_cached(&self) -> bool {
        matches!(self.body, VerifiedBody::File(_))
    }

    /// Streaming access to the proven bytes.
    pub fn open(&self) -> io::Result<Box<dyn Read + Send>> {
        match &self.body {
            VerifiedBody::Memory(bytes) => Ok(Box::new(io::Cursor::new(bytes.clone()))),
            VerifiedBody::File(path) => Ok(Box::new(File::open(path)?)),
        }
    }

    /// Materialise the proven bytes. Bounded by construction: nothing above
    /// `MAX_RECORD_BYTES` can ever have been committed.
    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        match &self.body {
            VerifiedBody::Memory(bytes) => Ok(bytes.clone()),
            VerifiedBody::File(path) => fs::read(path),
        }
    }

    /// Re-prove a cache entry from disk. A committed NAME is only a claim
    /// once the process that wrote it has exited; this is the proof.
    pub fn reverify(&self) -> io::Result<bool> {
        let mut reader = self.open()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; STREAM_CHUNK_BYTES];
        let mut total = 0u64;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total += read as u64;
            hasher.update(&buffer[..read]);
        }
        Ok(total == self.length && hex(&hasher.finalize().into()) == self.digest)
    }

    /// Drop the cache entry (the replay driver calls this after a record is
    /// applied so a multi-GiB logical replay keeps O(record) disk, not
    /// O(stream)).
    pub fn discard(self) -> io::Result<()> {
        match &self.body {
            VerifiedBody::Memory(_) => Ok(()),
            VerifiedBody::File(path) => match fs::remove_file(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                other => other,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Spool: write-only until proven.
// ---------------------------------------------------------------------------

/// A 0700 directory holding content-addressed spool entries. Committed
/// entries are named by their 64-hex digest; in-flight ones are
/// `.partial-*` and are swept on open, so a crash mid-stream leaves nothing
/// that could be mistaken for a verified record.
#[derive(Debug)]
pub struct SpoolDir {
    root: PathBuf,
}

static SPOOL_NONCE: AtomicU64 = AtomicU64::new(0);

impl SpoolDir {
    pub fn open(root: impl AsRef<Path>) -> io::Result<SpoolDir> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let dir = SpoolDir { root };
        dir.sweep_partials()?;
        Ok(dir)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Remove every in-flight entry. Called on open: after a crash or a
    /// restart the only thing an interrupted stream can have left behind is
    /// a partial, and a partial is never readable as a record.
    pub fn sweep_partials(&self) -> io::Result<usize> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(".partial-") {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// The digests of the COMMITTED entries (partials are not listed - they
    /// are not entries).
    pub fn committed_digests(&self) -> io::Result<Vec<String>> {
        let mut digests = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let name = entry?.file_name().to_string_lossy().to_string();
            if is_digest(&name) {
                digests.push(name);
            }
        }
        digests.sort();
        Ok(digests)
    }

    /// Adopt a cache entry across a RESTART. The file is re-hashed and the
    /// length re-measured before anything is handed back: a name is not a
    /// proof once another process could have written the file.
    pub fn adopt(&self, digest: &str, length: u64) -> io::Result<Option<VerifiedPayload>> {
        if !is_digest(digest) || length > MAX_RECORD_BYTES {
            return Ok(None);
        }
        let path = self.root.join(digest);
        if !path.exists() {
            return Ok(None);
        }
        let candidate = VerifiedPayload { digest: digest.to_string(), length, body: VerifiedBody::File(path) };
        if candidate.reverify()? {
            Ok(Some(candidate))
        } else {
            Ok(None)
        }
    }
}

fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Where a stream's bytes are held WHILE they are still unproven.
#[derive(Debug, Clone, Copy)]
pub enum SpoolPolicy<'a> {
    /// bounded in-memory spool; a record above `max_bytes` is refused
    /// before a single byte is allocated
    Memory { max_bytes: u64 },
    /// two-phase content-addressed cache entry: bytes land in a partial and
    /// are renamed onto the digest name only after proof
    Cache { dir: &'a SpoolDir, max_bytes: u64 },
}

impl SpoolPolicy<'_> {
    pub fn max_bytes(&self) -> u64 {
        let requested = match self {
            SpoolPolicy::Memory { max_bytes } => *max_bytes,
            SpoolPolicy::Cache { max_bytes, .. } => *max_bytes,
        };
        requested.min(MAX_RECORD_BYTES)
    }
}

enum SpoolBody {
    Memory(Vec<u8>),
    Cache { partial: PathBuf, target: PathBuf, file: File, root: PathBuf },
}

/// A WRITE-ONLY sink. There is deliberately no accessor: the only exit is
/// `commit`, and `commit` proves the digest and the length first.
///
/// The `Debug` impl deliberately renders NO bytes - not even a length-only
/// hexdump - so an unproven prefix cannot escape through a log line either.
pub struct Spool {
    body: Option<SpoolBody>,
    hasher: Sha256,
    written: u64,
    declared: u64,
    expected_digest: String,
}

impl Spool {
    /// Open a spool for a record whose catalogued digest and length are
    /// already known. An over-bound record is refused HERE, before any
    /// buffer is allocated and before the caller reads a byte.
    pub fn begin(policy: SpoolPolicy<'_>, expected_digest: &str, declared: u64) -> Result<Spool, StreamError> {
        let limit = policy.max_bytes();
        if declared > limit {
            return Err(StreamError::Oversize { declared, limit });
        }
        if !is_digest(expected_digest) {
            return Err(StreamError::Integrity(IntegrityFault::HeaderInconsistent(format!(
                "{expected_digest:?} is not a 64-char lowercase sha256 hex digest"
            ))));
        }
        let body = match policy {
            SpoolPolicy::Memory { .. } => SpoolBody::Memory(Vec::with_capacity(declared as usize)),
            SpoolPolicy::Cache { dir, .. } => {
                let nonce = SPOOL_NONCE.fetch_add(1, Ordering::Relaxed);
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default();
                let partial = dir.root.join(format!(".partial-{}-{nanos}-{nonce}", std::process::id()));
                let file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&partial)
                    .map_err(StreamError::io)?;
                SpoolBody::Cache { partial, target: dir.root.join(expected_digest), file, root: dir.root.clone() }
            }
        };
        Ok(Spool {
            body: Some(body),
            hasher: Sha256::new(),
            written: 0,
            declared,
            expected_digest: expected_digest.to_string(),
        })
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Absorb one chunk. A server that sends more than it declared is
    /// refused mid-transfer rather than after the fact.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), StreamError> {
        let observed = self.written + chunk.len() as u64;
        if observed > self.declared {
            return Err(StreamError::Integrity(IntegrityFault::Overrun { declared: self.declared, observed }));
        }
        match self.body.as_mut() {
            Some(SpoolBody::Memory(buffer)) => buffer.extend_from_slice(chunk),
            Some(SpoolBody::Cache { file, .. }) => file.write_all(chunk).map_err(StreamError::io)?,
            None => return Err(StreamError::Io("spool already consumed".into())),
        }
        self.hasher.update(chunk);
        self.written = observed;
        Ok(())
    }

    /// Prove the transfer and hand back the ONLY readable form of it. Any
    /// failure destroys everything written; there is no partial product.
    pub fn commit(mut self) -> Result<VerifiedPayload, StreamError> {
        if self.written != self.declared {
            return Err(StreamError::Integrity(IntegrityFault::LengthMismatch {
                declared: self.declared,
                observed: self.written,
            }));
        }
        let observed = hex(&std::mem::take(&mut self.hasher).finalize().into());
        if observed != self.expected_digest {
            return Err(StreamError::Integrity(IntegrityFault::DigestMismatch {
                expected: self.expected_digest.clone(),
                observed,
                length: self.written,
            }));
        }
        // proven; publish
        let body = match self.body.take() {
            Some(SpoolBody::Memory(buffer)) => VerifiedBody::Memory(buffer),
            Some(SpoolBody::Cache { partial, target, file, root }) => {
                file.sync_all().map_err(StreamError::io)?;
                drop(file);
                fs::rename(&partial, &target).map_err(StreamError::io)?;
                // durable publication: the rename itself must survive, or a
                // crash could resurrect the partial name after the fact
                if let Ok(dir) = File::open(&root) {
                    let _ = dir.sync_all();
                }
                VerifiedBody::File(target)
            }
            None => return Err(StreamError::Io("spool already consumed".into())),
        };
        Ok(VerifiedPayload { digest: observed, length: self.declared, body })
    }
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spool")
            .field("written", &self.written)
            .field("declared", &self.declared)
            .field("expected_digest", &self.expected_digest)
            .finish_non_exhaustive()
    }
}

impl Drop for Spool {
    /// An abandoned spool - refusal, cancellation, panic, `?` on any path -
    /// leaves nothing behind. This is why a corrupt prefix cannot survive
    /// to be applied later.
    fn drop(&mut self) {
        if let Some(SpoolBody::Cache { partial, .. }) = self.body.take() {
            let _ = fs::remove_file(partial);
        }
    }
}

// ---------------------------------------------------------------------------
// Payload sources: the upload side never takes a complete `&[u8]`.
// ---------------------------------------------------------------------------

/// A REWINDABLE byte source. Two passes are structural, not incidental: the
/// PUT_PAYLOAD capability binds the exact content digest and byte budget, so
/// the digest must be known before issuance, and the issuer will not mint a
/// token for bytes nobody has measured. Pass one measures; pass two
/// transmits under a reader that re-proves the same digest and aborts the
/// request if the source drifted.
pub trait PayloadSource {
    fn open(&self) -> io::Result<Box<dyn Read + Send>>;
    /// Advisory only; the measuring pass is authoritative.
    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// An in-memory source (the compatibility shape - still no base64).
pub struct BytesSource(pub Vec<u8>);

impl PayloadSource for BytesSource {
    fn open(&self) -> io::Result<Box<dyn Read + Send>> {
        Ok(Box::new(io::Cursor::new(self.0.clone())))
    }
    fn len_hint(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
}

/// A file source: the process never holds the record.
pub struct FileSource(pub PathBuf);

impl PayloadSource for FileSource {
    fn open(&self) -> io::Result<Box<dyn Read + Send>> {
        Ok(Box::new(File::open(&self.0)?))
    }
    fn len_hint(&self) -> Option<u64> {
        fs::metadata(&self.0).ok().map(|m| m.len())
    }
}

/// A deterministic SYNTHETIC source: `length` bytes from a seeded
/// splitmix64 stream, generated on demand. This is how a multi-GiB logical
/// stream is exercised without a multi-GiB buffer, a multi-GiB file, or a
/// real provider.
#[derive(Debug, Clone, Copy)]
pub struct SyntheticSource {
    pub length: u64,
    pub seed: u64,
}

impl PayloadSource for SyntheticSource {
    fn open(&self) -> io::Result<Box<dyn Read + Send>> {
        Ok(Box::new(SyntheticReader { remaining: self.length, state: self.seed, pending: [0; 8], pending_len: 0 }))
    }
    fn len_hint(&self) -> Option<u64> {
        Some(self.length)
    }
}

/// The generator behind `SyntheticSource`. Allocation-free.
pub struct SyntheticReader {
    remaining: u64,
    state: u64,
    pending: [u8; 8],
    pending_len: usize,
}

impl SyntheticReader {
    fn next_word(&mut self) -> u64 {
        // splitmix64
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Read for SyntheticReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(self.remaining as usize);
        let mut produced = 0;
        while produced < want {
            if self.pending_len == 0 {
                self.pending = self.next_word().to_le_bytes();
                self.pending_len = 8;
            }
            let take = self.pending_len.min(want - produced);
            let from = 8 - self.pending_len;
            buf[produced..produced + take].copy_from_slice(&self.pending[from..from + take]);
            self.pending_len -= take;
            produced += take;
        }
        self.remaining -= produced as u64;
        Ok(produced)
    }
}

/// What the measuring pass established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFingerprint {
    pub digest: String,
    pub length: u64,
}

/// Measure a source in bounded memory. An over-bound source is refused as
/// soon as the bound is CROSSED - the reader is abandoned rather than
/// drained, and nothing beyond one chunk buffer is ever allocated.
pub fn fingerprint(source: &dyn PayloadSource, limit: u64) -> Result<PayloadFingerprint, StreamError> {
    let limit = limit.min(MAX_RECORD_BYTES);
    if let Some(hint) = source.len_hint() {
        if hint > limit {
            return Err(StreamError::Oversize { declared: hint, limit });
        }
    }
    let mut reader = source.open().map_err(StreamError::io)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; STREAM_CHUNK_BYTES];
    let mut length = 0u64;
    loop {
        let read = reader.read(&mut buffer).map_err(StreamError::io)?;
        if read == 0 {
            break;
        }
        length += read as u64;
        if length > limit {
            return Err(StreamError::Oversize { declared: length, limit });
        }
        hasher.update(&buffer[..read]);
    }
    Ok(PayloadFingerprint { digest: hex(&hasher.finalize().into()), length })
}

/// The transmit pass. Re-proves the fingerprint while the bytes go out and
/// fails the READ - which aborts the HTTP request before it can be
/// completed - if the source drifted or ran short/long.
pub struct VerifyingReader {
    inner: Box<dyn Read + Send>,
    hasher: Sha256,
    sent: u64,
    expect: PayloadFingerprint,
    finished: bool,
}

impl VerifyingReader {
    pub fn new(inner: Box<dyn Read + Send>, expect: PayloadFingerprint) -> VerifyingReader {
        VerifyingReader { inner, hasher: Sha256::new(), sent: 0, expect, finished: false }
    }
}

impl Read for VerifyingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        let read = self.inner.read(buf)?;
        if read == 0 {
            self.finished = true;
            if self.sent != self.expect.length {
                return Err(io::Error::other(format!(
                    "{}",
                    IntegrityFault::LengthMismatch { declared: self.expect.length, observed: self.sent }
                )));
            }
            let observed = hex(&std::mem::take(&mut self.hasher).finalize().into());
            if observed != self.expect.digest {
                return Err(io::Error::other(format!(
                    "{}",
                    IntegrityFault::SourceDrifted { expected: self.expect.digest.clone(), observed }
                )));
            }
            return Ok(0);
        }
        self.sent += read as u64;
        if self.sent > self.expect.length {
            return Err(io::Error::other(format!(
                "{}",
                IntegrityFault::Overrun { declared: self.expect.length, observed: self.sent }
            )));
        }
        self.hasher.update(&buf[..read]);
        Ok(read)
    }
}

// ---------------------------------------------------------------------------
// Streaming ingest: bytes -> spool -> proof -> VerifiedPayload.
// ---------------------------------------------------------------------------

/// Per-transfer knobs. `progress` is the cancellation and slow-consumer
/// seam: it is called after every chunk with the running byte count and can
/// stop the transfer.
#[derive(Default)]
pub struct StreamOptions<'a> {
    /// The catalogued digest the caller BELIEVES it is reading, when it has
    /// one (from a scan page or an upload receipt). A response advertising
    /// a different digest is refused before a byte is read - the server does
    /// not get to redefine which record this is.
    pub expect_digest: Option<&'a str>,
    pub progress: Option<&'a mut dyn FnMut(u64) -> Flow>,
}

/// Pump `reader` into a spool and return the proven payload. The reader is
/// abandoned - not drained - on every refusal.
pub fn ingest(
    reader: &mut dyn Read,
    policy: SpoolPolicy<'_>,
    expected_digest: &str,
    declared: u64,
    options: &mut StreamOptions<'_>,
) -> Result<VerifiedPayload, StreamError> {
    if let Some(expected) = options.expect_digest {
        if expected != expected_digest {
            return Err(StreamError::Integrity(IntegrityFault::HeaderInconsistent(format!(
                "response advertises digest {expected_digest}, caller expected {expected}"
            ))));
        }
    }
    let mut spool = Spool::begin(policy, expected_digest, declared)?;
    let mut buffer = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            // a body the server ERRORED mid-transfer (the Worker's
            // PAYLOAD_INTEGRITY_VIOLATION abort of the response stream), a
            // reset, and an early close all surface as a read error here.
            // The spool dies with this stack frame, so the prefix it holds
            // is unreachable by construction - there is no path from here
            // to a `VerifiedPayload`.
            Err(error) => {
                return Err(StreamError::Integrity(IntegrityFault::TransferAborted {
                    declared,
                    observed: spool.written(),
                    detail: error.to_string(),
                }));
            }
        };
        if read == 0 {
            break;
        }
        spool.write(&buffer[..read])?;
        if let Some(progress) = options.progress.as_mut() {
            if progress(spool.written()) == Flow::Cancel {
                return Err(StreamError::Cancelled { after_bytes: spool.written() });
            }
        }
    }
    spool.commit()
}

// ---------------------------------------------------------------------------
// Verify-before-apply consumer contract.
// ---------------------------------------------------------------------------

/// The catalogued identity of one record, as the streaming read reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMeta {
    pub append_lsn: u64,
    pub type_sequence: u64,
    pub record_type: u8,
    pub payload_digest: String,
    pub payload_length: u64,
}

/// A WAL/recovery consumer. `apply` cannot be called with unverified bytes:
/// its payload argument is a `VerifiedPayload`, and this crate provides no
/// way to construct one that was not proven.
pub trait RecordConsumer {
    fn apply(&mut self, meta: &RecordMeta, payload: &VerifiedPayload) -> Result<(), String>;
    /// Acknowledgement is a SEPARATE act that happens strictly after a
    /// successful apply, so a consumer can never acknowledge a record it
    /// did not apply.
    fn acknowledge(&mut self, meta: &RecordMeta) -> Result<(), String>;
}

/// A recording consumer for proofs: it keeps exactly what it was asked to
/// apply and acknowledge, so a test can assert "nothing was applied".
#[derive(Debug, Default)]
pub struct RecordingConsumer {
    pub applied: Vec<(RecordMeta, Vec<u8>)>,
    pub acknowledged: Vec<u64>,
    /// when set, `apply` refuses this lsn (transactional-abort probe)
    pub refuse_lsn: Option<u64>,
}

impl RecordConsumer for RecordingConsumer {
    fn apply(&mut self, meta: &RecordMeta, payload: &VerifiedPayload) -> Result<(), String> {
        if self.refuse_lsn == Some(meta.append_lsn) {
            return Err(format!("consumer refused lsn {}", meta.append_lsn));
        }
        let bytes = payload.to_vec().map_err(|e| e.to_string())?;
        self.applied.push((meta.clone(), bytes));
        Ok(())
    }
    fn acknowledge(&mut self, meta: &RecordMeta) -> Result<(), String> {
        self.acknowledged.push(meta.append_lsn);
        Ok(())
    }
}

/// Bounds on ONE replay. Every scan/range walk this crate performs is
/// bounded on all three axes; there is no unbounded iteration.
#[derive(Debug, Clone, Copy)]
pub struct ReplayBounds {
    /// hard ceiling on records visited by one replay call
    pub max_records: u64,
    /// per-record byte ceiling (clamped to `MAX_RECORD_BYTES`)
    pub max_record_bytes: u64,
    /// records fetched before the driver re-checks the head cut
    pub page_records: u32,
}

impl Default for ReplayBounds {
    fn default() -> Self {
        ReplayBounds { max_records: 1_000_000, max_record_bytes: MAX_RECORD_BYTES, page_records: 256 }
    }
}

impl ReplayBounds {
    /// Refuse - never silently clamp - a caller-supplied page size the
    /// authority would clamp anyway: a caller must not believe it asked for
    /// a page it did not get.
    pub fn validate(&self) -> Result<(), StreamError> {
        if self.page_records == 0 || self.page_records > MAX_SCAN_PAGE_RECORDS {
            return Err(StreamError::Oversize {
                declared: u64::from(self.page_records),
                limit: u64::from(MAX_SCAN_PAGE_RECORDS),
            });
        }
        if self.max_record_bytes == 0 || self.max_record_bytes > MAX_RECORD_BYTES {
            return Err(StreamError::Oversize { declared: self.max_record_bytes, limit: MAX_RECORD_BYTES });
        }
        Ok(())
    }
}

/// What one replay actually did. Returned on success AND carried on the
/// error path, so a failed replay can be asserted against precisely.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    pub applied: u64,
    pub acknowledged: u64,
    pub bytes: u64,
    pub last_applied_lsn: Option<u64>,
    /// the record the replay was working on when it stopped, if it stopped
    /// mid-record. It was NOT applied.
    pub aborted_at_lsn: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("l1-spool-{label}-{}-{nanos}", std::process::id()))
    }

    fn digest_of(bytes: &[u8]) -> String {
        hex(&crate::sha256(bytes))
    }

    #[test]
    fn a_committed_spool_is_the_only_readable_product() {
        let payload = b"verify-before-apply".to_vec();
        let digest = digest_of(&payload);
        let mut spool = Spool::begin(SpoolPolicy::Memory { max_bytes: 1024 }, &digest, payload.len() as u64).unwrap();
        spool.write(&payload).unwrap();
        let verified = spool.commit().unwrap();
        assert_eq!(verified.digest(), digest);
        assert_eq!(verified.to_vec().unwrap(), payload);
        assert!(verified.reverify().unwrap());
    }

    #[test]
    fn a_corrupt_stream_yields_no_payload_and_no_cache_entry() {
        let dir = SpoolDir::open(tmpdir("corrupt")).unwrap();
        let payload = b"the catalogued bytes".to_vec();
        let digest = digest_of(&payload);
        let mut corrupt = payload.clone();
        corrupt[0] ^= 0xff;
        let mut spool =
            Spool::begin(SpoolPolicy::Cache { dir: &dir, max_bytes: 1024 }, &digest, payload.len() as u64).unwrap();
        spool.write(&corrupt).unwrap();
        let fault = spool.commit().unwrap_err();
        assert!(matches!(fault, StreamError::Integrity(IntegrityFault::DigestMismatch { .. })), "{fault}");
        assert!(dir.committed_digests().unwrap().is_empty(), "no entry may be published");
        assert!(fs::read_dir(dir.root()).unwrap().next().is_none(), "not even a partial survives");
    }

    #[test]
    fn a_truncated_stream_is_a_length_fault_and_publishes_nothing() {
        let dir = SpoolDir::open(tmpdir("truncated")).unwrap();
        let payload = b"0123456789".to_vec();
        let digest = digest_of(&payload);
        let mut spool = Spool::begin(SpoolPolicy::Cache { dir: &dir, max_bytes: 1024 }, &digest, 10).unwrap();
        spool.write(&payload[..4]).unwrap();
        let fault = spool.commit().unwrap_err();
        assert!(
            matches!(fault, StreamError::Integrity(IntegrityFault::LengthMismatch { declared: 10, observed: 4 })),
            "{fault}"
        );
        assert!(dir.committed_digests().unwrap().is_empty());
    }

    #[test]
    fn an_overrun_is_refused_mid_transfer() {
        let payload = b"0123456789".to_vec();
        let digest = digest_of(&payload);
        let mut spool = Spool::begin(SpoolPolicy::Memory { max_bytes: 1024 }, &digest, 10).unwrap();
        spool.write(&payload).unwrap();
        let fault = spool.write(b"extra").unwrap_err();
        assert!(matches!(fault, StreamError::Integrity(IntegrityFault::Overrun { declared: 10, .. })), "{fault}");
    }

    #[test]
    fn an_oversize_record_is_refused_before_allocation() {
        let fault = Spool::begin(SpoolPolicy::Memory { max_bytes: 1024 }, &digest_of(b""), 4096).unwrap_err();
        assert!(matches!(fault, StreamError::Oversize { declared: 4096, limit: 1024 }), "{fault}");
        // the crate-wide ceiling wins over a caller asking for more
        let fault = Spool::begin(SpoolPolicy::Memory { max_bytes: u64::MAX }, &digest_of(b""), MAX_RECORD_BYTES + 1)
            .unwrap_err();
        assert!(matches!(fault, StreamError::Oversize { limit: MAX_RECORD_BYTES, .. }), "{fault}");
    }

    #[test]
    fn abandoning_a_spool_destroys_the_partial() {
        let dir = SpoolDir::open(tmpdir("abandon")).unwrap();
        {
            let mut spool =
                Spool::begin(SpoolPolicy::Cache { dir: &dir, max_bytes: 1024 }, &digest_of(b"abc"), 3).unwrap();
            spool.write(b"ab").unwrap();
            // dropped without commit: cancellation, panic, `?`, all the same
        }
        assert!(fs::read_dir(dir.root()).unwrap().next().is_none(), "an abandoned spool leaves nothing");
    }

    #[test]
    fn open_sweeps_partials_left_by_a_crash_and_never_adopts_them() {
        let root = tmpdir("restart");
        let dir = SpoolDir::open(&root).unwrap();
        let digest = digest_of(b"payload");
        // simulate a process killed mid-stream: a partial on disk
        fs::write(root.join(format!(".partial-{}-crash", std::process::id())), b"pay").unwrap();
        assert!(dir.committed_digests().unwrap().is_empty(), "a partial is never an entry");
        let reopened = SpoolDir::open(&root).unwrap();
        assert_eq!(reopened.sweep_partials().unwrap(), 0, "open already swept it");
        assert!(fs::read_dir(&root).unwrap().next().is_none());
        assert!(reopened.adopt(&digest, 7).unwrap().is_none(), "nothing to adopt after a crash");
    }

    #[test]
    fn adoption_after_restart_rehashes_before_handing_bytes_back() {
        let root = tmpdir("adopt");
        let dir = SpoolDir::open(&root).unwrap();
        let payload = b"durable-record".to_vec();
        let digest = digest_of(&payload);
        let mut spool =
            Spool::begin(SpoolPolicy::Cache { dir: &dir, max_bytes: 1024 }, &digest, payload.len() as u64).unwrap();
        spool.write(&payload).unwrap();
        spool.commit().unwrap();

        let restarted = SpoolDir::open(&root).unwrap();
        let adopted = restarted.adopt(&digest, payload.len() as u64).unwrap().expect("entry adopted");
        assert_eq!(adopted.to_vec().unwrap(), payload);
        // a tampered cache entry is NOT adopted, name notwithstanding
        fs::write(root.join(&digest), b"tampered-------").unwrap();
        assert!(restarted.adopt(&digest, payload.len() as u64).unwrap().is_none());
    }

    #[test]
    fn fingerprint_measures_without_buffering_and_refuses_over_bound() {
        let source = SyntheticSource { length: 300_000, seed: 7 };
        let measured = fingerprint(&source, MAX_RECORD_BYTES).unwrap();
        assert_eq!(measured.length, 300_000);
        // deterministic: the same seed measures identically
        assert_eq!(fingerprint(&source, MAX_RECORD_BYTES).unwrap(), measured);
        let fault = fingerprint(&source, 1024).unwrap_err();
        assert!(matches!(fault, StreamError::Oversize { limit: 1024, .. }), "{fault}");
    }

    #[test]
    fn a_source_that_drifts_between_passes_fails_the_transmit_read() {
        let expect = PayloadFingerprint { digest: digest_of(b"original"), length: 8 };
        let mut reader = VerifyingReader::new(Box::new(io::Cursor::new(b"drifted!".to_vec())), expect);
        let mut sink = Vec::new();
        let error = io::copy(&mut reader, &mut sink).unwrap_err();
        assert!(error.to_string().contains("drifted between passes"), "{error}");
    }

    #[test]
    fn ingest_refuses_a_response_that_renames_the_record() {
        let payload = b"bytes".to_vec();
        let digest = digest_of(&payload);
        let other = digest_of(b"other");
        let mut reader = io::Cursor::new(payload.clone());
        let mut options = StreamOptions { expect_digest: Some(&other), progress: None };
        let fault =
            ingest(&mut reader, SpoolPolicy::Memory { max_bytes: 1024 }, &digest, payload.len() as u64, &mut options)
                .unwrap_err();
        assert!(matches!(fault, StreamError::Integrity(IntegrityFault::HeaderInconsistent(_))), "{fault}");
    }

    #[test]
    fn cancellation_mid_stream_publishes_nothing() {
        let dir = SpoolDir::open(tmpdir("cancel")).unwrap();
        let payload = vec![7u8; 200_000];
        let digest = digest_of(&payload);
        let mut seen = 0u64;
        let mut cancel = |written: u64| {
            seen = written;
            if written >= STREAM_CHUNK_BYTES as u64 {
                Flow::Cancel
            } else {
                Flow::Continue
            }
        };
        let mut reader = io::Cursor::new(payload.clone());
        let mut options = StreamOptions { expect_digest: None, progress: Some(&mut cancel) };
        let fault = ingest(
            &mut reader,
            SpoolPolicy::Cache { dir: &dir, max_bytes: MAX_RECORD_BYTES },
            &digest,
            payload.len() as u64,
            &mut options,
        )
        .unwrap_err();
        assert!(matches!(fault, StreamError::Cancelled { .. }), "{fault}");
        assert!(dir.committed_digests().unwrap().is_empty());
        assert!(fs::read_dir(dir.root()).unwrap().next().is_none());
    }

    #[test]
    fn batch_bounds_refuse_rather_than_clamp() {
        assert!(validate_batch(0, 0).is_err(), "an empty batch is not a batch");
        assert!(validate_batch(MAX_BATCH_MEMBERS, MAX_BATCH_BYTES).is_ok());
        assert!(validate_batch(MAX_BATCH_MEMBERS + 1, 1).is_err());
        assert!(validate_batch(1, MAX_BATCH_BYTES + 1).is_err());
    }

    #[test]
    fn replay_bounds_refuse_rather_than_clamp() {
        let over_page = ReplayBounds { page_records: MAX_SCAN_PAGE_RECORDS + 1, ..ReplayBounds::default() };
        assert!(over_page.validate().is_err());
        let no_page = ReplayBounds { page_records: 0, ..ReplayBounds::default() };
        assert!(no_page.validate().is_err());
        let over_record = ReplayBounds { max_record_bytes: MAX_RECORD_BYTES + 1, ..ReplayBounds::default() };
        assert!(over_record.validate().is_err());
        let no_record = ReplayBounds { max_record_bytes: 0, ..ReplayBounds::default() };
        assert!(no_record.validate().is_err());
        assert!(ReplayBounds::default().validate().is_ok());
    }
}
