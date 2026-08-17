/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Structured storage errors: operation identity, retry class, redacted context.
//!
//! The first version of this module carried strings — `Get(String)`, `Put(String)` — which
//! preserved upstream's variant *names* while discarding everything a caller needs to act:
//! whether retrying can help, and which operation actually failed once the string had been
//! wrapped twice. Against local disk that loss is invisible because storage errors are rare
//! and fatal; against a network object store, transient unavailability is an expected event
//! and "retry or report?" is a decision the layer above must make on every error.
//!
//! Three rules govern the shape:
//!
//! - **Operation identity is data, not prose.** [`Operation`] names the failed call; it
//!   survives wrapping and matching, where a string prefix does not.
//! - **Retry class is assigned where the knowledge is.** [`RetryClass::from_slatedb`] reads
//!   SlateDB's own [`slatedb::ErrorKind`], which distinguishes `Unavailable` (retry) from
//!   `Invalid`/`Data` (don't) at the source. Callers must not re-derive this from message
//!   text.
//! - **Context is redacted by construction.** The only secrets this crate holds are R2
//!   credentials, and [`crate::R2Credentials`] redacts them in its `Debug` impl — so error
//!   context built from `Display`/`Debug` of the types in this crate cannot leak them. Do not
//!   format raw environment variables or credential fields into `context`.

/// The storage call that failed. Carried as data so callers can match on it after wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Opening the store (backend construction, cache directory, SlateDB open).
    Open,
    /// Validating or resolving configuration; also identity validation.
    Configure,
    Put,
    Get,
    /// `seek_for_prev`-shaped reverse lookup.
    GetPrev,
    /// Applying a [`crate::Batch`].
    BatchWrite,
    Iterate,
    /// Clearing one keyspace.
    Clear,
    /// The exact scan behind `stats`.
    Stats,
    /// The bounded, memoized estimate path.
    Estimate,
    Flush,
    Close,
    Checkpoint,
    CloneCheckpoint,
    ReleaseCheckpoint,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Operation::Open => "open",
            Operation::Configure => "configure",
            Operation::Put => "put",
            Operation::Get => "get",
            Operation::GetPrev => "get_prev",
            Operation::BatchWrite => "batch write",
            Operation::Iterate => "iterate",
            Operation::Clear => "clear",
            Operation::Stats => "stats scan",
            Operation::Estimate => "estimate",
            Operation::Flush => "flush",
            Operation::Close => "close",
            Operation::Checkpoint => "checkpoint",
            Operation::CloneCheckpoint => "clone checkpoint",
            Operation::ReleaseCheckpoint => "release checkpoint",
        };
        f.write_str(name)
    }
}

/// Whether retrying the same call can succeed.
///
/// Assigned from SlateDB's own error taxonomy rather than parsed out of message text, so the
/// classification cannot rot when a message is reworded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryClass {
    /// The failure is environmental — network, contention, service unavailability — and the
    /// identical call may succeed later. Callers may retry with backoff.
    Transient,
    /// Retrying the identical call cannot succeed: invalid configuration, fenced handle,
    /// corrupted data, closed database. Something must change first.
    Permanent,
    /// The source did not say. Callers should treat this as permanent for correctness
    /// decisions and transient for availability decisions, and the distinction should be
    /// pushed toward [`Self::Transient`]/[`Self::Permanent`] where the knowledge exists.
    Unknown,
}

impl RetryClass {
    /// Classify a SlateDB error by its published kind.
    pub fn from_slatedb(error: &slatedb::Error) -> Self {
        match error.kind() {
            // "The user must retry or drop the operation."
            slatedb::ErrorKind::Unavailable => RetryClass::Transient,
            // "The transaction must be retried or dropped."
            slatedb::ErrorKind::Transaction => RetryClass::Transient,
            // Closed handles, invalid requests and corrupted data do not heal on retry.
            slatedb::ErrorKind::Closed(_) | slatedb::ErrorKind::Invalid | slatedb::ErrorKind::Data => {
                RetryClass::Permanent
            }
            slatedb::ErrorKind::Internal => RetryClass::Unknown,
            // `ErrorKind` is `#[non_exhaustive]`. A kind added upstream is unknown to us until
            // we classify it deliberately; defaulting it to `Unknown` (treated as permanent for
            // correctness decisions) fails safe rather than inventing a retry class.
            _ => RetryClass::Unknown,
        }
    }
}

/// A storage failure: which operation, whether to retry, and redacted human context.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{operation} failed ({retry:?}): {context}")]
pub struct KeyspaceError {
    pub operation: Operation,
    pub retry: RetryClass,
    /// Human-readable context. Must never contain credentials; see the module docs.
    pub context: String,
}

impl KeyspaceError {
    pub fn new(operation: Operation, retry: RetryClass, context: impl Into<String>) -> Self {
        Self { operation, retry, context: context.into() }
    }

    /// A configuration rejection: permanent by definition.
    pub fn config(context: impl Into<String>) -> Self {
        Self::new(Operation::Configure, RetryClass::Permanent, context)
    }

    /// An open failure not attributable to SlateDB (filesystem, credentials, runtime).
    pub fn open(context: impl Into<String>) -> Self {
        Self::new(Operation::Open, RetryClass::Permanent, context)
    }

    /// Wrap a SlateDB error, taking the retry class from its own taxonomy.
    pub fn slatedb(operation: Operation, error: slatedb::Error) -> Self {
        Self::new(operation, RetryClass::from_slatedb(&error), error.to_string())
    }

    /// Whether a caller may retry the identical call.
    pub fn is_transient(&self) -> bool {
        self.retry == RetryClass::Transient
    }
}
