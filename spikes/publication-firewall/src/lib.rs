//! ADR-0012 **Candidate B** spike: publication firewall over STOCK SlateDB.
//!
//! Candidate A (measured in `docs/evidence/G3/slatedb-external-epoch-spike.json`)
//! patches the pinned crate so every manifest publication carries a
//! controller-issued epoch. Candidate B keeps crates.io SlateDB untouched
//! and enforces fencing OUTSIDE it, at the only channel the engine has to
//! storage: an `ObjectStore` wrapper that refuses mutations from any handle
//! whose *credential domain* the controller has revoked. "Fresh credential
//! domain" models what a provider (R2 scoped API tokens, IAM session
//! credentials) enforces server-side in production; the spike enforces it
//! in-process so the semantics are measurable offline.
//!
//! What this spike is for: measuring, not deciding. It answers
//! - does a store-boundary firewall fence EVERY mutation path, including
//!   the `Admin`/checkpoint paths the upstream crate leaves unfenced?
//! - what does a fenced stale writer observe, and when?
//! - what does Candidate B structurally FAIL to provide? (inv. 78-80's
//!   exact externally-issued epoch VALUES for a *stock* SlateDB client -
//!   see [`TransitionPolicy`] - and first-write-wins CAS arbitration
//!   between two handles that are both still authorized.)
//!
//! ## Round-3 audit repairs (F-01, F-02, F-03)
//!
//! **F-01 - one authority guard per operation.** The previous `rename`
//! implementation nested one authority read guard inside another. Tokio's
//! `RwLock` is fair/write-preferring: a rotation writer queued between the
//! two acquisitions makes the inner read wait behind the writer while the
//! writer waits for the outer read - deadlock. The gate is restructured:
//! every operation first CLASSIFIES every path it touches, acquires exactly
//! ONE authority read guard, validates the whole transition under it (all
//! preflight reads and typed-transition checks included), performs the
//! single underlying mutation still under it, and releases. No code path in
//! this crate acquires the authority lock while an authority guard is held.
//! Lock hierarchy: the authority `RwLock` is the only async lock; the leaf
//! `std::sync::Mutex`es (log, journal, attested state, quarantine) are
//! acquired one at a time, never while holding another, and never across an
//! `.await`.
//!
//! **F-02 - authority and immutability apply to EVERY mutating path.** The
//! previous gate fenced only `manifest/` paths, so a revoked actor could
//! overwrite or delete reachable (manifest-referenced) data keys. The
//! policy is now:
//! - non-publication keys are AUTHORITATIVE DATA: create-only, or
//!   idempotent when the bytes at an existing key are identical;
//! - different bytes at an existing key are a typed refusal AND flag the
//!   key as quarantined (someone attempted to corrupt reachable state);
//! - delete of an existing authoritative data key is denied globally
//!   (pre-G13 policy), for CURRENT actors too - not only revoked ones;
//! - a revoked/stale domain may at most CREATE a brand-new data key
//!   (orphan bytes no reachable manifest names - permitted containment);
//!   every other mutation - overwrite, multipart create/complete,
//!   copy/rename, delete - is refused with a typed error;
//! - multipart uploads are journaled under an `UploadAttemptId` at
//!   initiation; `complete()` is admitted only for the exact journaled
//!   uncommitted attempt and re-checks authority and immutability at use
//!   time; `abort()` is admitted only for the exact uncommitted attempt;
//! - copy/rename validate source and destination key classes and treat the
//!   rename source as a delete (so a referenced source cannot be deleted).
//!
//! **F-03 - the gateway validates TYPED manifest transitions, not paths.**
//! Under [`TransitionPolicy::RequireAttested`], a publication must decode
//! as a versioned transition envelope carrying mutation class, role,
//! base/target manifest ids and old/new writer/compactor epochs, and the
//! whole transition is validated against the gateway's attested state
//! under the same single authority guard: PROMOTING writer-open may only
//! increase the writer epoch, ACTIVE publication preserves the attested
//! epochs, compactor-open changes only the compactor epoch, and an
//! unknown or malformed envelope/manifest version fails closed. Stock
//! SlateDB cannot author these envelopes - which is precisely the measured
//! Candidate-B limitation (inv. 78-80): the harness therefore runs stock
//! `Db` cycles under [`TransitionPolicy::LegacyUnattested`], where
//! publications are admitted on authority + immutability alone and the
//! typed gate is unreachable. A production Candidate B would require a
//! cooperating (i.e. patched) client - or Candidate A.
//!
//! ## Use-time enforcement, not check-time (S-P0-08)
//!
//! The gate is one atomic conditional operation: authority is a
//! reader/writer domain cell, every admitted mutation holds the read guard
//! ACROSS the provider call, and rotation takes the write guard - so
//! rotation linearizes strictly after every in-flight admitted mutation
//! has completed and strictly before any later one is admitted. Raw
//! multipart uploads get the same treatment: parts are staged bytes, but
//! `complete()` - the operation that makes the object visible - re-runs
//! the gate atomically instead of trusting the initiation-time check.
//!
//! NON-PRODUCTION: nothing links this crate; the production lane stays on
//! crates.io SlateDB until the ADR-0012 decision is made with both
//! candidates on the table.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::BoxStream;
use slatedb::object_store::path::Path as ObjectPath;
use slatedb::object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt as _, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions,
    UploadPart,
};

type StoreResult<T> = slatedb::object_store::Result<T>;

/// The credential-domain space is exhausted (S-P0-09): rotation at
/// `u64::MAX` is a typed terminal refusal and the current domain is NOT
/// mutated - a wrapped counter would mint domain 0, which older handles
/// could collide with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialDomainExhausted;

impl std::fmt::Display for CredentialDomainExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "credential domain space exhausted; rotation refused without mutation"
        )
    }
}

impl std::error::Error for CredentialDomainExhausted {}

/// The controller stand-in: one reader/writer cell naming the currently
/// authorized credential domain. Production would rotate provider
/// credentials; the semantics under measurement are identical, INCLUDING
/// the drain property: [`Self::rotate`] takes the write side, so it cannot
/// return until every in-flight admitted mutation (each holding the read
/// side across its provider call) has completed - and once it returns, no
/// mutation under the old domain can be admitted or complete.
#[derive(Debug)]
pub struct PublicationAuthority {
    authorized: tokio::sync::RwLock<u64>,
}

impl PublicationAuthority {
    pub fn new() -> Arc<Self> {
        Self::starting_at(1)
    }

    /// Start at an arbitrary domain - exists so the exhaustion boundary is
    /// testable without 2^64 rotations.
    pub fn starting_at(domain: u64) -> Arc<Self> {
        Arc::new(Self {
            authorized: tokio::sync::RwLock::new(domain),
        })
    }

    pub async fn current(&self) -> u64 {
        *self.authorized.read().await
    }

    /// Revoke every outstanding handle: mint the next domain.
    ///
    /// Blocks until in-flight admitted mutations drain (see the type doc).
    /// Exhaustion at `u64::MAX` is a typed refusal with NO mutation: the
    /// incumbent domain simply remains the last authority forever, which
    /// is fail-secure (nothing new can be minted, nothing old is silently
    /// re-authorized by a wrap to zero).
    pub async fn rotate(&self) -> Result<u64, CredentialDomainExhausted> {
        let mut authorized = self.authorized.write().await;
        let next = authorized.checked_add(1).ok_or(CredentialDomainExhausted)?;
        *authorized = next;
        Ok(next)
    }
}

// ---------------------------------------------------------------------
// Key classification (F-02): every key the engine can touch has a class,
// and unknown prefixes fail CLOSED into the immutable class.
// ---------------------------------------------------------------------

/// The two key classes the firewall distinguishes. Classification is a
/// pure function of the path and never takes a lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// Anything under a `manifest/` segment: the publication channel, the
    /// only writes that change what data is REACHABLE.
    Publication,
    /// Everything else the engine writes (`compacted/` SSTs, `wal/`, and
    /// any unknown prefix - fail closed): immutable once written.
    AuthoritativeData,
}

fn classify(path: &ObjectPath) -> KeyClass {
    if path.parts().any(|part| part.as_ref() == "manifest") {
        KeyClass::Publication
    } else {
        KeyClass::AuthoritativeData
    }
}

// ---------------------------------------------------------------------
// Typed refusals (F-02/F-03): every denial is a typed value, recoverable
// from the object_store error by `firewall_refusal`.
// ---------------------------------------------------------------------

/// Every refusal the firewall can issue, as a typed value. Wrapped as the
/// `source` of an `object_store` `Generic` error so stock SlateDB sees an
/// ordinary store failure while tests (and a future gateway client) can
/// recover the exact typed cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallRefusal {
    /// The handle's credential domain is not the currently authorized one.
    RevokedDomain {
        operation: &'static str,
        path: String,
        domain: u64,
        current: u64,
    },
    /// Different bytes were offered for an existing immutable key. The key
    /// is flagged as quarantined: something attempted to corrupt reachable
    /// state in place.
    ImmutableKeyOverwrite {
        operation: &'static str,
        path: String,
    },
    /// Delete of an existing authoritative data key: denied globally
    /// (pre-G13), for current actors too - an active manifest may
    /// reference the key.
    AuthoritativeDeleteDenied {
        operation: &'static str,
        path: String,
    },
    /// Delete of the manifest the gateway currently attests as active.
    ReferencedManifestDelete {
        operation: &'static str,
        path: String,
        attested_manifest_id: u64,
    },
    /// Copy/rename across key classes (data <-> publication).
    KeyClassMismatch {
        operation: &'static str,
        from: String,
        to: String,
    },
    /// `complete()` for an attempt the journal does not record as the
    /// exact uncommitted attempt for this path.
    UnjournaledMultipartCompletion { path: String, attempt: u64 },
    /// `abort()` for anything but the exact journaled uncommitted attempt.
    MultipartAbortNotPermitted { path: String, attempt: u64 },
    /// A publication under [`TransitionPolicy::RequireAttested`] whose
    /// typed manifest transition failed to decode or validate (F-03).
    ManifestTransitionRejected {
        operation: &'static str,
        path: String,
        error: TransitionError,
    },
}

impl std::fmt::Display for FirewallRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevokedDomain {
                operation,
                path,
                domain,
                current,
            } => write!(
                f,
                "mutation fenced: credential domain {domain} is revoked (current {current}); \
                 {operation} {path} refused"
            ),
            Self::ImmutableKeyOverwrite { operation, path } => write!(
                f,
                "immutable key overwrite refused and quarantined: {operation} {path} \
                 offered different bytes for an existing key"
            ),
            Self::AuthoritativeDeleteDenied { operation, path } => write!(
                f,
                "delete of completed authoritative data is denied globally (pre-G13): \
                 {operation} {path}"
            ),
            Self::ReferencedManifestDelete {
                operation,
                path,
                attested_manifest_id,
            } => write!(
                f,
                "{operation} {path} refused: manifest {attested_manifest_id} is the \
                 attested active manifest"
            ),
            Self::KeyClassMismatch {
                operation,
                from,
                to,
            } => write!(
                f,
                "{operation} refused: source {from} and destination {to} are in \
                 different key classes"
            ),
            Self::UnjournaledMultipartCompletion { path, attempt } => write!(
                f,
                "multipart completion refused: attempt {attempt} for {path} is not the \
                 journaled uncommitted attempt"
            ),
            Self::MultipartAbortNotPermitted { path, attempt } => write!(
                f,
                "multipart abort refused: attempt {attempt} for {path} is not the \
                 journaled uncommitted attempt"
            ),
            Self::ManifestTransitionRejected {
                operation,
                path,
                error,
            } => write!(
                f,
                "typed manifest transition rejected ({error:?}): {operation} {path}"
            ),
        }
    }
}

impl std::error::Error for FirewallRefusal {}

impl FirewallRefusal {
    fn into_store_error(self) -> slatedb::object_store::Error {
        slatedb::object_store::Error::Generic {
            store: "PublicationFirewall",
            source: Box::new(self),
        }
    }
}

/// Recover the typed refusal from a store error, if the error is one of
/// the firewall's.
pub fn firewall_refusal(error: &slatedb::object_store::Error) -> Option<&FirewallRefusal> {
    match error {
        slatedb::object_store::Error::Generic { store, source }
            if *store == "PublicationFirewall" =>
        {
            source.downcast_ref::<FirewallRefusal>()
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Typed manifest transitions (F-03).
// ---------------------------------------------------------------------

/// Who is publishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Writer,
    Compactor,
}

/// What kind of manifest transition is being published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationClass {
    /// PROMOTING: a writer takes over the database - may only INCREASE
    /// the writer epoch.
    WriterOpen,
    /// ACTIVE: an ordinary publication - preserves the attested epochs.
    ActivePublication,
    /// A compactor takes over compaction - changes only the compactor
    /// epoch.
    CompactorOpen,
}

/// Why a typed transition was rejected. `Decode` variants fail closed on
/// malformed input; the rest are semantic violations against the
/// gateway's attested state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    TooShort {
        len: usize,
    },
    BadMagic,
    UnsupportedVersion {
        version: u16,
    },
    UnknownRole {
        role: u8,
    },
    UnknownClass {
        class: u8,
    },
    /// The publication path is not `.../manifest/<u64>.manifest`.
    MalformedManifestName,
    /// The id encoded in the path is not the envelope's target.
    PathIdMismatch {
        path_id: u64,
        target: u64,
    },
    WrongBaseManifest {
        attested: u64,
        base: u64,
    },
    TargetNotSuccessor {
        base: u64,
        target: u64,
    },
    /// The envelope's old writer epoch is not the attested one (a stale
    /// reopen replays an epoch the gateway has moved past).
    StaleWriterEpoch {
        attested: u64,
        old: u64,
    },
    StaleCompactorEpoch {
        attested: u64,
        old: u64,
    },
    RoleClassMismatch {
        role: Role,
        class: MutationClass,
    },
    /// A writer-open that does not increase the writer epoch (covers
    /// self-reopen: new == old).
    WriterEpochNotIncreased {
        old: u64,
        new: u64,
    },
    CompactorEpochNotIncreased {
        old: u64,
        new: u64,
    },
    WriterEpochChangedByCompactor {
        old: u64,
        new: u64,
    },
    CompactorEpochChangedByWriter {
        old: u64,
        new: u64,
    },
    EpochChangedOnActivePublication,
}

/// The state the gateway attests: the currently active manifest and the
/// epochs it carries. Advanced only by a validated typed transition whose
/// provider mutation succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttestedManifest {
    pub manifest_id: u64,
    pub writer_epoch: u64,
    pub compactor_epoch: u64,
}

/// The versioned transition envelope a cooperating gateway client puts at
/// the head of every manifest object. Layout (big-endian):
/// magic `TDBM` (4) | version u16 | role u8 | class u8 | base id u64 |
/// target id u64 | old/new writer epoch u64 x2 | old/new compactor epoch
/// u64 x2; the manifest body follows. Unknown versions fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestTransition {
    pub role: Role,
    pub class: MutationClass,
    pub base_manifest_id: u64,
    pub target_manifest_id: u64,
    pub old_writer_epoch: u64,
    pub new_writer_epoch: u64,
    pub old_compactor_epoch: u64,
    pub new_compactor_epoch: u64,
}

impl ManifestTransition {
    pub const MAGIC: [u8; 4] = *b"TDBM";
    pub const VERSION: u16 = 1;
    pub const HEADER_LEN: usize = 56;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN);
        out.extend_from_slice(&Self::MAGIC);
        out.extend_from_slice(&Self::VERSION.to_be_bytes());
        out.push(match self.role {
            Role::Writer => 1,
            Role::Compactor => 2,
        });
        out.push(match self.class {
            MutationClass::WriterOpen => 1,
            MutationClass::ActivePublication => 2,
            MutationClass::CompactorOpen => 3,
        });
        for field in [
            self.base_manifest_id,
            self.target_manifest_id,
            self.old_writer_epoch,
            self.new_writer_epoch,
            self.old_compactor_epoch,
            self.new_compactor_epoch,
        ] {
            out.extend_from_slice(&field.to_be_bytes());
        }
        out
    }

    /// Decode the envelope from the head of a manifest object. Fails
    /// closed: short input, wrong magic, unknown version/role/class are
    /// all typed errors, never a permissive fallback.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransitionError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(TransitionError::TooShort { len: bytes.len() });
        }
        if bytes[0..4] != Self::MAGIC {
            return Err(TransitionError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != Self::VERSION {
            return Err(TransitionError::UnsupportedVersion { version });
        }
        let role = match bytes[6] {
            1 => Role::Writer,
            2 => Role::Compactor,
            other => return Err(TransitionError::UnknownRole { role: other }),
        };
        let class = match bytes[7] {
            1 => MutationClass::WriterOpen,
            2 => MutationClass::ActivePublication,
            3 => MutationClass::CompactorOpen,
            other => return Err(TransitionError::UnknownClass { class: other }),
        };
        let mut fields = [0u64; 6];
        for (i, field) in fields.iter_mut().enumerate() {
            let start = 8 + i * 8;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[start..start + 8]);
            *field = u64::from_be_bytes(raw);
        }
        Ok(Self {
            role,
            class,
            base_manifest_id: fields[0],
            target_manifest_id: fields[1],
            old_writer_epoch: fields[2],
            new_writer_epoch: fields[3],
            old_compactor_epoch: fields[4],
            new_compactor_epoch: fields[5],
        })
    }

    /// Validate the WHOLE transition against the attested state and the id
    /// the path names; returns the successor attested state. Pure - takes
    /// no lock; the caller holds the attested cell.
    fn validate_against(
        &self,
        attested: &AttestedManifest,
        path_id: u64,
    ) -> Result<AttestedManifest, TransitionError> {
        if self.target_manifest_id != path_id {
            return Err(TransitionError::PathIdMismatch {
                path_id,
                target: self.target_manifest_id,
            });
        }
        if self.base_manifest_id != attested.manifest_id {
            return Err(TransitionError::WrongBaseManifest {
                attested: attested.manifest_id,
                base: self.base_manifest_id,
            });
        }
        let successor = self.base_manifest_id.checked_add(1);
        if successor != Some(self.target_manifest_id) {
            return Err(TransitionError::TargetNotSuccessor {
                base: self.base_manifest_id,
                target: self.target_manifest_id,
            });
        }
        if self.old_writer_epoch != attested.writer_epoch {
            return Err(TransitionError::StaleWriterEpoch {
                attested: attested.writer_epoch,
                old: self.old_writer_epoch,
            });
        }
        if self.old_compactor_epoch != attested.compactor_epoch {
            return Err(TransitionError::StaleCompactorEpoch {
                attested: attested.compactor_epoch,
                old: self.old_compactor_epoch,
            });
        }
        match self.class {
            MutationClass::WriterOpen => {
                if self.role != Role::Writer {
                    return Err(TransitionError::RoleClassMismatch {
                        role: self.role,
                        class: self.class,
                    });
                }
                if self.new_writer_epoch <= self.old_writer_epoch {
                    return Err(TransitionError::WriterEpochNotIncreased {
                        old: self.old_writer_epoch,
                        new: self.new_writer_epoch,
                    });
                }
                if self.new_compactor_epoch != self.old_compactor_epoch {
                    return Err(TransitionError::CompactorEpochChangedByWriter {
                        old: self.old_compactor_epoch,
                        new: self.new_compactor_epoch,
                    });
                }
            }
            MutationClass::ActivePublication => {
                if self.role != Role::Writer {
                    return Err(TransitionError::RoleClassMismatch {
                        role: self.role,
                        class: self.class,
                    });
                }
                if self.new_writer_epoch != self.old_writer_epoch
                    || self.new_compactor_epoch != self.old_compactor_epoch
                {
                    return Err(TransitionError::EpochChangedOnActivePublication);
                }
            }
            MutationClass::CompactorOpen => {
                if self.role != Role::Compactor {
                    return Err(TransitionError::RoleClassMismatch {
                        role: self.role,
                        class: self.class,
                    });
                }
                if self.new_compactor_epoch <= self.old_compactor_epoch {
                    return Err(TransitionError::CompactorEpochNotIncreased {
                        old: self.old_compactor_epoch,
                        new: self.new_compactor_epoch,
                    });
                }
                if self.new_writer_epoch != self.old_writer_epoch {
                    return Err(TransitionError::WriterEpochChangedByCompactor {
                        old: self.old_writer_epoch,
                        new: self.new_writer_epoch,
                    });
                }
            }
        }
        Ok(AttestedManifest {
            manifest_id: self.target_manifest_id,
            writer_epoch: self.new_writer_epoch,
            compactor_epoch: self.new_compactor_epoch,
        })
    }
}

/// Decode the manifest id a publication path names. Strict-mode
/// publications require `.../manifest/<ascii-u64>.manifest`; anything
/// else fails closed (encoded aliases, traversal-ish names, non-numeric
/// stems, overflow).
fn manifest_path_id(path: &ObjectPath) -> Result<u64, TransitionError> {
    let parts: Vec<_> = path.parts().collect();
    let n = parts.len();
    if n < 2 || parts[n - 2].as_ref() != "manifest" {
        return Err(TransitionError::MalformedManifestName);
    }
    let file = parts[n - 1].as_ref().to_owned();
    let stem = file
        .strip_suffix(".manifest")
        .ok_or(TransitionError::MalformedManifestName)?;
    if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TransitionError::MalformedManifestName);
    }
    stem.parse::<u64>()
        .map_err(|_| TransitionError::MalformedManifestName)
}

/// How this handle's publications are validated (F-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionPolicy {
    /// Every publication must decode as a valid [`ManifestTransition`]
    /// and validate against the attested state; malformed input fails
    /// closed. This is the shape a production gateway would enforce.
    RequireAttested,
    /// Stock-SlateDB compatibility: publications are admitted on
    /// authority + immutability alone, because a stock client cannot
    /// author transition envelopes. This mode EXISTS to measure that
    /// limitation - it is not a production posture.
    LegacyUnattested,
}

// ---------------------------------------------------------------------
// Observability + shared gateway state.
// ---------------------------------------------------------------------

/// One observed mutation through the firewall - the spike's measurement
/// channel (which paths were touched, which were refused, for whom, and
/// whether a corruption attempt was quarantined).
#[derive(Debug, Clone)]
pub struct MutationAttempt {
    pub path: String,
    pub operation: &'static str,
    pub credential_domain: u64,
    pub publication: bool,
    pub allowed: bool,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadState {
    Uncommitted,
    Committed,
    Aborted,
}

/// The multipart journal (F-02): every initiation records an attempt;
/// completion and abort are admitted only against the exact recorded
/// uncommitted attempt.
#[derive(Debug, Default)]
struct UploadJournal {
    next_attempt: u64,
    entries: HashMap<u64, (String, UploadState)>,
}

/// Shared firewall state: authority, attempt log, multipart journal,
/// attested manifest state, and the quarantine set. One per gateway;
/// every handle minted from it shares the same state.
#[derive(Debug)]
pub struct FirewallControl {
    authority: Arc<PublicationAuthority>,
    log: Mutex<Vec<MutationAttempt>>,
    journal: Mutex<UploadJournal>,
    attested: Mutex<AttestedManifest>,
    quarantine: Mutex<Vec<String>>,
}

impl FirewallControl {
    pub fn new() -> Arc<Self> {
        Self::with_authority(PublicationAuthority::new())
    }

    pub fn with_authority(authority: Arc<PublicationAuthority>) -> Arc<Self> {
        Arc::new(Self {
            authority,
            log: Mutex::new(Vec::new()),
            journal: Mutex::new(UploadJournal::default()),
            attested: Mutex::new(AttestedManifest::default()),
            quarantine: Mutex::new(Vec::new()),
        })
    }

    pub fn authority(&self) -> &Arc<PublicationAuthority> {
        &self.authority
    }

    pub fn attempts(&self) -> Vec<MutationAttempt> {
        self.log.lock().unwrap().clone()
    }

    /// Keys flagged by refused overwrite attempts (F-02).
    pub fn quarantined(&self) -> Vec<String> {
        self.quarantine.lock().unwrap().clone()
    }

    /// Snapshot of the attested manifest state (F-03).
    pub fn attested(&self) -> AttestedManifest {
        *self.attested.lock().unwrap()
    }

    /// Mint a store handle bound to one credential domain and policy.
    pub fn handle(
        self: &Arc<Self>,
        inner: Arc<dyn ObjectStore>,
        credential_domain: u64,
        policy: TransitionPolicy,
    ) -> FirewalledStore {
        FirewalledStore {
            inner,
            control: Arc::clone(self),
            credential_domain,
            policy,
        }
    }

    /// Allocate the next `UploadAttemptId`. Leaf lock only; called before
    /// the authority guard is taken, never under it.
    fn allocate_attempt(&self) -> u64 {
        let mut journal = self.journal.lock().unwrap();
        journal.next_attempt += 1;
        journal.next_attempt
    }
}

// ---------------------------------------------------------------------
// The gate (F-01): classify everything, ONE authority guard, validate the
// whole transition under it, one mutation under it.
// ---------------------------------------------------------------------

/// The full description of a store operation, classified BEFORE any lock
/// is taken. Every variant names every path the operation mutates.
enum OpSpec<'a> {
    Put {
        path: &'a ObjectPath,
        bytes: &'a [u8],
    },
    Delete {
        path: &'a ObjectPath,
    },
    Copy {
        from: &'a ObjectPath,
        to: &'a ObjectPath,
    },
    Rename {
        from: &'a ObjectPath,
        to: &'a ObjectPath,
    },
    UploadInit {
        path: &'a ObjectPath,
        attempt: u64,
    },
    UploadComplete {
        path: &'a ObjectPath,
        attempt: u64,
        bytes: &'a [u8],
    },
    UploadAbort {
        path: &'a ObjectPath,
        attempt: u64,
    },
}

/// State the gate pre-committed during validation and must undo if the
/// provider mutation (or a later validation step) fails.
enum Rollback {
    Attested {
        previous: AttestedManifest,
        target: AttestedManifest,
    },
    JournalRemove {
        attempt: u64,
    },
    JournalState {
        attempt: u64,
        previous: UploadState,
    },
}

enum Refused {
    Typed {
        attempt: MutationAttempt,
        refusal: FirewallRefusal,
    },
    Store(slatedb::object_store::Error),
}

struct Validator<'v> {
    inner: &'v Arc<dyn ObjectStore>,
    control: &'v FirewallControl,
    domain: u64,
    authorized: u64,
    policy: TransitionPolicy,
    operation: &'static str,
    entries: Vec<MutationAttempt>,
    rollbacks: Vec<Rollback>,
}

impl<'v> Validator<'v> {
    fn entry(&self, path: &ObjectPath, allowed: bool, quarantined: bool) -> MutationAttempt {
        MutationAttempt {
            path: path.to_string(),
            operation: self.operation,
            credential_domain: self.domain,
            publication: classify(path) == KeyClass::Publication,
            allowed,
            quarantined,
        }
    }

    /// Refuse: undo every pre-committed effect, then hand back the typed
    /// refusal plus its log entry.
    fn refuse(
        &mut self,
        path: &ObjectPath,
        quarantined: bool,
        refusal: FirewallRefusal,
    ) -> Refused {
        apply_rollbacks(self.control, std::mem::take(&mut self.rollbacks));
        Refused::Typed {
            attempt: self.entry(path, false, quarantined),
            refusal,
        }
    }

    /// The immutable-key overwrite refusal, shared by the publication and
    /// authoritative-data write paths: record the target for quarantine (a
    /// conflicting overwrite is suspicious residue), then refuse.
    fn quarantine_overwrite(&mut self, path: &ObjectPath) -> Refused {
        self.control.quarantine.lock().unwrap().push(path.to_string());
        let refusal = FirewallRefusal::ImmutableKeyOverwrite {
            operation: self.operation,
            path: path.to_string(),
        };
        self.refuse(path, true, refusal)
    }

    /// A manifest path/transition that failed to decode or validate: refuse
    /// (not quarantined - a malformed successor never took effect) with the
    /// typed transition-rejected refusal. Shared by the write, delete and
    /// upload-init publication paths.
    fn manifest_rejected(&mut self, path: &ObjectPath, error: TransitionError) -> Refused {
        let refusal = FirewallRefusal::ManifestTransitionRejected {
            operation: self.operation,
            path: path.to_string(),
            error,
        };
        self.refuse(path, false, refusal)
    }

    /// Read the current bytes at `path` from the underlying store, `None`
    /// when absent. Runs under the (single) authority guard; touches no
    /// lock in this crate.
    async fn read_existing(&mut self, path: &ObjectPath) -> Result<Option<Vec<u8>>, Refused> {
        match self.inner.get(path).await {
            Ok(result) => match result.bytes().await {
                Ok(bytes) => Ok(Some(bytes.to_vec())),
                Err(e) => Err(Refused::Store(e)),
            },
            Err(slatedb::object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(Refused::Store(e)),
        }
    }

    async fn validate(&mut self, op: &OpSpec<'_>) -> Result<(), Refused> {
        match op {
            OpSpec::Put { path, bytes } => self.write(path, bytes).await,
            OpSpec::Delete { path } => self.remove(path).await,
            OpSpec::Copy { from, to } => self.copy_like(from, to, false).await,
            OpSpec::Rename { from, to } => self.copy_like(from, to, true).await,
            OpSpec::UploadInit { path, attempt } => self.upload_init(path, *attempt),
            OpSpec::UploadComplete {
                path,
                attempt,
                bytes,
            } => self.upload_complete(path, *attempt, bytes).await,
            OpSpec::UploadAbort { path, attempt } => self.upload_abort(path, *attempt),
        }
    }

    fn revoked(&mut self, path: &ObjectPath) -> Refused {
        let refusal = FirewallRefusal::RevokedDomain {
            operation: self.operation,
            path: path.to_string(),
            domain: self.domain,
            current: self.authorized,
        };
        self.refuse(path, false, refusal)
    }

    /// An object lands (or is replaced) at `path` with exactly `bytes`.
    async fn write(&mut self, path: &ObjectPath, bytes: &[u8]) -> Result<(), Refused> {
        match classify(path) {
            KeyClass::Publication => {
                if self.domain != self.authorized {
                    return Err(self.revoked(path));
                }
                if let Some(existing) = self.read_existing(path).await? {
                    // manifests are immutable too: republishing identical
                    // bytes is idempotent, anything else is quarantined.
                    if existing == bytes {
                        self.entries.push(self.entry(path, true, false));
                        return Ok(());
                    }
                    return Err(self.quarantine_overwrite(path));
                }
                if self.policy == TransitionPolicy::RequireAttested {
                    let outcome = manifest_path_id(path).and_then(|path_id| {
                        ManifestTransition::decode(bytes).and_then(|transition| {
                            // check-and-advance atomically under the leaf
                            // cell: a concurrent admitted writer targeting
                            // the same successor loses the base check.
                            let mut attested = self.control.attested.lock().unwrap();
                            let next = transition.validate_against(&attested, path_id)?;
                            let previous = *attested;
                            *attested = next;
                            Ok(Rollback::Attested {
                                previous,
                                target: next,
                            })
                        })
                    });
                    match outcome {
                        Ok(rollback) => self.rollbacks.push(rollback),
                        Err(error) => return Err(self.manifest_rejected(path, error)),
                    }
                }
                self.entries.push(self.entry(path, true, false));
                Ok(())
            }
            KeyClass::AuthoritativeData => {
                match self.read_existing(path).await? {
                    Some(existing) => {
                        // an existing key: only the current domain may even
                        // offer bytes, and only identical ones.
                        if self.domain != self.authorized {
                            return Err(self.revoked(path));
                        }
                        if existing == bytes {
                            self.entries.push(self.entry(path, true, false));
                            Ok(())
                        } else {
                            Err(self.quarantine_overwrite(path))
                        }
                    }
                    None => {
                        // brand-new key: allowed for any domain - a stale
                        // actor can at worst strand orphan bytes no
                        // reachable manifest names.
                        self.entries.push(self.entry(path, true, false));
                        Ok(())
                    }
                }
            }
        }
    }

    /// The object at `path` is removed.
    async fn remove(&mut self, path: &ObjectPath) -> Result<(), Refused> {
        match classify(path) {
            KeyClass::Publication => {
                if self.domain != self.authorized {
                    return Err(self.revoked(path));
                }
                if self.policy == TransitionPolicy::RequireAttested {
                    match manifest_path_id(path) {
                        Ok(path_id) => {
                            let attested_id = self.control.attested.lock().unwrap().manifest_id;
                            if path_id == attested_id {
                                let refusal = FirewallRefusal::ReferencedManifestDelete {
                                    operation: self.operation,
                                    path: path.to_string(),
                                    attested_manifest_id: attested_id,
                                };
                                return Err(self.refuse(path, false, refusal));
                            }
                        }
                        Err(error) => return Err(self.manifest_rejected(path, error)),
                    }
                }
                self.entries.push(self.entry(path, true, false));
                Ok(())
            }
            KeyClass::AuthoritativeData => {
                if self.read_existing(path).await?.is_some() {
                    // denied globally (pre-G13), current actors included:
                    // an active manifest may reference this key.
                    let refusal = FirewallRefusal::AuthoritativeDeleteDenied {
                        operation: self.operation,
                        path: path.to_string(),
                    };
                    return Err(self.refuse(path, false, refusal));
                }
                // absent key: pass through (the inner store reports
                // NotFound); nothing authoritative is at stake.
                self.entries.push(self.entry(path, true, false));
                Ok(())
            }
        }
    }

    /// Copy (`rename == false`) or rename (`rename == true`): the
    /// destination receives the source's bytes; rename also removes the
    /// source. Classes must match, and the source-removal half of rename
    /// goes through the same rules as delete.
    async fn copy_like(
        &mut self,
        from: &ObjectPath,
        to: &ObjectPath,
        rename: bool,
    ) -> Result<(), Refused> {
        if classify(from) != classify(to) {
            let refusal = FirewallRefusal::KeyClassMismatch {
                operation: self.operation,
                from: from.to_string(),
                to: to.to_string(),
            };
            return Err(self.refuse(to, false, refusal));
        }
        match self.read_existing(from).await? {
            Some(source_bytes) => {
                self.write(to, &source_bytes).await?;
                if rename {
                    self.remove(from).await?;
                }
                Ok(())
            }
            None => {
                // absent source: nothing to validate; the inner store
                // reports NotFound.
                self.entries.push(self.entry(to, true, false));
                Ok(())
            }
        }
    }

    /// Multipart initiation: journaled, and denied outright for a revoked
    /// domain on every key class (a journaled upload is a declared intent
    /// to make an object visible, not orphan residue).
    fn upload_init(&mut self, path: &ObjectPath, attempt: u64) -> Result<(), Refused> {
        if self.domain != self.authorized {
            return Err(self.revoked(path));
        }
        if self.policy == TransitionPolicy::RequireAttested
            && classify(path) == KeyClass::Publication
        {
            if let Err(error) = manifest_path_id(path) {
                return Err(self.manifest_rejected(path, error));
            }
        }
        {
            let mut journal = self.control.journal.lock().unwrap();
            journal
                .entries
                .insert(attempt, (path.to_string(), UploadState::Uncommitted));
        }
        self.rollbacks.push(Rollback::JournalRemove { attempt });
        self.entries.push(self.entry(path, true, false));
        Ok(())
    }

    /// Multipart completion: current authority, the exact journaled
    /// uncommitted attempt, and the full write rules (immutability, typed
    /// transition) against the staged bytes.
    async fn upload_complete(
        &mut self,
        path: &ObjectPath,
        attempt: u64,
        bytes: &[u8],
    ) -> Result<(), Refused> {
        if self.domain != self.authorized {
            return Err(self.revoked(path));
        }
        let journaled = {
            let mut journal = self.control.journal.lock().unwrap();
            match journal.entries.get_mut(&attempt) {
                Some((recorded_path, state))
                    if *state == UploadState::Uncommitted && recorded_path == path.as_ref() =>
                {
                    *state = UploadState::Committed;
                    true
                }
                _ => false,
            }
        };
        if !journaled {
            let refusal = FirewallRefusal::UnjournaledMultipartCompletion {
                path: path.to_string(),
                attempt,
            };
            return Err(self.refuse(path, false, refusal));
        }
        self.rollbacks.push(Rollback::JournalState {
            attempt,
            previous: UploadState::Uncommitted,
        });
        // `write` refusals roll the journal state back via `refuse`.
        self.write(path, bytes).await
    }

    /// Multipart abort: staged-bytes cleanup, admitted only for the exact
    /// journaled uncommitted attempt (never for a committed one, never
    /// for an attempt the journal does not know). Deliberately not
    /// domain-gated: removing never-visible staged bytes is containment,
    /// not publication.
    fn upload_abort(&mut self, path: &ObjectPath, attempt: u64) -> Result<(), Refused> {
        let journaled = {
            let mut journal = self.control.journal.lock().unwrap();
            match journal.entries.get_mut(&attempt) {
                Some((recorded_path, state))
                    if *state == UploadState::Uncommitted && recorded_path == path.as_ref() =>
                {
                    *state = UploadState::Aborted;
                    true
                }
                _ => false,
            }
        };
        if !journaled {
            let refusal = FirewallRefusal::MultipartAbortNotPermitted {
                path: path.to_string(),
                attempt,
            };
            return Err(self.refuse(path, false, refusal));
        }
        self.rollbacks.push(Rollback::JournalState {
            attempt,
            previous: UploadState::Uncommitted,
        });
        self.entries.push(self.entry(path, true, false));
        Ok(())
    }
}

fn apply_rollbacks(control: &FirewallControl, rollbacks: Vec<Rollback>) {
    for rollback in rollbacks.into_iter().rev() {
        match rollback {
            Rollback::Attested { previous, target } => {
                let mut attested = control.attested.lock().unwrap();
                // compare-and-rollback: only undo our own advance; if a
                // later validated transition already built on top, leave
                // it (spike-level resolution of a provider-failure race).
                if *attested == target {
                    *attested = previous;
                }
            }
            Rollback::JournalRemove { attempt } => {
                control.journal.lock().unwrap().entries.remove(&attempt);
            }
            Rollback::JournalState { attempt, previous } => {
                if let Some((_, state)) = control.journal.lock().unwrap().entries.get_mut(&attempt)
                {
                    *state = previous;
                }
            }
        }
    }
}

/// The one gate. Free function (not `&self`) so the `'static` delete
/// stream and the multipart wrapper share it with the ordinary methods -
/// the gate logic must never fork.
///
/// F-01: the WHOLE operation - classification of every involved path,
/// preflight reads, typed-transition validation, and the single provider
/// mutation - runs under exactly ONE authority read guard, acquired here
/// and held to the end. Nothing reachable from this function acquires the
/// authority lock again.
///
/// S-P0-08: check and use are ONE atomic conditional operation with
/// respect to rotation. `rotate()` needs the write guard, so it cannot
/// interleave between validation and the mutation becoming durable.
async fn gate_and_run<T>(
    inner: &Arc<dyn ObjectStore>,
    control: &FirewallControl,
    credential_domain: u64,
    policy: TransitionPolicy,
    operation: &'static str,
    op: OpSpec<'_>,
    mutation: impl Future<Output = StoreResult<T>>,
) -> StoreResult<T> {
    let authorized = control.authority.authorized.read().await;
    let mut validator = Validator {
        inner,
        control,
        domain: credential_domain,
        authorized: *authorized,
        policy,
        operation,
        entries: Vec::new(),
        rollbacks: Vec::new(),
    };
    match validator.validate(&op).await {
        Err(Refused::Typed { attempt, refusal }) => {
            control.log.lock().unwrap().push(attempt);
            Err(refusal.into_store_error())
        }
        Err(Refused::Store(error)) => Err(error),
        Ok(()) => {
            control.log.lock().unwrap().append(&mut validator.entries);
            // the guard (`authorized`) is alive across this await:
            // admitted means admitted-to-completion, and rotation waits
            let outcome = mutation.await;
            if outcome.is_err() {
                apply_rollbacks(control, std::mem::take(&mut validator.rollbacks));
            }
            outcome
        }
    }
}

// ---------------------------------------------------------------------
// The store handle.
// ---------------------------------------------------------------------

/// A store handle bound to one credential domain and one
/// [`TransitionPolicy`], sharing a [`FirewallControl`].
///
/// Structural limitation, measured and permanent for this candidate with
/// a STOCK client: the firewall sees paths and opaque bytes. It can
/// decide WHO may mutate, and - for a cooperating client that authors
/// [`ManifestTransition`] envelopes - WHAT transition is published; but a
/// stock SlateDB client cannot author those envelopes, so its epoch
/// NUMBERS remain internally allocated (inv. 78-80), and adopting
/// whatever epoch the store picked is the prohibited observe-and-bind.
/// Candidate A provides exactly that; Candidate B cannot, at any wrapper
/// thickness, without patching the client.
#[derive(Debug)]
pub struct FirewalledStore {
    inner: Arc<dyn ObjectStore>,
    control: Arc<FirewallControl>,
    credential_domain: u64,
    policy: TransitionPolicy,
}

impl std::fmt::Display for FirewalledStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FirewalledStore(domain={}, {:?}, {})",
            self.credential_domain, self.policy, self.inner
        )
    }
}

fn payload_bytes(payload: &PutPayload) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(payload.content_length());
    for chunk in payload.iter() {
        bytes.extend_from_slice(chunk.as_ref());
    }
    bytes
}

#[async_trait]
impl ObjectStore for FirewalledStore {
    async fn put_opts(
        &self,
        location: &ObjectPath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> StoreResult<PutResult> {
        let bytes = payload_bytes(&payload);
        gate_and_run(
            &self.inner,
            &self.control,
            self.credential_domain,
            self.policy,
            "put",
            OpSpec::Put {
                path: location,
                bytes: &bytes,
            },
            self.inner.put_opts(location, payload, opts),
        )
        .await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjectPath,
        opts: PutMultipartOptions,
    ) -> StoreResult<Box<dyn MultipartUpload>> {
        // the attempt id is allocated BEFORE the gate (leaf lock only);
        // the journal entry is recorded during validation, under the
        // single authority guard, and removed if initiation fails.
        let attempt = self.control.allocate_attempt();
        let inner = gate_and_run(
            &self.inner,
            &self.control,
            self.credential_domain,
            self.policy,
            "put_multipart",
            OpSpec::UploadInit {
                path: location,
                attempt,
            },
            self.inner.put_multipart_opts(location, opts),
        )
        .await?;
        Ok(Box::new(GatedMultipartUpload {
            inner,
            inner_store: Arc::clone(&self.inner),
            control: Arc::clone(&self.control),
            credential_domain: self.credential_domain,
            policy: self.policy,
            path: location.clone(),
            attempt,
            staged: Vec::new(),
        }))
    }

    async fn get_opts(&self, location: &ObjectPath, options: GetOptions) -> StoreResult<GetResult> {
        self.inner.get_opts(location, options).await
    }

    fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, StoreResult<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&ObjectPath>) -> StoreResult<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &ObjectPath,
        to: &ObjectPath,
        options: CopyOptions,
    ) -> StoreResult<()> {
        gate_and_run(
            &self.inner,
            &self.control,
            self.credential_domain,
            self.policy,
            "copy",
            OpSpec::Copy { from, to },
            self.inner.copy_opts(from, to, options),
        )
        .await
    }

    async fn rename_opts(
        &self,
        from: &ObjectPath,
        to: &ObjectPath,
        options: RenameOptions,
    ) -> StoreResult<()> {
        // F-01: both halves (the copy onto `to`, the delete of `from`)
        // are classified and validated under ONE authority guard, then
        // the single underlying rename runs while it is held. The old
        // shape - an outer guard for the destination and a nested inner
        // guard for the source - deadlocks against a rotation writer
        // queued between the two acquisitions.
        gate_and_run(
            &self.inner,
            &self.control,
            self.credential_domain,
            self.policy,
            "rename",
            OpSpec::Rename { from, to },
            self.inner.rename_opts(from, to, options),
        )
        .await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, StoreResult<ObjectPath>>,
    ) -> BoxStream<'static, StoreResult<ObjectPath>> {
        use futures::StreamExt;
        let domain = self.credential_domain;
        let policy = self.policy;
        let control = Arc::clone(&self.control);
        let inner = Arc::clone(&self.inner);
        locations
            .then(move |location| {
                let control = Arc::clone(&control);
                let inner = Arc::clone(&inner);
                async move {
                    let location = location?;
                    gate_and_run(
                        &inner,
                        &control,
                        domain,
                        policy,
                        "delete",
                        OpSpec::Delete { path: &location },
                        inner.delete(&location),
                    )
                    .await
                    .map(|()| location)
                }
            })
            .boxed()
    }
}

/// A raw multipart handle. Parts are staged, never-visible bytes and pass
/// through (mirrored locally so completion can validate immutability and
/// typed transitions against the EXACT bytes that would become visible);
/// `complete()` - the visibility-granting mutation - re-runs the gate
/// atomically (S-P0-08) against the journaled attempt; `abort()` is
/// admitted only for the exact uncommitted attempt.
#[derive(Debug)]
struct GatedMultipartUpload {
    inner: Box<dyn MultipartUpload>,
    inner_store: Arc<dyn ObjectStore>,
    control: Arc<FirewallControl>,
    credential_domain: u64,
    policy: TransitionPolicy,
    path: ObjectPath,
    attempt: u64,
    staged: Vec<u8>,
}

#[async_trait]
impl MultipartUpload for GatedMultipartUpload {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        self.staged.extend(payload_bytes(&data));
        self.inner.put_part(data)
    }

    async fn complete(&mut self) -> StoreResult<PutResult> {
        let Self {
            inner,
            inner_store,
            control,
            credential_domain,
            policy,
            path,
            attempt,
            staged,
        } = self;
        gate_and_run(
            inner_store,
            control,
            *credential_domain,
            *policy,
            "multipart_complete",
            OpSpec::UploadComplete {
                path,
                attempt: *attempt,
                bytes: staged,
            },
            inner.complete(),
        )
        .await
    }

    async fn abort(&mut self) -> StoreResult<()> {
        let Self {
            inner,
            inner_store,
            control,
            credential_domain,
            policy,
            path,
            attempt,
            ..
        } = self;
        gate_and_run(
            inner_store,
            control,
            *credential_domain,
            *policy,
            "multipart_abort",
            OpSpec::UploadAbort {
                path,
                attempt: *attempt,
            },
            inner.abort(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slatedb::config::{PutOptions, Settings, WriteOptions};
    use slatedb::object_store::memory::InMemory;
    use slatedb::object_store::PutOptions as StorePutOptions;
    use slatedb::Db;

    /// The U2 write posture (slate.rs `write_options()`): `await_durable:
    /// false` - with `flush_interval: None` and the WAL off, a durable
    /// await would wait forever; durability is `flush()`'s job.
    async fn put(db: &Db, key: &[u8], value: &[u8]) -> Result<(), slatedb::Error> {
        db.put_with_options(
            key,
            value,
            &PutOptions::default(),
            &WriteOptions {
                await_durable: false,
                ..Default::default()
            },
        )
        .await
        .map(|_| ())
    }

    /// The U2 posture (fork/typedb slate.rs `settings()`): SlateDB WAL off,
    /// no compactor, no GC - TypeDB's WAL is the durability authority.
    fn posture() -> Settings {
        let mut settings = Settings::default();
        settings.wal_enabled = false;
        settings.flush_interval = None;
        settings.compactor_options = None;
        settings.garbage_collector_options = None;
        settings.compression_codec = None;
        settings.l0_max_ssts = 1_000_000;
        settings.l0_max_ssts_per_key = 1_000_000;
        // Q-13, re-observed HERE: with the stock default (None = retry
        // transient errors indefinitely) the firewall's refusal put
        // `flush()` into an infinite retry loop - the fenced writer HUNG
        // instead of failing. A store-boundary candidate inherits this
        // hazard on every refusal path; Candidate A's typed Fenced error is
        // terminal by construction. Recorded in the comparison.
        settings.object_store_max_retries = Some(4);
        settings
    }

    struct Harness {
        remote: Arc<dyn ObjectStore>,
        control: Arc<FirewallControl>,
    }

    impl Harness {
        fn new() -> Self {
            Self::over(Arc::new(InMemory::new()))
        }

        fn over(remote: Arc<dyn ObjectStore>) -> Self {
            Self {
                remote,
                control: FirewallControl::new(),
            }
        }

        fn authority(&self) -> &Arc<PublicationAuthority> {
            self.control.authority()
        }

        /// Stock-SlateDB compatibility handle: the client cannot author
        /// transition envelopes, so publications are admitted on
        /// authority + immutability alone (the measured F-03 limitation).
        fn handle(&self, credential_domain: u64) -> Arc<dyn ObjectStore> {
            Arc::new(self.control.handle(
                self.remote.clone(),
                credential_domain,
                TransitionPolicy::LegacyUnattested,
            ))
        }

        /// Gateway handle: typed manifest transitions required (F-03).
        fn strict_handle(&self, credential_domain: u64) -> Arc<dyn ObjectStore> {
            Arc::new(self.control.handle(
                self.remote.clone(),
                credential_domain,
                TransitionPolicy::RequireAttested,
            ))
        }

        async fn open(&self, credential_domain: u64) -> Result<Db, slatedb::Error> {
            Db::builder("spike-db", self.handle(credential_domain))
                .with_settings(posture())
                .build()
                .await
        }

        fn attempts(&self) -> Vec<MutationAttempt> {
            self.control.attempts()
        }
    }

    fn assert_refused(err: &slatedb::object_store::Error, want: impl Fn(&FirewallRefusal) -> bool) {
        let refusal = firewall_refusal(err)
            .unwrap_or_else(|| panic!("expected a typed firewall refusal, got: {err}"));
        assert!(want(refusal), "unexpected refusal: {refusal:?}");
    }

    async fn raw_bytes(store: &Arc<dyn ObjectStore>, path: &ObjectPath) -> Option<Vec<u8>> {
        match store.get(path).await {
            Ok(r) => Some(r.bytes().await.expect("bytes").to_vec()),
            Err(slatedb::object_store::Error::NotFound { .. }) => None,
            Err(e) => panic!("unexpected store error: {e}"),
        }
    }

    /// Coverage: every mutation of a full open -> put -> flush -> close
    /// cycle flows through the firewall, and the manifest publications among
    /// them are identifiable by path alone. This is the property that makes
    /// a store-boundary firewall a COMPLETE gate for a provider to enforce:
    /// the engine has no second channel - including the `Admin` checkpoint
    /// paths that bypass upstream's own fencing types.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_publication_path_flows_through_the_firewall() {
        let harness = Harness::new();
        let db = harness.open(1).await.expect("authorized open");
        put(&db, b"k1", b"v1").await.expect("put");
        db.flush().await.expect("flush");
        db.close().await.expect("close");

        let attempts = harness.attempts();
        let publications: Vec<&MutationAttempt> =
            attempts.iter().filter(|a| a.publication).collect();
        assert!(
            !publications.is_empty(),
            "an open/put/flush/close cycle must publish manifests; the firewall saw none"
        );
        assert!(publications
            .iter()
            .all(|a| a.allowed && a.credential_domain == 1));
        // and the cycle also wrote data-path objects that are NOT publications
        assert!(
            attempts.iter().any(|a| !a.publication),
            "expected non-publication data writes (SSTs) in the cycle"
        );
        // no key was quarantined by an ordinary cycle
        assert!(harness.control.quarantined().is_empty());
    }

    /// Pause-fence-resume, the SL-P1 shape: rotation alone (no replacement
    /// writer yet) fences the stale handle's next publication - the refusal
    /// comes from the firewall, not from upstream CAS arbitration. Data
    /// already durable stays readable; the stale writer's post-revocation
    /// residue is refused manifest writes and (at worst) orphan bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revoked_writer_cannot_publish_and_a_successor_can() {
        let harness = Harness::new();
        let stale = harness.open(1).await.expect("authorized open");
        put(&stale, b"k1", b"v1").await.expect("put");
        stale.flush().await.expect("flush under authority");

        // controller revokes domain 1 (credential rotation); nothing else
        let successor_domain = harness.authority().rotate().await.expect("rotate");
        assert_eq!(successor_domain, 2);

        // the stale writer's next publication dies at the store boundary
        put(&stale, b"k2", b"v2")
            .await
            .expect("memtable write is local");
        let refused = stale.flush().await;
        assert!(
            refused.is_err(),
            "a revoked domain must not publish a manifest"
        );
        let refusals: Vec<MutationAttempt> = harness
            .attempts()
            .into_iter()
            .filter(|a| !a.allowed)
            .collect();
        assert!(!refusals.is_empty());
        assert!(
            refusals.iter().all(|a| a.credential_domain == 1),
            "only domain-1 attempts may be refused: {refusals:?}"
        );
        assert!(
            refusals.iter().any(|a| a.publication),
            "the manifest publication itself must be among the refusals: {refusals:?}"
        );
        drop(stale);

        // the successor opens under the fresh domain and proceeds; the
        // predecessor's durable prefix is intact
        let successor = harness
            .open(successor_domain)
            .await
            .expect("successor open");
        let durable = successor.get(b"k1").await.expect("read");
        assert_eq!(durable.as_deref(), Some(&b"v1"[..]));
        put(&successor, b"k3", b"v3").await.expect("put");
        successor.flush().await.expect("successor publishes");
        successor.close().await.expect("close");
    }

    /// Stale REOPEN (the directive's named case): opening a database is
    /// itself a publication (epoch bump), so a handle whose domain was
    /// revoked cannot even reach the point of holding a writer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stale_reopen_is_refused_at_open() {
        let harness = Harness::new();
        let first = harness.open(1).await.expect("authorized open");
        put(&first, b"k1", b"v1").await.expect("put");
        first.flush().await.expect("flush");
        first.close().await.expect("close");

        harness.authority().rotate().await.expect("rotate");
        let stale_open = harness.open(1).await;
        assert!(
            stale_open.is_err(),
            "open publishes; a revoked domain must fail to open"
        );
        // and the refusal was the firewall's, on a manifest path
        let refusals: Vec<MutationAttempt> = harness
            .attempts()
            .into_iter()
            .filter(|a| !a.allowed)
            .collect();
        assert!(refusals
            .iter()
            .any(|a| a.publication && a.credential_domain == 1));
    }

    /// The measured LIMIT of Candidate B for a STOCK client, stated as an
    /// executable fact: with `TransitionPolicy::LegacyUnattested` (the
    /// only mode stock SlateDB can run under, because it cannot author
    /// `ManifestTransition` envelopes) the firewall observes paths and
    /// opaque bytes only. Nothing in this mode can cause the manifests to
    /// carry controller-issued epoch VALUES - the attempts log (this
    /// mode's entire vocabulary) has no epoch in it, and the stock builder
    /// API accepts none. inv. 78-80 therefore cannot be satisfied for a
    /// stock client by ANY wrapper; the typed-transition gate (F-03)
    /// exists, but only a cooperating - i.e. patched - client can speak
    /// it, which is Candidate A's half of the comparison.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_firewall_vocabulary_has_no_epoch_in_it() {
        let harness = Harness::new();
        let db = harness.open(1).await.expect("open");
        put(&db, b"k", b"v").await.expect("put");
        db.flush().await.expect("flush");
        db.close().await.expect("close");
        for attempt in harness.attempts() {
            // the whole observable record: path, operation, domain,
            // verdict, quarantine flag. No field carries or could carry a
            // SlateWriterEpoch value.
            let MutationAttempt {
                path: _,
                operation: _,
                credential_domain,
                publication: _,
                allowed,
                quarantined,
            } = attempt;
            assert!(credential_domain == 1 && allowed && !quarantined);
        }
        // and the attested state never moved: no stock publication could
        // author a typed transition.
        assert_eq!(harness.control.attested(), AttestedManifest::default());
    }

    // ----------------------------------------------------------------
    // S-P0-08: the gate is use-time-atomic, not check-then-use.
    // ----------------------------------------------------------------

    /// An inner store whose puts can be held mid-flight: signals when a put
    /// has ENTERED the provider (i.e. is past any admission check) and
    /// waits for an explicit release before completing.
    #[derive(Debug)]
    struct HoldingStore {
        inner: Arc<dyn ObjectStore>,
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<tokio::sync::Notify>,
        hold: std::sync::atomic::AtomicBool,
    }

    impl std::fmt::Display for HoldingStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "HoldingStore({})", self.inner)
        }
    }

    #[async_trait]
    impl ObjectStore for HoldingStore {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            opts: StorePutOptions,
        ) -> StoreResult<PutResult> {
            if self.hold.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = self.entered.send(());
                self.release.notified().await;
            }
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjectPath,
            opts: PutMultipartOptions,
        ) -> StoreResult<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> StoreResult<GetResult> {
            self.inner.get_opts(location, options).await
        }

        fn list(&self, prefix: Option<&ObjectPath>) -> BoxStream<'static, StoreResult<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> StoreResult<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> StoreResult<()> {
            self.inner.copy_opts(from, to, options).await
        }

        async fn rename_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: RenameOptions,
        ) -> StoreResult<()> {
            self.inner.rename_opts(from, to, options).await
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, StoreResult<ObjectPath>>,
        ) -> BoxStream<'static, StoreResult<ObjectPath>> {
            self.inner.delete_stream(locations)
        }
    }

    /// The race the original spike had (S-P0-08): admit under domain 1,
    /// rotate while the provider PUT is still in flight, and the "revoked"
    /// publication lands anyway. With the atomic gate, rotation CANNOT take
    /// effect while an admitted publication is in flight - it drains first
    /// - so no publication ever completes under an authority that has
    /// already moved on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_cannot_interleave_between_admission_and_provider_completion() {
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let holding = Arc::new(HoldingStore {
            inner: Arc::new(InMemory::new()),
            entered: entered_tx,
            release: Arc::clone(&release),
            hold: std::sync::atomic::AtomicBool::new(true),
        });
        let harness = Harness::over(holding);
        let store = harness.handle(1);

        // an admitted publication, now held INSIDE the provider
        let manifest_path = ObjectPath::from("spike-db/manifest/00000000000000000001.manifest");
        let in_flight = tokio::spawn({
            let store = Arc::clone(&store);
            let manifest_path = manifest_path.clone();
            async move {
                store
                    .put_opts(
                        &manifest_path,
                        PutPayload::from_static(b"root"),
                        slatedb::object_store::PutOptions::default(),
                    )
                    .await
            }
        });
        entered_rx
            .recv()
            .await
            .expect("the put must enter the provider");

        // revocation while the admitted publication is in flight
        let mut rotation = tokio::spawn({
            let authority = Arc::clone(harness.authority());
            async move { authority.rotate().await }
        });

        // the atomic property: rotation must NOT complete while the
        // admitted publication is still inside the provider. (Under the
        // old check-then-use gate this timeout observes rotation
        // completing immediately - the executable form of the TOCTOU.)
        let premature =
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut rotation).await;
        assert!(
            premature.is_err(),
            "rotation took effect while an admitted publication was still in flight: \
             the gate is check-then-use, not atomic"
        );

        // release the provider: the publication completes UNDER DOMAIN 1,
        // and only then does rotation land
        release.notify_waiters();
        in_flight
            .await
            .expect("join")
            .expect("the admitted publication completes under its admitting authority");
        let new_domain = rotation
            .await
            .expect("join")
            .expect("rotation proceeds after drain");
        assert_eq!(new_domain, 2);

        // and after rotation, domain 1 is refused at admission
        let refused = store
            .put_opts(
                &ObjectPath::from("spike-db/manifest/00000000000000000002.manifest"),
                PutPayload::from_static(b"stale"),
                slatedb::object_store::PutOptions::default(),
            )
            .await;
        assert!(
            refused.is_err(),
            "post-rotation domain-1 publication must be refused"
        );
    }

    /// S-P0-08, multipart half: initiation-time authority is NOT completion
    /// authority. A raw multipart upload admitted under domain 1 whose
    /// `complete()` arrives after rotation must be refused, and the object
    /// must not exist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_multipart_completion_after_rotation_is_refused_and_publishes_nothing() {
        let harness = Harness::new();
        let store = harness.handle(1);
        let manifest_path = ObjectPath::from("spike-db/manifest/00000000000000000009.manifest");

        // initiated (and admitted) under domain 1
        let mut upload = store
            .put_multipart_opts(&manifest_path, PutMultipartOptions::default())
            .await
            .expect("initiation under authority");
        upload
            .put_part(PutPayload::from_static(b"staged-part"))
            .await
            .expect("parts are staged bytes and pass");

        // authority rotates between initiation and completion
        harness.authority().rotate().await.expect("rotate");

        let refused = upload.complete().await;
        assert!(
            refused.is_err(),
            "multipart complete() must revalidate authority at use time"
        );
        assert_refused(&refused.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::RevokedDomain { .. })
        });
        let landed = store.get_opts(&manifest_path, GetOptions::default()).await;
        assert!(
            landed.is_err(),
            "a refused completion must leave no visible object"
        );
        // the refusal is recorded as a fenced publication attempt
        assert!(harness
            .attempts()
            .iter()
            .any(|a| { a.operation == "multipart_complete" && a.publication && !a.allowed }));

        // a successor handle CAN complete a fresh multipart on the same key
        let successor = harness.handle(2);
        let mut upload = successor
            .put_multipart_opts(&manifest_path, PutMultipartOptions::default())
            .await
            .expect("successor initiation");
        upload
            .put_part(PutPayload::from_static(b"successor-part"))
            .await
            .expect("part");
        upload.complete().await.expect("successor completion");
    }

    // ----------------------------------------------------------------
    // S-P0-09 (rotation counter): typed exhaustion, no mutation.
    // ----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn domain_rotation_is_exact_at_the_boundary_and_refuses_exhaustion() {
        // MAX-1 -> MAX is an ordinary rotation.
        let authority = PublicationAuthority::starting_at(u64::MAX - 1);
        assert_eq!(authority.rotate().await, Ok(u64::MAX));
        assert_eq!(authority.current().await, u64::MAX);

        // At MAX, rotation is a typed refusal and mutates NOTHING - twice,
        // to prove the refusal is stable rather than a one-shot.
        for _ in 0..2 {
            assert_eq!(authority.rotate().await, Err(CredentialDomainExhausted));
            assert_eq!(
                authority.current().await,
                u64::MAX,
                "a refused rotation must not mint or alter authority (a wrap would mint domain 0)"
            );
        }

        // and the incumbent MAX-domain handle is still the authority: a
        // failed rotation revokes nobody.
        let control = FirewallControl::with_authority(authority);
        let store = control.handle(
            Arc::new(InMemory::new()),
            u64::MAX,
            TransitionPolicy::LegacyUnattested,
        );
        store
            .put_opts(
                &ObjectPath::from("spike-db/manifest/00000000000000000001.manifest"),
                PutPayload::from_static(b"root"),
                slatedb::object_store::PutOptions::default(),
            )
            .await
            .expect("the incumbent remains authorized after a refused rotation");
    }

    // ----------------------------------------------------------------
    // F-01: one authority guard per operation; validation is bounded even
    // with a rotation writer queued mid-operation.
    // ----------------------------------------------------------------

    /// The audit's deterministic barrier probe. Schedule (all steps gated
    /// on explicit signals, no sleeps on the critical property):
    ///
    /// 1. OUTER ADMISSION HELD: a domain-1 publication is admitted and
    ///    held INSIDE the provider, so an authority read guard stays held
    ///    for as long as the test wants.
    /// 2. ROTATION WRITER QUEUED: `rotate()` is spawned and provably
    ///    blocked behind that guard (bounded timeout observes it pending).
    /// 3. SOURCE VALIDATION: a `rename` - the two-publication-path
    ///    operation - starts (barrier-ordered), enqueues on the authority
    ///    lock behind the writer, and a SECOND rotation writer is queued
    ///    behind it.
    /// 4. The hold is released. THE PROPERTY: the rename must complete or
    ///    refuse within a bound.
    ///
    /// Under the pre-fix nested-guard shape this exact schedule deadlocks:
    /// the rename's outer (destination) guard is admitted after the first
    /// rotation lands, and its INNER (source) read acquisition then queues
    /// behind the second writer, which is itself waiting for the outer
    /// guard - the timeout below observes the deadlock. The single-guard
    /// gate validates source and destination under ONE guard and drains.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn source_validation_is_bounded_with_a_rotation_writer_queued() {
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let memory: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let holding = Arc::new(HoldingStore {
            inner: Arc::clone(&memory),
            entered: entered_tx,
            release: Arc::clone(&release),
            hold: std::sync::atomic::AtomicBool::new(true),
        });
        let harness = Harness::over(holding);

        // the rename source exists in the underlying store
        let rename_from = ObjectPath::from("spike-db/manifest/00000000000000000015.manifest");
        let rename_to = ObjectPath::from("spike-db/manifest/00000000000000000017.manifest");
        memory
            .put(&rename_from, PutPayload::from_static(b"m15"))
            .await
            .expect("seed source");

        // 1. outer admission held inside the provider (guard held)
        let held_store = harness.handle(1);
        let held = tokio::spawn({
            let store = Arc::clone(&held_store);
            async move {
                store
                    .put_opts(
                        &ObjectPath::from("spike-db/manifest/00000000000000000016.manifest"),
                        PutPayload::from_static(b"m16"),
                        slatedb::object_store::PutOptions::default(),
                    )
                    .await
            }
        });
        entered_rx.recv().await.expect("held put enters provider");

        // 2. rotation writer queued behind the held admission
        let mut first_rotation = tokio::spawn({
            let authority = Arc::clone(harness.authority());
            async move { authority.rotate().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut first_rotation)
                .await
                .is_err(),
            "the rotation writer must be queued behind the held admission"
        );

        // 3. the rename starts (barrier-ordered) and enqueues on the
        //    authority lock; then a second rotation writer queues behind it
        let renamer = harness.handle(2); // valid once the first rotation lands
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut rename = tokio::spawn({
            let renamer = Arc::clone(&renamer);
            let barrier = Arc::clone(&barrier);
            let rename_from = rename_from.clone();
            let rename_to = rename_to.clone();
            async move {
                barrier.wait().await;
                renamer
                    .rename_opts(&rename_from, &rename_to, RenameOptions::default())
                    .await
            }
        });
        barrier.wait().await;
        // scheduling grace: the spawned rename reaches the authority lock
        // and enqueues (it has its own worker thread and no other await
        // point before the lock)
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut second_rotation = tokio::spawn({
            let authority = Arc::clone(harness.authority());
            async move { authority.rotate().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut second_rotation)
                .await
                .is_err(),
            "the second rotation writer must be queued"
        );

        // 4. release the held admission; the whole queue must drain
        release.notify_waiters();
        held.await
            .expect("join")
            .expect("held publication completes under domain 1");
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut first_rotation)
            .await
            .expect("first rotation lands")
            .expect("join")
            .expect("rotate");

        // THE F-01 PROPERTY: with a rotation writer queued mid-operation,
        // the two-path operation completes or refuses within a bound.
        let renamed = tokio::time::timeout(std::time::Duration::from_secs(2), &mut rename)
            .await
            .expect(
                "rename must complete or refuse within the bound; a timeout here is the \
                 nested-guard deadlock (inner source read behind the queued writer, the \
                 writer behind the outer destination guard)",
            )
            .expect("join");
        renamed.expect("rename admitted under the current domain");
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut second_rotation)
            .await
            .expect("second rotation lands after the rename drains")
            .expect("join")
            .expect("rotate");

        // and the rename actually happened
        assert!(raw_bytes(&memory, &rename_from).await.is_none());
        assert_eq!(
            raw_bytes(&memory, &rename_to).await.as_deref(),
            Some(&b"m15"[..])
        );
    }

    // ----------------------------------------------------------------
    // F-02: authority and immutability on EVERY mutating path.
    // ----------------------------------------------------------------

    /// The audit's probe shape: a revoked actor attempts overwrite and
    /// delete on a manifest-referenced data key. Both are typed-denied and
    /// the bytes are unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revoked_actor_cannot_overwrite_or_delete_a_referenced_data_key() {
        let harness = Harness::new();
        let writer = harness.handle(1);
        let sst = ObjectPath::from("spike-db/compacted/0000000000000001.sst");
        let manifest = ObjectPath::from("spike-db/manifest/00000000000000000001.manifest");

        writer
            .put(&sst, PutPayload::from_static(b"sst-v1"))
            .await
            .expect("create under authority");
        // the key is completed authoritative data an active manifest names
        writer
            .put(
                &manifest,
                PutPayload::from_static(b"refs: 0000000000000001.sst"),
            )
            .await
            .expect("manifest referencing the key");

        harness.authority().rotate().await.expect("rotate");

        // overwrite by the revoked actor: typed denial
        let overwrite = writer
            .put(&sst, PutPayload::from_static(b"attacker-bytes"))
            .await;
        assert_refused(&overwrite.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::RevokedDomain { domain: 1, .. })
        });

        // delete by the revoked actor: typed denial (delete routes through
        // delete_stream, the only delete channel the trait has)
        let deleted = writer.delete(&sst).await;
        assert_refused(&deleted.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::AuthoritativeDeleteDenied { .. })
        });

        // bytes unchanged underneath
        assert_eq!(
            raw_bytes(&harness.remote, &sst).await.as_deref(),
            Some(&b"sst-v1"[..])
        );

        // and even the CURRENT domain cannot delete completed
        // authoritative data (denied globally pre-G13)
        let successor = harness.handle(2);
        let deleted = successor.delete(&sst).await;
        assert_refused(&deleted.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::AuthoritativeDeleteDenied { .. })
        });
        assert_eq!(
            raw_bytes(&harness.remote, &sst).await.as_deref(),
            Some(&b"sst-v1"[..])
        );
    }

    /// Immutable data keys are create-only or same-bytes idempotent;
    /// different bytes at an existing key are a typed refusal AND set the
    /// quarantine flag. A stale actor may still create a brand-new key
    /// (orphan containment).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn immutable_data_keys_are_create_only_or_same_bytes_idempotent() {
        let harness = Harness::new();
        let writer = harness.handle(1);
        let sst = ObjectPath::from("spike-db/compacted/0000000000000002.sst");

        writer
            .put(&sst, PutPayload::from_static(b"bytes"))
            .await
            .expect("create");
        // same bytes: idempotent
        writer
            .put(&sst, PutPayload::from_static(b"bytes"))
            .await
            .expect("same-bytes put is idempotent");
        assert!(harness.control.quarantined().is_empty());

        // different bytes, CURRENT domain: refused and quarantined
        let overwrite = writer.put(&sst, PutPayload::from_static(b"other")).await;
        assert_refused(&overwrite.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::ImmutableKeyOverwrite { .. })
        });
        assert_eq!(harness.control.quarantined(), vec![sst.to_string()]);
        assert!(
            harness
                .attempts()
                .iter()
                .any(|a| !a.allowed && a.quarantined && a.path == sst.to_string()),
            "the refusal must be logged with the quarantine flag"
        );
        assert_eq!(
            raw_bytes(&harness.remote, &sst).await.as_deref(),
            Some(&b"bytes"[..])
        );

        // a stale actor may still create a brand-new key: orphan bytes
        harness.authority().rotate().await.expect("rotate");
        let orphan = ObjectPath::from("spike-db/compacted/0000000000000003.sst");
        writer
            .put(&orphan, PutPayload::from_static(b"orphan"))
            .await
            .expect("stale creation of a brand-new data key is permitted containment");
    }

    /// Multipart is journaled: completion is admitted only for the exact
    /// journaled uncommitted `UploadAttemptId`; abort only for the exact
    /// uncommitted attempt; initiation is denied for a revoked domain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multipart_is_gated_on_the_exact_journaled_attempt() {
        let harness = Harness::new();
        let store = harness.handle(1);
        let key = ObjectPath::from("spike-db/compacted/0000000000000009.sst");

        // abort of the exact uncommitted attempt: admitted; completion of
        // the SAME attempt afterwards: refused (it is no longer the
        // journaled uncommitted attempt), and no object appears.
        let mut upload = store
            .put_multipart_opts(&key, PutMultipartOptions::default())
            .await
            .expect("initiation");
        upload
            .put_part(PutPayload::from_static(b"part"))
            .await
            .expect("part");
        upload
            .abort()
            .await
            .expect("abort of the exact uncommitted attempt");
        let completed = upload.complete().await;
        assert_refused(&completed.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::UnjournaledMultipartCompletion { .. })
        });
        assert!(raw_bytes(&harness.remote, &key).await.is_none());

        // a fresh attempt completes; abort AFTER completion is refused
        // (only the exact uncommitted attempt may be aborted).
        let mut upload = store
            .put_multipart_opts(&key, PutMultipartOptions::default())
            .await
            .expect("second initiation");
        upload
            .put_part(PutPayload::from_static(b"part"))
            .await
            .expect("part");
        upload.complete().await.expect("gated completion");
        let aborted = upload.abort().await;
        assert_refused(&aborted.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::MultipartAbortNotPermitted { .. })
        });
        assert_eq!(
            raw_bytes(&harness.remote, &key).await.as_deref(),
            Some(&b"part"[..])
        );

        // initiation by a revoked domain is denied on any key class
        harness.authority().rotate().await.expect("rotate");
        let stale_init = store
            .put_multipart_opts(
                &ObjectPath::from("spike-db/compacted/0000000000000010.sst"),
                PutMultipartOptions::default(),
            )
            .await;
        assert_refused(&stale_init.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::RevokedDomain { domain: 1, .. })
        });
    }

    /// Copy/rename validate key classes and treat the rename source as a
    /// delete: a referenced (existing authoritative) source cannot be
    /// deleted, and cross-class moves are refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn copy_and_rename_validate_classes_and_cannot_delete_a_referenced_source() {
        let harness = Harness::new();
        let store = harness.handle(1);
        let sst = ObjectPath::from("spike-db/compacted/0000000000000004.sst");
        store
            .put(&sst, PutPayload::from_static(b"sst"))
            .await
            .expect("create");

        // cross-class: data -> publication refused
        let cross = store
            .copy_opts(
                &sst,
                &ObjectPath::from("spike-db/manifest/00000000000000000008.manifest"),
                CopyOptions::default(),
            )
            .await;
        assert_refused(&cross.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::KeyClassMismatch { .. })
        });

        // rename of an existing authoritative data key deletes its source:
        // refused, source intact, destination absent
        let dest = ObjectPath::from("spike-db/compacted/0000000000000005.sst");
        let renamed = store
            .rename_opts(&sst, &dest, RenameOptions::default())
            .await;
        assert_refused(&renamed.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::AuthoritativeDeleteDenied { .. })
        });
        assert_eq!(
            raw_bytes(&harness.remote, &sst).await.as_deref(),
            Some(&b"sst"[..])
        );
        assert!(raw_bytes(&harness.remote, &dest).await.is_none());

        // copy (no source delete) of a data key to a fresh data key is
        // create-only and admitted
        store
            .copy_opts(&sst, &dest, CopyOptions::default())
            .await
            .expect("copy to a fresh key of the same class");

        // and a revoked domain may not copy at all onto existing keys
        harness.authority().rotate().await.expect("rotate");
        let stale_copy = store.copy_opts(&sst, &dest, CopyOptions::default()).await;
        assert_refused(&stale_copy.unwrap_err(), |r| {
            matches!(r, FirewallRefusal::RevokedDomain { domain: 1, .. })
        });
    }

    // ----------------------------------------------------------------
    // F-03: typed manifest transitions, validated - not just key paths.
    // ----------------------------------------------------------------

    fn transition(
        role: Role,
        class: MutationClass,
        base: u64,
        target: u64,
        writer: (u64, u64),
        compactor: (u64, u64),
    ) -> Vec<u8> {
        let mut bytes = ManifestTransition {
            role,
            class,
            base_manifest_id: base,
            target_manifest_id: target,
            old_writer_epoch: writer.0,
            new_writer_epoch: writer.1,
            old_compactor_epoch: compactor.0,
            new_compactor_epoch: compactor.1,
        }
        .encode();
        bytes.extend_from_slice(b"...manifest body...");
        bytes
    }

    fn manifest_path(id: u64) -> ObjectPath {
        ObjectPath::from(format!("spike-db/manifest/{id:020}.manifest"))
    }

    async fn publish(
        store: &Arc<dyn ObjectStore>,
        path: &ObjectPath,
        bytes: Vec<u8>,
    ) -> StoreResult<PutResult> {
        store
            .put_opts(
                path,
                PutPayload::from(bytes),
                slatedb::object_store::PutOptions::default(),
            )
            .await
    }

    /// The typed happy path: PROMOTING writer-open (writer epoch may only
    /// increase), ACTIVE publication (attested epochs preserved),
    /// compactor-open (only the compactor epoch changes) - each advancing
    /// the attested state exactly once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_gateway_validates_typed_manifest_transitions() {
        let harness = Harness::new();
        let gateway = harness.strict_handle(1);

        // PROMOTING writer-open: writer epoch 0 -> 1
        publish(
            &gateway,
            &manifest_path(1),
            transition(
                Role::Writer,
                MutationClass::WriterOpen,
                0,
                1,
                (0, 1),
                (0, 0),
            ),
        )
        .await
        .expect("writer-open");
        assert_eq!(
            harness.control.attested(),
            AttestedManifest {
                manifest_id: 1,
                writer_epoch: 1,
                compactor_epoch: 0
            }
        );

        // ACTIVE publication: epochs preserved
        publish(
            &gateway,
            &manifest_path(2),
            transition(
                Role::Writer,
                MutationClass::ActivePublication,
                1,
                2,
                (1, 1),
                (0, 0),
            ),
        )
        .await
        .expect("active publication");
        assert_eq!(harness.control.attested().writer_epoch, 1);

        // compactor-open: only the compactor epoch changes
        publish(
            &gateway,
            &manifest_path(3),
            transition(
                Role::Compactor,
                MutationClass::CompactorOpen,
                2,
                3,
                (1, 1),
                (0, 1),
            ),
        )
        .await
        .expect("compactor-open");
        assert_eq!(
            harness.control.attested(),
            AttestedManifest {
                manifest_id: 3,
                writer_epoch: 1,
                compactor_epoch: 1
            }
        );

        // and the attested current manifest cannot be deleted
        let refused = gateway.delete(&manifest_path(3)).await;
        assert_refused(&refused.unwrap_err(), |r| {
            matches!(
                r,
                FirewallRefusal::ReferencedManifestDelete {
                    attested_manifest_id: 3,
                    ..
                }
            )
        });
    }

    /// Decoder fail-closed cases: short input, wrong magic, unknown
    /// version/role/class, malformed manifest file names, and a path/id
    /// mismatch all refuse with a typed error and publish NOTHING.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_or_unknown_manifest_transitions_fail_closed() {
        let harness = Harness::new();
        let gateway = harness.strict_handle(1);

        let cases: Vec<(&str, ObjectPath, Vec<u8>, fn(&TransitionError) -> bool)> = vec![
            ("too short", manifest_path(1), b"TDBM".to_vec(), |e| {
                matches!(e, TransitionError::TooShort { .. })
            }),
            (
                "bad magic (a stock SlateDB manifest is not an envelope)",
                manifest_path(1),
                vec![0u8; ManifestTransition::HEADER_LEN],
                |e| matches!(e, TransitionError::BadMagic),
            ),
            (
                "unknown version fails closed",
                manifest_path(1),
                {
                    let mut bytes = transition(
                        Role::Writer,
                        MutationClass::WriterOpen,
                        0,
                        1,
                        (0, 1),
                        (0, 0),
                    );
                    bytes[4..6].copy_from_slice(&2u16.to_be_bytes());
                    bytes
                },
                |e| matches!(e, TransitionError::UnsupportedVersion { version: 2 }),
            ),
            (
                "unknown role fails closed",
                manifest_path(1),
                {
                    let mut bytes = transition(
                        Role::Writer,
                        MutationClass::WriterOpen,
                        0,
                        1,
                        (0, 1),
                        (0, 0),
                    );
                    bytes[6] = 9;
                    bytes
                },
                |e| matches!(e, TransitionError::UnknownRole { role: 9 }),
            ),
            (
                "unknown class fails closed",
                manifest_path(1),
                {
                    let mut bytes = transition(
                        Role::Writer,
                        MutationClass::WriterOpen,
                        0,
                        1,
                        (0, 1),
                        (0, 0),
                    );
                    bytes[7] = 7;
                    bytes
                },
                |e| matches!(e, TransitionError::UnknownClass { class: 7 }),
            ),
            (
                "malformed manifest file name",
                ObjectPath::from("spike-db/manifest/not-a-number.manifest"),
                transition(
                    Role::Writer,
                    MutationClass::WriterOpen,
                    0,
                    1,
                    (0, 1),
                    (0, 0),
                ),
                |e| matches!(e, TransitionError::MalformedManifestName),
            ),
            (
                "oversized numeric name (u64 overflow) fails closed",
                ObjectPath::from("spike-db/manifest/99999999999999999999999999.manifest"),
                transition(
                    Role::Writer,
                    MutationClass::WriterOpen,
                    0,
                    1,
                    (0, 1),
                    (0, 0),
                ),
                |e| matches!(e, TransitionError::MalformedManifestName),
            ),
            (
                "path id != envelope target",
                manifest_path(4),
                transition(
                    Role::Writer,
                    MutationClass::WriterOpen,
                    0,
                    1,
                    (0, 1),
                    (0, 0),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::PathIdMismatch {
                            path_id: 4,
                            target: 1
                        }
                    )
                },
            ),
        ];

        for (name, path, bytes, want) in cases {
            let refused = publish(&gateway, &path, bytes).await;
            let err = refused
                .err()
                .unwrap_or_else(|| panic!("case must refuse: {name}"));
            assert_refused(
                &err,
                |r| matches!(r, FirewallRefusal::ManifestTransitionRejected { error, .. } if want(error)),
            );
            assert!(
                raw_bytes(&harness.remote, &path).await.is_none(),
                "a refused publication must leave no bytes: {name}"
            );
            assert_eq!(
                harness.control.attested(),
                AttestedManifest::default(),
                "a refused publication must not advance attested state: {name}"
            );
        }
    }

    /// Semantic refusals against the attested state: wrong base, wrong
    /// (stale) epoch, wrong role, an ACTIVE publication smuggling an epoch
    /// change, a compactor touching the writer epoch, self-reopen, and a
    /// stale reopen replaying an already-superseded writer epoch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_base_epoch_role_self_reopen_and_stale_reopen_are_refused() {
        let harness = Harness::new();
        let gateway = harness.strict_handle(1);

        // establish attested state: manifest 1, writer epoch 1
        publish(
            &gateway,
            &manifest_path(1),
            transition(
                Role::Writer,
                MutationClass::WriterOpen,
                0,
                1,
                (0, 1),
                (0, 0),
            ),
        )
        .await
        .expect("writer-open");
        // and a second writer takeover: writer epoch 2
        publish(
            &gateway,
            &manifest_path(2),
            transition(
                Role::Writer,
                MutationClass::WriterOpen,
                1,
                2,
                (1, 2),
                (0, 0),
            ),
        )
        .await
        .expect("second writer-open");
        let attested = harness.control.attested();
        assert_eq!((attested.manifest_id, attested.writer_epoch), (2, 2));

        let cases: Vec<(&str, u64, Vec<u8>, fn(&TransitionError) -> bool)> = vec![
            (
                "wrong base manifest id",
                3,
                transition(
                    Role::Writer,
                    MutationClass::WriterOpen,
                    1,
                    3,
                    (2, 3),
                    (0, 0),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::WrongBaseManifest {
                            attested: 2,
                            base: 1
                        }
                    )
                },
            ),
            (
                "target is not the successor of base",
                4,
                transition(
                    Role::Writer,
                    MutationClass::WriterOpen,
                    2,
                    4,
                    (2, 3),
                    (0, 0),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::TargetNotSuccessor { base: 2, target: 4 }
                    )
                },
            ),
            (
                "stale reopen: replays writer epoch 1, attested is 2",
                3,
                transition(
                    Role::Writer,
                    MutationClass::WriterOpen,
                    2,
                    3,
                    (1, 3),
                    (0, 0),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::StaleWriterEpoch {
                            attested: 2,
                            old: 1
                        }
                    )
                },
            ),
            (
                "self-reopen: writer-open that does not increase the epoch",
                3,
                transition(
                    Role::Writer,
                    MutationClass::WriterOpen,
                    2,
                    3,
                    (2, 2),
                    (0, 0),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::WriterEpochNotIncreased { old: 2, new: 2 }
                    )
                },
            ),
            (
                "wrong role: compactor authoring a writer-open",
                3,
                transition(
                    Role::Compactor,
                    MutationClass::WriterOpen,
                    2,
                    3,
                    (2, 3),
                    (0, 0),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::RoleClassMismatch {
                            role: Role::Compactor,
                            class: MutationClass::WriterOpen
                        }
                    )
                },
            ),
            (
                "ACTIVE publication smuggling a writer-epoch change",
                3,
                transition(
                    Role::Writer,
                    MutationClass::ActivePublication,
                    2,
                    3,
                    (2, 3),
                    (0, 0),
                ),
                |e| matches!(e, TransitionError::EpochChangedOnActivePublication),
            ),
            (
                "compactor-open touching the writer epoch",
                3,
                transition(
                    Role::Compactor,
                    MutationClass::CompactorOpen,
                    2,
                    3,
                    (2, 3),
                    (0, 1),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::WriterEpochChangedByCompactor { old: 2, new: 3 }
                    )
                },
            ),
            (
                "compactor-open that does not increase the compactor epoch",
                3,
                transition(
                    Role::Compactor,
                    MutationClass::CompactorOpen,
                    2,
                    3,
                    (2, 2),
                    (0, 0),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::CompactorEpochNotIncreased { old: 0, new: 0 }
                    )
                },
            ),
            (
                "stale compactor epoch in the envelope",
                3,
                transition(
                    Role::Compactor,
                    MutationClass::CompactorOpen,
                    2,
                    3,
                    (2, 2),
                    (5, 6),
                ),
                |e| {
                    matches!(
                        e,
                        TransitionError::StaleCompactorEpoch {
                            attested: 0,
                            old: 5
                        }
                    )
                },
            ),
        ];

        for (name, target, bytes, want) in cases {
            let path = manifest_path(target);
            let err = publish(&gateway, &path, bytes)
                .await
                .err()
                .unwrap_or_else(|| panic!("case must refuse: {name}"));
            assert_refused(
                &err,
                |r| matches!(r, FirewallRefusal::ManifestTransitionRejected { error, .. } if want(error)),
            );
            assert!(
                raw_bytes(&harness.remote, &path).await.is_none(),
                "refused transition must leave no bytes: {name}"
            );
            let after = harness.control.attested();
            assert_eq!(
                (after.manifest_id, after.writer_epoch, after.compactor_epoch),
                (2, 2, 0),
                "refused transition must not advance attested state: {name}"
            );
        }

        // the state still accepts the CORRECT next transition
        publish(
            &gateway,
            &manifest_path(3),
            transition(
                Role::Writer,
                MutationClass::ActivePublication,
                2,
                3,
                (2, 2),
                (0, 0),
            ),
        )
        .await
        .expect("valid successor transition still admitted");
    }
}
