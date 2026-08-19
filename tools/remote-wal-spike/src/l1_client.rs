//! L1 remote-WAL client: the CURRENT control-plane Worker protocol
//! (`control-plane/src/controller/worker-entry.ts`) spoken over real HTTP to
//! workerd (`wrangler dev`), payloads travelling through the (local) R2 data
//! path. Rewritten for audit C-P0-01: the previous client spoke a retired
//! protocol (caller-chosen keys, caller-supplied request digests, numeric
//! u64s, caller-named scan bounds).
//!
//! Protocol facts this client encodes:
//!   - every route except `/health` and `POST /capability` requires a
//!     controller-issued capability in `x-capability`; issuance itself is
//!     credentialed via `x-issuer-authorization` (Q-02). Tokens are
//!     SINGLE-REQUEST: the nonce is bound at first use to the exact request,
//!     so this client mints one token per request and never reuses one - an
//!     identical caller-driven retry simply mints a fresh token and relies
//!     on operation-identity idempotency at the authority.
//!   - payload keys are ISSUER-DERIVED and content-addressed
//!     (`p/<databaseId>/<sha256hex>`): the key comes back from issuance for
//!     `PUT_PAYLOAD`, and this client refuses a non-canonical one rather
//!     than uploading under it.
//!   - the finalize dedupe digest is SERVER-derived (Q-18): no
//!     `requestDigest` field exists on the wire request.
//!   - sequence values are exact u64s carried as CANONICAL decimal strings
//!     (F7): JSON numbers and aliases like "00" are typed decode errors,
//!     never coercions - there is no 2^53 cliff in this client.
//!   - scan pages are bounded by a SERVER-owned snapshot: `snapshotId` from
//!     `POST /wal/{db}/{gen}/iterator`; the client never names `throughLsn`.
//!   - capability methods are a CLOSED registry with MANDATORY per-method
//!     restrictions (R4-SEC-03/04/05): WAL_FINALIZE and WAL_READ tokens bind
//!     the exact session AND generation (issuance body carries `generation`
//!     as a JSON number; the token binds the canonical decimal string), and
//!     each session-lifecycle transition is its own exact method naming its
//!     target actor - the generic SESSION_ADMIN bearer method no longer
//!     exists. This client threads every restriction explicitly and never
//!     defaults or zero-fills one it was not given.
//!
//! Every refusal is a typed outcome, nothing here panics on wire input, and
//! all retry loops are bounded.

use serde::{Deserialize, Deserializer, Serialize};

use crate::{hex, sha256};

/// The local-dev issuer credential (`control-plane/src/controller/core/
/// key-config.ts` DEV_ISSUER_SECRET). Scaffolding for the L1 lane only:
/// managed deployments refuse this constant outright.
pub const DEV_ISSUER_SECRET: &str = "dev-insecure-issuer-secret";

#[derive(Debug)]
pub enum L1Error {
    /// transport failed; the operation's outcome is unknown
    Http(String),
    /// the server refused or answered outside the route's success shape
    Protocol { status: u16, body: String },
    /// the response did not decode as the protocol shape (includes any
    /// non-canonical u64 encoding - exactness is part of the contract)
    Decode(String),
    /// capability issuance was refused or returned a malformed grant
    Issuance { status: u16, body: String },
    /// a session/generation-bound capability was requested while the client
    /// holds no bound actor: the caller must register (or `bind_actor`) the
    /// exact session and generation first - there is deliberately no default
    /// and no zero fallback for either field (R4-SEC-05)
    ActorUnbound,
}

impl std::fmt::Display for L1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L1Error::Http(e) => write!(f, "transport: {e}"),
            L1Error::Protocol { status, body } => write!(f, "protocol refusal ({status}): {body}"),
            L1Error::Decode(e) => write!(f, "decode: {e}"),
            L1Error::Issuance { status, body } => write!(f, "capability issuance ({status}): {body}"),
            L1Error::ActorUnbound => {
                write!(f, "no bound actor (session + generation): register_session or bind_actor first")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Exact u64 wire codec (F7): canonical decimal strings, full range.
// ---------------------------------------------------------------------------

/// Parse a canonical decimal-string u64: `0`, or a nonzero digit followed by
/// digits. Aliases ("00", "01"), signs, floats, and overflow are errors -
/// one value has one encoding (audit C-P1-02).
pub fn parse_wire_u64(raw: &str) -> Result<u64, String> {
    let bytes = raw.as_bytes();
    let canonical = match bytes {
        [b'0'] => true,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
        [] => false,
    };
    if !canonical {
        return Err(format!("{raw:?} is not a canonical decimal u64"));
    }
    raw.parse::<u64>().map_err(|_| format!("{raw:?} outside u64 range"))
}

/// A sequence value on the wire is a STRING; a JSON number here is a client/
/// server drift bug surfaced as a typed decode error, never a rounded read.
fn de_wire_u64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let raw = String::deserialize(deserializer)?;
    parse_wire_u64(&raw).map_err(serde::de::Error::custom)
}

fn de_wire_u64_opt<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    let raw: Option<String> = Option::deserialize(deserializer)?;
    raw.map(|s| parse_wire_u64(&s).map_err(serde::de::Error::custom)).transpose()
}

/// A physical WAL position: the empty head is `"-1"` on the wire (the SQL
/// lane's `COALESCE(MAX(append_lsn), -1)`), every other value is a u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalPosition {
    Empty,
    At(u64),
}

impl<'de> Deserialize<'de> for WalPosition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw == "-1" {
            return Ok(WalPosition::Empty);
        }
        parse_wire_u64(&raw).map(WalPosition::At).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Strict base64 (standard alphabet, mandatory padding): payload bytes come
// back base64-inline on the read paths; a malformed encoding is a typed
// decode error. Local implementation keeps the crate dependency-light.
// ---------------------------------------------------------------------------

pub fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    fn value_of(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 byte {c:#04x}")),
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(format!("base64 length {} is not a multiple of 4", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || chunk[..4 - pad].contains(&b'=') {
            return Err("misplaced base64 padding".into());
        }
        let mut acc = 0u32;
        for &c in &chunk[..4 - pad] {
            acc = (acc << 6) | value_of(c)?;
        }
        acc <<= 6 * pad as u32;
        let produced = 3 - pad;
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + produced]);
    }
    Ok(out)
}

/// Percent-encode a value for a URL path, preserving `/` (object keys are
/// slash-structured path suffixes on the payload route).
fn encode_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Wire shapes.
// ---------------------------------------------------------------------------

/// Capability method names, exactly as the worker's CLOSED method registry
/// spells them (`core/capability.ts` REQUIRED_RESTRICTIONS). R4-SEC-04
/// retired the generic SESSION_ADMIN bearer method: each lifecycle
/// transition this client performs is its own exact action, and issuance
/// refuses any name outside the registry with CAPABILITY_METHOD_UNKNOWN.
/// Only the methods this client actually mints are spelled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityMethod {
    /// legacy register/rollover macro (dev-only route); binds session + generation
    SessionRegister,
    /// actor-wide fence; binds the target session only
    SessionFence,
    /// budget installation; binds the acting session
    BudgetsSet,
    WalFinalize,
    WalRead,
    PutPayload,
}

impl CapabilityMethod {
    fn wire(self) -> &'static str {
        match self {
            CapabilityMethod::SessionRegister => "SESSION_REGISTER",
            CapabilityMethod::SessionFence => "SESSION_FENCE",
            CapabilityMethod::BudgetsSet => "BUDGETS_SET",
            CapabilityMethod::WalFinalize => "WAL_FINALIZE",
            CapabilityMethod::WalRead => "WAL_READ",
            CapabilityMethod::PutPayload => "PUT_PAYLOAD",
        }
    }
}

/// Restrictions a mint request carries. Which of these a method REQUIRES is
/// the issuer's closed registry (REQUIRED_RESTRICTIONS): a mint missing a
/// required one is refused with CAPABILITY_RESTRICTION_MISSING - absence is
/// never a wider token. `Default` spells "no restriction requested"; it is
/// NOT a fallback value for a required field (there is no zero-generation
/// default anywhere in this client).
#[derive(Debug, Clone, Copy, Default)]
pub struct MintRestrictions<'a> {
    /// the startup session the token authorizes (the exact actor)
    pub session: Option<&'a str>,
    /// the exact generation the token authorizes; a JSON NUMBER on the
    /// issuance wire, bound into the token as a canonical decimal string
    pub generation: Option<u64>,
    /// sha256 hex of the payload body (PUT_PAYLOAD)
    pub digest: Option<&'a str>,
    /// byte budget (PUT_PAYLOAD)
    pub max_bytes: Option<u64>,
}

/// One issued grant. `key` is present only for `PUT_PAYLOAD` - the
/// issuer-derived content-addressed object key the token is bound to.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuedCapability {
    pub token: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SequencingKind {
    #[serde(rename = "SEQUENCED")]
    Sequenced,
    #[serde(rename = "UNSEQUENCED")]
    Unsequenced,
}

/// `POST /wal/finalize` body. No `requestDigest`: the replay/dedupe digest
/// is recomputed server-side from the canonical request (Q-18); a
/// caller-supplied digest is at best redundant and at worst a forgery vector.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeHttpRequest {
    pub database_id: String,
    pub generation: u64,
    pub startup_session_id: String,
    pub operation_id: String,
    pub sequencing_kind: SequencingKind,
    /// TypeDB durability record type (u8) - catalogued server-side so
    /// type-filtered replay is an index scan, not a payload fetch per record.
    pub record_type: u8,
    pub logical_key: Option<String>,
    /// MUST be the canonical `p/<databaseId>/<payloadDigest>` from the
    /// upload receipt; anything else is a 400 NON_CANONICAL_PAYLOAD_KEY.
    pub payload_key: String,
    pub payload_digest: String,
    pub payload_length: u64,
}

impl FinalizeHttpRequest {
    /// Bind the three payload fields to ONE upload receipt - hand-pairing a
    /// key with another payload's length is how receipts drift.
    pub fn payload_from(&mut self, receipt: &UploadReceipt) {
        self.payload_key = receipt.key.clone();
        self.payload_digest = receipt.digest.clone();
        self.payload_length = receipt.length;
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeHttpOutcome {
    pub ok: bool,
    #[serde(default, deserialize_with = "de_wire_u64_opt")]
    pub append_lsn: Option<u64>,
    #[serde(default, deserialize_with = "de_wire_u64_opt")]
    pub type_sequence: Option<u64>,
    #[serde(default, deserialize_with = "de_wire_u64_opt")]
    pub control_seq: Option<u64>,
    #[serde(default)]
    pub replayed: Option<bool>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Receipt for one uploaded payload: the issuer-derived canonical key plus
/// the digest/length the client computed and the server confirmed.
#[derive(Debug, Clone)]
pub struct UploadReceipt {
    pub key: String,
    pub digest: String,
    pub length: u64,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct UploadWireOutcome {
    // success shape carries no `ok`; refusals carry `ok:false` + `error`
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    sha256hex: Option<String>,
    // a JS `byteLength`, encoded as a JSON number (not a sequence value)
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    deduplicated: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactReadOutcome {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub payload_key: Option<String>,
    #[serde(default)]
    pub payload_digest: Option<String>,
    #[serde(default, deserialize_with = "de_wire_u64_opt")]
    pub type_sequence: Option<u64>,
    #[serde(default)]
    pub record_type: Option<u8>,
    #[serde(default)]
    pub payload_base64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadOutcome {
    pub ok: bool,
    pub head_lsn: WalPosition,
    #[serde(deserialize_with = "de_wire_u64")]
    pub head_type_sequence: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IteratorOutcome {
    pub ok: bool,
    pub head_lsn: WalPosition,
    /// Opaque server-owned snapshot cut; the only way to bound a scan.
    pub snapshot_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRecord {
    #[serde(deserialize_with = "de_wire_u64")]
    pub append_lsn: u64,
    #[serde(deserialize_with = "de_wire_u64")]
    pub type_sequence: u64,
    pub sequencing_kind: String,
    pub record_type: u8,
    pub payload_key: String,
    pub payload_digest: String,
    pub payload_length: u64,
    pub logical_key: Option<String>,
    pub payload_base64: String,
}

/// Parameters of one `/scan` page request. The cut is the server-minted
/// `snapshot_id`; there is deliberately no way to express `throughLsn`.
#[derive(Debug, Clone)]
pub struct ScanQuery<'a> {
    pub snapshot_id: &'a str,
    pub from_ts: u64,
    pub from_lsn: u64,
    pub record_type: Option<u8>,
    pub limit: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOutcome {
    pub ok: bool,
    #[serde(default)]
    pub records: Vec<ScanRecord>,
    #[serde(default, deserialize_with = "de_wire_u64_opt")]
    pub next_from_lsn: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastOutcome {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub record: Option<ScanRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditOutcome {
    pub ok: bool,
    pub contiguous: bool,
    pub count: u64,
    pub max_lsn: WalPosition,
}

#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    pub max_unpublished_outbox: u64,
    pub max_payload_length: u64,
    pub max_tail_records: u64,
}

// ---------------------------------------------------------------------------
// Client.
// ---------------------------------------------------------------------------

pub struct L1Client {
    base: String,
    principal: String,
    issuer_secret: String,
    agent: ureq::Agent,
    /// The bound actor: the startup session this client operates as, plus
    /// the EXACT generation that session currently holds authority in.
    /// WAL_READ tokens are minted for this pair (R4-SEC-05: runtime reads
    /// are actor-bound and revalidated live at use time). `None` until the
    /// caller registers or binds - a read before that is a typed
    /// `ActorUnbound` refusal, never a defaulted or zero-filled mint.
    actor: std::sync::Mutex<Option<(String, u64)>>,
}

impl L1Client {
    pub fn new(base: impl Into<String>, principal: impl Into<String>, issuer_secret: impl Into<String>) -> Self {
        // 4xx/5xx are typed protocol outcomes here (409 conflict, 422 data-
        // path rejection, 404 exact miss) - never transport errors
        let config = ureq::config::Config::builder().http_status_as_error(false).build();
        Self {
            base: base.into(),
            principal: principal.into(),
            issuer_secret: issuer_secret.into(),
            agent: config.new_agent(),
            actor: std::sync::Mutex::new(None),
        }
    }

    /// Bind the actor identity this client mints read tokens for: the
    /// startup session and the exact generation it currently operates
    /// under. `register_session` re-binds this on every successful
    /// (re-)registration, so after a rollover the client's read authority
    /// follows the session's CURRENT generation - exactly like its commit
    /// authority does at the controller.
    pub fn bind_actor(&self, session: &str, generation: u64) {
        *self.actor.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((session.to_string(), generation));
    }

    /// The bound (session, generation) pair, or the typed refusal. No
    /// default and no zero fallback: an unbound actor cannot mint an
    /// actor-bound capability.
    fn actor(&self) -> Result<(String, u64), L1Error> {
        self.actor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(L1Error::ActorUnbound)
    }

    pub fn health(&self) -> Result<(), L1Error> {
        let mut response =
            self.agent.get(format!("{}/health", self.base)).call().map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let body: serde_json::Value = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if status == 200 && body["ok"] == serde_json::Value::Bool(true) {
            Ok(())
        } else {
            Err(L1Error::Protocol { status, body: body.to_string() })
        }
    }

    /// Mint ONE capability (`POST /capability`, credentialed issuance). Each
    /// request needs its own token - the authority binds the nonce to the
    /// first request it authorizes. Every restriction the method REQUIRES
    /// (issuer's REQUIRED_RESTRICTIONS registry) must ride in the mint or
    /// issuance refuses with CAPABILITY_RESTRICTION_MISSING; `generation`
    /// travels as a JSON NUMBER here and is bound into the token as a
    /// canonical decimal string. Public so contract tests can probe the
    /// issuer's refusal matrix directly (e.g. a mint that omits the
    /// generation a finalize token must carry).
    pub fn issue(
        &self,
        database_id: &str,
        method: CapabilityMethod,
        restrict: MintRestrictions<'_>,
    ) -> Result<IssuedCapability, L1Error> {
        let mut spec = serde_json::json!({
            "principal": self.principal,
            "databaseId": database_id,
            "method": method.wire(),
            "ttlMs": 60_000,
        });
        if let Some(session) = restrict.session {
            spec["session"] = session.into();
        }
        if let Some(generation) = restrict.generation {
            spec["generation"] = generation.into();
        }
        if let Some(digest) = restrict.digest {
            spec["digest"] = digest.into();
        }
        if let Some(max_bytes) = restrict.max_bytes {
            spec["maxBytes"] = max_bytes.into();
        }
        let mut response = self
            .agent
            .post(format!("{}/capability", self.base))
            .header("x-issuer-authorization", &self.issuer_secret)
            .send_json(&spec)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        // Read TEXT first: a mint-time refusal is not always JSON (the local
        // lane surfaces the issuer's thrown CAPABILITY_RESTRICTION_MISSING /
        // CAPABILITY_METHOD_UNKNOWN as an error page), and the refusal
        // identity must survive into the typed Issuance error instead of
        // dying as a JSON decode error.
        let raw = response.body_mut().read_to_string().map_err(|e| L1Error::Http(e.to_string()))?;
        let body: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        if status != 200 || body["ok"] != serde_json::Value::Bool(true) {
            return Err(L1Error::Issuance { status, body: raw });
        }
        serde_json::from_value(body).map_err(|e| L1Error::Decode(format!("issuance grant: {e}")))
    }

    /// Capability-bearing POST where the only success shape is HTTP 200 with
    /// `{"ok": true}`. Anything else (non-200 status, `ok:false`, missing
    /// `ok`) is a typed protocol error: register/fence/budgets callers act
    /// on the *effect* having been applied, so silently accepting an error
    /// body would let a caller believe state exists that was never installed.
    /// Each lifecycle transition mints its OWN exact method (R4-SEC-04 - the
    /// generic SESSION_ADMIN bearer method no longer exists) carrying the
    /// restrictions that method requires.
    fn lifecycle_post(
        &self,
        database_id: &str,
        method: CapabilityMethod,
        restrict: MintRestrictions<'_>,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(), L1Error> {
        let cap = self.issue(database_id, method, restrict)?;
        let mut response = self
            .agent
            .post(format!("{}{}", self.base, path))
            .header("x-capability", &cap.token)
            .send_json(body)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let parsed: serde_json::Value =
            response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if status != 200 || parsed["ok"] != serde_json::Value::Bool(true) {
            return Err(L1Error::Protocol { status, body: parsed.to_string() });
        }
        Ok(())
    }

    /// Register (or, for the live actor, roll over) a startup session. The
    /// SESSION_REGISTER capability binds the exact target actor AND the
    /// exact generation (R4-SEC-04). On success the client re-binds its
    /// actor state to (session, generation): commit AND read authority
    /// follow the session's CURRENT generation, so after a rollover
    /// finalizing in the old one refuses with SESSION_GENERATION_MISMATCH
    /// and read tokens are minted for the new one.
    pub fn register_session(&self, database_id: &str, generation: u64, session: &str) -> Result<(), L1Error> {
        self.lifecycle_post(
            database_id,
            CapabilityMethod::SessionRegister,
            MintRestrictions { session: Some(session), generation: Some(generation), ..Default::default() },
            "/session/register",
            &serde_json::json!({ "databaseId": database_id, "generation": generation, "startupSessionId": session }),
        )?;
        self.bind_actor(session, generation);
        Ok(())
    }

    /// Fencing is actor-wide: it revokes this startup session's append
    /// authority across every generation it registered - so the
    /// SESSION_FENCE capability binds only the target session (the body's
    /// generation is wire compatibility, not authority scope).
    pub fn fence_session(&self, database_id: &str, generation: u64, session: &str) -> Result<(), L1Error> {
        self.lifecycle_post(
            database_id,
            CapabilityMethod::SessionFence,
            MintRestrictions { session: Some(session), ..Default::default() },
            "/session/fence",
            &serde_json::json!({ "databaseId": database_id, "generation": generation, "startupSessionId": session }),
        )
    }

    /// Install admission budgets (BUDGETS_SET, session-bound: the core
    /// revalidates that `session` is still the live actor). Without a
    /// validated budget row every finalize refuses
    /// (ADMISSION_REJECTED_NO_BUDGET) - missing budget means deny, never
    /// unlimited.
    pub fn set_budgets(&self, database_id: &str, session: &str, budgets: &Budgets) -> Result<(), L1Error> {
        self.lifecycle_post(
            database_id,
            CapabilityMethod::BudgetsSet,
            MintRestrictions { session: Some(session), ..Default::default() },
            "/budgets",
            &serde_json::json!({
                "databaseId": database_id,
                "maxUnpublishedOutbox": budgets.max_unpublished_outbox,
                "maxPayloadLength": budgets.max_payload_length,
                "maxTailRecords": budgets.max_tail_records,
            }),
        )
    }

    /// Upload one payload through the capability-bound data path. The key is
    /// ISSUER-DERIVED (`p/<databaseId>/<sha256hex>` for the body's digest);
    /// this client refuses to upload under any other shape, and refuses a
    /// receipt whose digest disagrees with what it hashed locally.
    pub fn upload_payload(&self, database_id: &str, bytes: &[u8]) -> Result<UploadReceipt, L1Error> {
        let digest = hex(&sha256(bytes));
        let cap = self.issue(
            database_id,
            CapabilityMethod::PutPayload,
            MintRestrictions { digest: Some(&digest), max_bytes: Some(bytes.len() as u64), ..Default::default() },
        )?;
        let canonical = format!("p/{database_id}/{digest}");
        let key = match cap.key {
            Some(key) if key == canonical => key,
            other => {
                return Err(L1Error::Decode(format!(
                    "issuer key {other:?} is not the canonical {canonical:?}; refusing to upload"
                )));
            }
        };
        let mut response = self
            .agent
            .put(format!("{}/payload/{}", self.base, encode_path(&key)))
            .header("x-capability", &cap.token)
            .send(bytes)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let raw: serde_json::Value = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if status != 200 {
            return Err(L1Error::Protocol { status, body: raw.to_string() });
        }
        let outcome: UploadWireOutcome =
            serde_json::from_value(raw.clone()).map_err(|e| L1Error::Decode(e.to_string()))?;
        match outcome {
            UploadWireOutcome { key: Some(k), sha256hex: Some(d), length: Some(l), deduplicated }
                if k == key && d == digest && l == bytes.len() as u64 =>
            {
                Ok(UploadReceipt { key, digest, length: l, deduplicated: deduplicated.unwrap_or(false) })
            }
            _ => Err(L1Error::Protocol { status, body: format!("upload receipt disagrees: {raw}") }),
        }
    }

    /// Finalize; NEVER treats transport failure as failure of the operation -
    /// the caller resolves ambiguity by re-invoking with the identical
    /// request under a fresh token (the controller replays the original
    /// allocation by operation identity).
    pub fn finalize(&self, request: &FinalizeHttpRequest) -> Result<(u16, FinalizeHttpOutcome), L1Error> {
        // the finalize capability is SESSION- AND GENERATION-bound (donor A3
        // + audit C-05, R4-SEC-03): the token carries the actor identity the
        // request claims and the EXACT generation it finalizes in - a token
        // minted for generation N is not write authority in N+1, and a mint
        // omitting either restriction is refused at issuance
        // (CAPABILITY_RESTRICTION_MISSING), before finalize is ever reached
        let cap = self.issue(
            &request.database_id,
            CapabilityMethod::WalFinalize,
            MintRestrictions {
                session: Some(&request.startup_session_id),
                generation: Some(request.generation),
                ..Default::default()
            },
        )?;
        let mut response = self
            .agent
            .post(format!("{}/wal/finalize", self.base))
            .header("x-capability", &cap.token)
            .send_json(request)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let outcome: FinalizeHttpOutcome =
            response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    /// One capability-bearing GET under a fresh ACTOR-BOUND WAL_READ token
    /// (R4-SEC-05): the token names the client's bound session AND the
    /// generation that session currently operates under - the session's
    /// CURRENT generation, which after a rollover differs from the path
    /// generation being read. The Worker revalidates live authority at use
    /// time, so a fenced/unknown session gets a typed 409 regardless of an
    /// unexpired token.
    fn read_get(&self, database_id: &str, path: &str, query: &[(&str, String)]) -> Result<ureq::http::Response<ureq::Body>, L1Error> {
        let (session, generation) = self.actor()?;
        let cap = self.issue(
            database_id,
            CapabilityMethod::WalRead,
            MintRestrictions { session: Some(&session), generation: Some(generation), ..Default::default() },
        )?;
        let mut request = self.agent.get(format!("{}{}", self.base, path)).header("x-capability", &cap.token);
        for (name, value) in query {
            request = request.query(*name, value);
        }
        request.call().map_err(|e| L1Error::Http(e.to_string()))
    }

    pub fn read_exact(&self, database_id: &str, generation: u64, lsn: u64) -> Result<(u16, ExactReadOutcome), L1Error> {
        let mut response = self.read_get(database_id, &format!("/wal/{database_id}/{generation}/{lsn}"), &[])?;
        let status = response.status().as_u16();
        let outcome = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    /// WAL head: highest AppendLsn AND highest TypeSequence (the durability
    /// client's `current()`/`previous()` need the latter).
    pub fn head(&self, database_id: &str, generation: u64) -> Result<HeadOutcome, L1Error> {
        let mut response = self.read_get(database_id, &format!("/wal/{database_id}/{generation}/head"), &[])?;
        let status = response.status().as_u16();
        if status != 200 {
            let body: serde_json::Value =
                response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
            return Err(L1Error::Protocol { status, body: body.to_string() });
        }
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }

    /// Pin a fixed iteration snapshot. The returned `snapshot_id` is the
    /// server-owned cut every subsequent `scan` page presents; pages of one
    /// logical iteration never observe later appends.
    pub fn open_iterator(&self, database_id: &str, generation: u64) -> Result<IteratorOutcome, L1Error> {
        // same actor-bound WAL_READ mint as read_get: session + the actor's
        // CURRENT generation (R4-SEC-05), never an unbound reader
        let (session, actor_generation) = self.actor()?;
        let cap = self.issue(
            database_id,
            CapabilityMethod::WalRead,
            MintRestrictions { session: Some(&session), generation: Some(actor_generation), ..Default::default() },
        )?;
        let mut response = self
            .agent
            .post(format!("{}/wal/{database_id}/{generation}/iterator", self.base))
            .header("x-capability", &cap.token)
            .send_json(serde_json::json!({}))
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        if status != 200 {
            let body: serde_json::Value =
                response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
            return Err(L1Error::Protocol { status, body: body.to_string() });
        }
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }

    /// One ordered replay page (physical order, `type_sequence >= from_ts`,
    /// bounded by the pinned snapshot), payloads inline and digest-verified
    /// server-side. Follow `next_from_lsn` until `None`.
    pub fn scan(&self, database_id: &str, generation: u64, query: &ScanQuery<'_>) -> Result<(u16, ScanOutcome), L1Error> {
        let mut params = vec![
            ("snapshotId", query.snapshot_id.to_string()),
            ("fromTs", query.from_ts.to_string()),
            ("fromLsn", query.from_lsn.to_string()),
            ("limit", query.limit.to_string()),
        ];
        if let Some(record_type) = query.record_type {
            params.push(("recordType", record_type.to_string()));
        }
        let mut response = self.read_get(database_id, &format!("/wal/{database_id}/{generation}/scan"), &params)?;
        let status = response.status().as_u16();
        let outcome = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    /// Last record of a type in physical order (`find_last_type`); a miss is
    /// a typed 404 outcome, never EOF.
    pub fn last_by_type(
        &self,
        database_id: &str,
        generation: u64,
        record_type: u8,
    ) -> Result<(u16, LastOutcome), L1Error> {
        let mut response = self.read_get(
            database_id,
            &format!("/wal/{database_id}/{generation}/last"),
            &[("recordType", record_type.to_string())],
        )?;
        let status = response.status().as_u16();
        let outcome = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    /// Contiguity audit over one generation's tail.
    pub fn audit(&self, database_id: &str, generation: u64) -> Result<AuditOutcome, L1Error> {
        let mut response = self.read_get(database_id, &format!("/wal/{database_id}/{generation}/audit"), &[])?;
        let status = response.status().as_u16();
        if status != 200 {
            let body: serde_json::Value =
                response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
            return Err(L1Error::Protocol { status, body: body.to_string() });
        }
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_u64_accepts_only_canonical_decimals_over_the_full_range() {
        assert_eq!(parse_wire_u64("0"), Ok(0));
        assert_eq!(parse_wire_u64("7"), Ok(7));
        // full u64 range - a f64/2^53 lane would round this
        assert_eq!(parse_wire_u64("18446744073709551615"), Ok(u64::MAX));
        for alias in ["", "00", "01", "007", "+1", "-1", "1.5", "1e3", " 1", "18446744073709551616"] {
            assert!(parse_wire_u64(alias).is_err(), "{alias:?} must be refused");
        }
    }

    #[test]
    fn json_numbers_are_never_accepted_where_the_wire_says_string() {
        // the server encodes every sequence as a decimal string; a numeric
        // appendLsn is drift, surfaced as a decode error - not a rounded read
        let numeric = serde_json::json!({ "ok": true, "appendLsn": 0, "replayed": false });
        assert!(serde_json::from_value::<FinalizeHttpOutcome>(numeric).is_err());
        let canonical = serde_json::json!({ "ok": true, "appendLsn": "18446744073709551615", "replayed": false });
        let decoded = serde_json::from_value::<FinalizeHttpOutcome>(canonical).unwrap();
        assert_eq!(decoded.append_lsn, Some(u64::MAX));
    }

    #[test]
    fn wal_position_decodes_the_empty_head() {
        assert_eq!(serde_json::from_value::<WalPosition>("-1".into()).unwrap(), WalPosition::Empty);
        assert_eq!(serde_json::from_value::<WalPosition>("3".into()).unwrap(), WalPosition::At(3));
        assert!(serde_json::from_value::<WalPosition>("-2".into()).is_err());
        assert!(serde_json::from_value::<WalPosition>(serde_json::json!(3)).is_err());
    }

    #[test]
    fn base64_decodes_strictly() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
        assert_eq!(base64_decode("Y29tbWl0LXJlY29yZC0x").unwrap(), b"commit-record-1");
        for bad in ["Y", "Y===", "=YWJ", "YW Jj", "YWJj!"] {
            assert!(base64_decode(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn payload_path_encoding_preserves_key_structure() {
        assert_eq!(encode_path("p/db-1/abc"), "p/db-1/abc");
        assert_eq!(encode_path("p/d b%/x"), "p/d%20b%25/x");
    }
}
