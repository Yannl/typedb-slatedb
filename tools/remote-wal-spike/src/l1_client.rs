//! L1 remote-WAL client: the CURRENT control-plane Worker protocol
//! (`control-plane/src/controller/worker-entry.ts`) spoken over real HTTP to
//! workerd (`wrangler dev`), payloads travelling through the (local) R2 data
//! path. Reworked for R5-SEC-02: the client operates against the MANAGED
//! control-plane surface through the PRIVATE ISSUER path - no dev routes.
//!
//! Protocol facts this client encodes:
//!   - the client is a pure BEARER of issuer-granted schema-v3 Ed25519
//!     tokens: it holds NO signing material and constructs NO tokens. Every
//!     capability - the internal PROVISION capability included - is obtained
//!     over HTTP from the private issuer (`control-plane/scripts/issuer.mjs`
//!     startIssuerServer: loopback-only, bearer-authenticated,
//!     `POST /issue {spec} -> {token}`, `POST /provision-token {binding} ->
//!     {token}`). The managed worker surface deliberately has NO issuance
//!     route (`/capability` is dev-only and answers 404 there), and the
//!     managed runtime holds only PUBLIC verification keys (R5-SEC-03), so
//!     this bearer topology is the only one that can work in production.
//!   - tokens are SINGLE-REQUEST: the nonce is bound at first use to the
//!     exact request, so this client requests one token per request and
//!     never reuses one - an identical caller-driven retry simply obtains a
//!     fresh token and relies on operation-identity idempotency at the
//!     authority.
//!   - session lifecycle is the production reserve -> attest -> activate
//!     protocol (R4-SEC-04 exact per-action capabilities; ONLY activation
//!     fences). The legacy one-call `/session/register` macro and the
//!     `/session/fence` + `/budgets` admin routes are dev-only and absent
//!     from the managed surface; admission budgets ride the provisioning
//!     transaction instead (`POST /provision`).
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
//!     restrictions (R4-SEC-03/04/05) enforced at the ISSUER (the real
//!     `core/issuer.ts` mintCapabilityToken refuses an under-restricted
//!     spec with CAPABILITY_RESTRICTION_MISSING before any token exists)
//!     and re-enforced by the worker's verifier. WAL_FINALIZE and WAL_READ
//!     tokens bind the exact session AND generation (issuance spec carries
//!     `generation` as a JSON number; the token binds the canonical decimal
//!     string). This client threads every restriction explicitly and never
//!     defaults or zero-fills one it was not given.
//!
//! Every refusal is a typed outcome, nothing here panics on wire input, and
//! all retry loops are bounded.

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    hex,
    l1_stream::{
        self, IntegrityFault, PayloadSource, RecordMeta, ReplayBounds, ReplayReport, SpoolPolicy, StreamError,
        StreamOptions, VerifiedPayload, VerifyingReader, MAX_RECORD_BYTES, MAX_SCAN_PAGE_BYTES, MAX_SCAN_PAGE_RECORDS,
        PAYLOAD_STREAM_MEDIA_TYPE,
    },
    sha256,
};

#[derive(Debug)]
pub enum L1Error {
    /// transport failed; the operation's outcome is unknown
    Http(String),
    /// the server refused or answered outside the route's success shape
    Protocol { status: u16, body: String },
    /// the response did not decode as the protocol shape (includes any
    /// non-canonical u64 encoding - exactness is part of the contract)
    Decode(String),
    /// the private issuer refused issuance (or answered a malformed grant)
    Issuance { status: u16, body: String },
    /// a session/generation-bound capability was requested while the client
    /// holds no bound actor: the caller must activate (or `bind_actor`) the
    /// exact session and generation first - there is deliberately no default
    /// and no zero fallback for either field (R4-SEC-05)
    ActorUnbound,
    /// R6-PERF-01: a streaming transfer was refused. NOTHING was applied,
    /// nothing was acknowledged, and every byte the transfer had already
    /// absorbed was destroyed with the spool that held it.
    Stream(StreamError),
}

impl From<StreamError> for L1Error {
    fn from(error: StreamError) -> L1Error {
        L1Error::Stream(error)
    }
}

impl std::fmt::Display for L1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L1Error::Http(e) => write!(f, "transport: {e}"),
            L1Error::Protocol { status, body } => write!(f, "protocol refusal ({status}): {body}"),
            L1Error::Decode(e) => write!(f, "decode: {e}"),
            L1Error::Issuance { status, body } => write!(f, "capability issuance ({status}): {body}"),
            L1Error::ActorUnbound => {
                write!(f, "no bound actor (session + generation): activate_session or bind_actor first")
            }
            L1Error::Stream(error) => write!(f, "streaming refusal: {error}"),
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
/// refuses any name outside the registry. Only the methods this client
/// actually requests are spelled here - in particular the dev-only
/// SESSION_REGISTER/SESSION_FENCE/BUDGETS_SET route methods are gone: the
/// managed lifecycle is reserve -> attest -> activate (+ renew), and
/// budgets ride provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityMethod {
    /// reserve a startup-session id (grants nothing; single-use per id)
    SessionReserve,
    /// bind the reservation to one process nonce (still grants nothing)
    SessionAttest,
    /// the ONE fencing transition: verified activation under a lease
    SessionActivate,
    /// heartbeat lease extension for the active/draining actor
    SessionRenew,
    WalFinalize,
    WalRead,
    PutPayload,
    /// session-independent recovery/forensics journal audit
    JournalVerify,
}

impl CapabilityMethod {
    fn wire(self) -> &'static str {
        match self {
            CapabilityMethod::SessionReserve => "SESSION_RESERVE",
            CapabilityMethod::SessionAttest => "SESSION_ATTEST",
            CapabilityMethod::SessionActivate => "SESSION_ACTIVATE",
            CapabilityMethod::SessionRenew => "SESSION_RENEW",
            CapabilityMethod::WalFinalize => "WAL_FINALIZE",
            CapabilityMethod::WalRead => "WAL_READ",
            CapabilityMethod::PutPayload => "PUT_PAYLOAD",
            CapabilityMethod::JournalVerify => "JOURNAL_VERIFY",
        }
    }
}

/// Restrictions an issuance request carries. Which of these a method
/// REQUIRES is the issuer's closed registry (REQUIRED_RESTRICTIONS): a
/// request missing a required one is refused at the issuer with
/// CAPABILITY_RESTRICTION_MISSING - absence is never a wider token.
/// `Default` spells "no restriction requested"; it is NOT a fallback value
/// for a required field (there is no zero-generation default anywhere in
/// this client).
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
    /// tenant override for adversarial probes (a forged cross-tenant claim);
    /// ordinary issuance omits it and receives the issuer's own tenant
    pub tenant_id: Option<&'a str>,
}

/// The typed issuance spec body for `POST /issue` - the exact field names
/// `scripts/issuer.mjs` reads. Kept a pure function so the spec encoding
/// (generation as a JSON NUMBER, absent restrictions truly absent) is
/// unit-testable without a live issuer.
pub fn issuance_spec(
    principal: &str,
    database_id: &str,
    method: CapabilityMethod,
    restrict: &MintRestrictions<'_>,
) -> serde_json::Value {
    let mut spec = serde_json::json!({
        "principal": principal,
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
    if let Some(tenant_id) = restrict.tenant_id {
        spec["tenantId"] = tenant_id.into();
    }
    spec
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

/// One record delivered by the STREAMING exact read. `payload` is the only
/// way bytes leave that path, and it exists only after the full digest and
/// length were proven.
#[derive(Debug)]
pub struct StreamedRead {
    pub meta: RecordMeta,
    pub payload: VerifiedPayload,
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
///
/// R6-PERF-01 bounded pagination: BOTH page axes are explicit and
/// client-validated against the authority's own ceilings
/// (`MAX_SCAN_PAGE_RECORDS`, `MAX_SCAN_PAGE_BYTES`). The Worker CLAMPS an
/// over-wide request silently; this client REFUSES it, because a caller
/// that believes it asked for 5000 records and quietly got 1000 will read
/// the missing 4000 as end-of-stream.
#[derive(Debug, Clone)]
pub struct ScanQuery<'a> {
    pub snapshot_id: &'a str,
    pub from_ts: u64,
    pub from_lsn: u64,
    pub record_type: Option<u8>,
    pub limit: u32,
    /// per-page payload byte budget (pre-base64). `None` lets the authority
    /// apply its own ceiling; `Some(n)` must be within it.
    pub max_bytes: Option<u64>,
}

impl ScanQuery<'_> {
    /// A page request with the crate's default bounds.
    pub fn new(snapshot_id: &str, from_lsn: u64, limit: u32) -> ScanQuery<'_> {
        ScanQuery { snapshot_id, from_ts: 0, from_lsn, record_type: None, limit, max_bytes: None }
    }

    /// Refuse - never clamp - an out-of-bounds page request.
    pub fn validate(&self) -> Result<(), StreamError> {
        if self.limit == 0 || self.limit > MAX_SCAN_PAGE_RECORDS {
            return Err(StreamError::Oversize {
                declared: u64::from(self.limit),
                limit: u64::from(MAX_SCAN_PAGE_RECORDS),
            });
        }
        if let Some(max_bytes) = self.max_bytes {
            if max_bytes == 0 || max_bytes > MAX_SCAN_PAGE_BYTES {
                return Err(StreamError::Oversize { declared: max_bytes, limit: MAX_SCAN_PAGE_BYTES });
            }
        }
        Ok(())
    }
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

/// Outcome of the provisioning transaction: `created` is true for the
/// binding write, false for an idempotent replay of the same binding.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionOutcome {
    pub created: bool,
}

/// Outcome of a verified activation (`POST /session/activate`): the
/// controller-time lease deadline and how many predecessor actors this
/// activation fenced - the ONE takeover mechanism on the managed surface.
#[derive(Debug, Clone, Copy)]
pub struct ActivationOutcome {
    pub lease_deadline_ms: u64,
    pub fenced_predecessors: u64,
}

/// `GET /journal/{db}/verify` verdict (F8): the server recomputes the whole
/// hash chain + MACs; `length` is the number of journaled commands.
#[derive(Debug, Clone, Copy)]
pub struct JournalOutcome {
    pub ok: bool,
    pub length: u64,
}

// ---------------------------------------------------------------------------
// Client.
// ---------------------------------------------------------------------------

/// Where the client gets authority from (the private issuer) and where it
/// spends it (the managed worker surface). The issuer bearer credential is
/// the client's ONLY credential: everything else is granted per-request.
#[derive(Debug, Clone)]
pub struct L1Config {
    /// managed control-plane worker base URL
    pub base: String,
    /// private issuer base URL (loopback sidecar locally; a private service
    /// binding in production topology)
    pub issuer_base: String,
    /// bearer credential the issuer authenticates issuance with
    pub issuer_bearer: String,
    /// principal name stamped into issued tokens (attribution)
    pub principal: String,
    /// the tenant this client provisions and operates databases under
    pub tenant_id: String,
}

pub struct L1Client {
    config: L1Config,
    agent: ureq::Agent,
    /// The bound actor: the startup session this client operates as, plus
    /// the EXACT generation that session currently holds authority in.
    /// WAL_READ tokens are requested for this pair (R4-SEC-05: runtime
    /// reads are actor-bound and revalidated live at use time). `None`
    /// until the caller activates or binds - a read before that is a typed
    /// `ActorUnbound` refusal, never a defaulted or zero-filled request.
    actor: std::sync::Mutex<Option<(String, u64)>>,
}

impl L1Client {
    pub fn new(config: L1Config) -> Self {
        // 4xx/5xx are typed protocol outcomes here (409 conflict, 422 data-
        // path rejection, 404 exact miss) - never transport errors
        let agent_config = ureq::config::Config::builder().http_status_as_error(false).build();
        Self { config, agent: agent_config.new_agent(), actor: std::sync::Mutex::new(None) }
    }

    /// Bind the actor identity this client requests read tokens for: the
    /// startup session and the exact generation it currently operates
    /// under. `activate_session` re-binds this on every successful
    /// activation, so after a takeover the client's read authority follows
    /// the session's CURRENT generation - exactly like its commit
    /// authority does at the controller.
    pub fn bind_actor(&self, session: &str, generation: u64) {
        *self.actor.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((session.to_string(), generation));
    }

    /// The bound (session, generation) pair, or the typed refusal. No
    /// default and no zero fallback: an unbound actor cannot request an
    /// actor-bound capability.
    fn actor(&self) -> Result<(String, u64), L1Error> {
        self.actor.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone().ok_or(L1Error::ActorUnbound)
    }

    pub fn health(&self) -> Result<(), L1Error> {
        let mut response =
            self.agent.get(format!("{}/health", self.config.base)).call().map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let body: serde_json::Value = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if status == 200 && body["ok"] == serde_json::Value::Bool(true) {
            Ok(())
        } else {
            Err(L1Error::Protocol { status, body: body.to_string() })
        }
    }

    /// One bearer-authenticated POST to the private issuer. The refusal
    /// body text is preserved verbatim in the typed Issuance error: the
    /// issuer's refusal identity (ISSUER_UNAUTHORIZED / ISSUE_SPEC_INVALID
    /// with its CAPABILITY_RESTRICTION_MISSING detail / INVALID_BINDING)
    /// is diagnostic surface, and it must survive rather than dying as a
    /// JSON decode error.
    fn issuer_post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, L1Error> {
        let mut response = self
            .agent
            .post(format!("{}{}", self.config.issuer_base, path))
            .header("authorization", format!("Bearer {}", self.config.issuer_bearer))
            .send_json(body)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let raw = response.body_mut().read_to_string().map_err(|e| L1Error::Http(e.to_string()))?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        if status != 200 || parsed["ok"] != serde_json::Value::Bool(true) {
            return Err(L1Error::Issuance { status, body: raw });
        }
        Ok(parsed)
    }

    /// Obtain ONE capability from the private issuer (`POST /issue`). Each
    /// request needs its own token - the authority binds the nonce to the
    /// first request it authorizes. Every restriction the method REQUIRES
    /// (the issuer's REQUIRED_RESTRICTIONS registry) must ride in the spec
    /// or issuance refuses with CAPABILITY_RESTRICTION_MISSING;
    /// `generation` travels as a JSON NUMBER here and is bound into the
    /// token as a canonical decimal string. Public so contract tests and
    /// the suite can probe the issuer's refusal matrix directly (e.g. a
    /// spec that omits the generation a finalize token must carry).
    pub fn issue(
        &self,
        database_id: &str,
        method: CapabilityMethod,
        restrict: MintRestrictions<'_>,
    ) -> Result<IssuedCapability, L1Error> {
        let spec = issuance_spec(&self.config.principal, database_id, method, &restrict);
        let body = self.issuer_post("/issue", &serde_json::json!({ "spec": spec }))?;
        serde_json::from_value(body).map_err(|e| L1Error::Decode(format!("issuance grant: {e}")))
    }

    /// Obtain the internal PROVISION capability for `(tenant, database)`
    /// from the issuer (`POST /provision-token`). The client BEARS the
    /// token; it cannot construct one - the provisioning-scope private key
    /// lives with the issuer alone (R5-SEC-03).
    pub fn provision_token(&self, database_id: &str) -> Result<String, L1Error> {
        let body = self.issuer_post(
            "/provision-token",
            &serde_json::json!({ "binding": {
                "tenantId": self.config.tenant_id, "databaseId": database_id,
            } }),
        )?;
        match body["token"].as_str() {
            Some(token) => Ok(token.to_string()),
            None => Err(L1Error::Decode(format!("provision grant without token: {body}"))),
        }
    }

    /// Provision the authority for this client's tenant + `database_id`
    /// through the production `/provision` route (R4 PR1) - the ONLY act
    /// that binds an uninitialized controller. Admission budgets ride the
    /// SAME transaction (the managed surface has no budget-admin route);
    /// provisioning without budgets leaves the database write-denying
    /// (Q-12: no budget row means deny, never unlimited). Success is
    /// `created: true`; an idempotent replay of the same binding answers
    /// `created: false` - NOTE a replay does not install budgets, so they
    /// must ride the first call. Everything else - forged scope,
    /// conflicting binding, malformed ids - is the typed refusal.
    pub fn provision(&self, database_id: &str, budgets: Option<&Budgets>) -> Result<ProvisionOutcome, L1Error> {
        let token = self.provision_token(database_id)?;
        self.provision_with_token(database_id, &token, budgets)
    }

    /// The worker half of provisioning under an explicitly supplied
    /// `x-provision` token. Public so adversarial checks can present the
    /// WRONG material (e.g. an ordinary capability-scope token) and pin the
    /// typed mint/verify-scope refusal.
    pub fn provision_with_token(
        &self,
        database_id: &str,
        provision_token: &str,
        budgets: Option<&Budgets>,
    ) -> Result<ProvisionOutcome, L1Error> {
        let mut body = serde_json::json!({
            "tenantId": self.config.tenant_id,
            "databaseId": database_id,
        });
        if let Some(budgets) = budgets {
            body["budgets"] = serde_json::json!({
                "maxUnpublishedOutbox": budgets.max_unpublished_outbox,
                "maxPayloadLength": budgets.max_payload_length,
                "maxTailRecords": budgets.max_tail_records,
            });
        }
        let mut response = self
            .agent
            .post(format!("{}/provision", self.config.base))
            .header("x-provision", provision_token)
            .send_json(&body)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let raw = response.body_mut().read_to_string().map_err(|e| L1Error::Http(e.to_string()))?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        if status != 200 || parsed["ok"] != serde_json::Value::Bool(true) {
            return Err(L1Error::Protocol { status, body: raw });
        }
        Ok(ProvisionOutcome { created: parsed["created"] == serde_json::Value::Bool(true) })
    }

    /// Capability-bearing POST where the only success shape is HTTP 200 with
    /// `{"ok": true}`; the parsed success body is returned for outcome
    /// fields (lease deadline, fenced count). Anything else (non-200
    /// status, `ok:false`, missing `ok`) is a typed protocol error:
    /// lifecycle callers act on the *effect* having been applied, so
    /// silently accepting an error body would let a caller believe state
    /// exists that was never installed. Each transition requests its OWN
    /// exact method (R4-SEC-04) carrying the restrictions that method
    /// requires.
    fn lifecycle_post(
        &self,
        database_id: &str,
        method: CapabilityMethod,
        restrict: MintRestrictions<'_>,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, L1Error> {
        let cap = self.issue(database_id, method, restrict)?;
        let mut response = self
            .agent
            .post(format!("{}{}", self.config.base, path))
            .header("x-capability", &cap.token)
            .send_json(body)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let parsed: serde_json::Value = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if status != 200 || parsed["ok"] != serde_json::Value::Bool(true) {
            return Err(L1Error::Protocol { status, body: parsed.to_string() });
        }
        Ok(parsed)
    }

    /// Reserve a startup-session id (`POST /session/reserve`). Grants
    /// nothing; ids are single-use identities, so a NEW actor always
    /// reserves a NEW id - the takeover/rollover path is a fresh
    /// reservation at the target generation, never reuse.
    pub fn reserve_session(
        &self,
        database_id: &str,
        generation: u64,
        session: &str,
        holder: &str,
    ) -> Result<(), L1Error> {
        self.lifecycle_post(
            database_id,
            CapabilityMethod::SessionReserve,
            MintRestrictions { session: Some(session), generation: Some(generation), ..Default::default() },
            "/session/reserve",
            &serde_json::json!({
                "databaseId": database_id, "generation": generation,
                "startupSessionId": session, "holder": holder,
            }),
        )?;
        Ok(())
    }

    /// Bind the reservation to this process (`POST /session/attest`). Still
    /// grants nothing; the nonce presented here must be re-presented at
    /// activation.
    pub fn attest_session(&self, database_id: &str, session: &str, process_nonce: &str) -> Result<(), L1Error> {
        self.lifecycle_post(
            database_id,
            CapabilityMethod::SessionAttest,
            MintRestrictions { session: Some(session), ..Default::default() },
            "/session/attest",
            &serde_json::json!({
                "databaseId": database_id, "startupSessionId": session, "processNonce": process_nonce,
            }),
        )?;
        Ok(())
    }

    /// The ONE transaction that authorizes takeover (`POST
    /// /session/activate`, 12.4): verified activation fences every
    /// predecessor and establishes this actor under a controller-time
    /// lease. On success the client re-binds its actor state to (session,
    /// generation): commit AND read authority follow the activated
    /// generation.
    pub fn activate_session(
        &self,
        database_id: &str,
        generation: u64,
        session: &str,
        process_nonce: &str,
        lease_ms: u64,
    ) -> Result<ActivationOutcome, L1Error> {
        let body = self.lifecycle_post(
            database_id,
            CapabilityMethod::SessionActivate,
            MintRestrictions { session: Some(session), generation: Some(generation), ..Default::default() },
            "/session/activate",
            &serde_json::json!({
                "databaseId": database_id, "generation": generation, "startupSessionId": session,
                "processNonce": process_nonce, "leaseMs": lease_ms,
            }),
        )?;
        let outcome = ActivationOutcome {
            lease_deadline_ms: body["leaseDeadlineMs"]
                .as_u64()
                .ok_or_else(|| L1Error::Decode(format!("activation without leaseDeadlineMs: {body}")))?,
            fenced_predecessors: body["fencedPredecessors"]
                .as_u64()
                .ok_or_else(|| L1Error::Decode(format!("activation without fencedPredecessors: {body}")))?,
        };
        self.bind_actor(session, generation);
        Ok(outcome)
    }

    /// Heartbeat lease extension (`POST /session/renew`); refuses once the
    /// lease already expired - expiry is terminal, renewal cannot resurrect.
    pub fn renew_session(&self, database_id: &str, session: &str, lease_ms: u64) -> Result<(), L1Error> {
        self.lifecycle_post(
            database_id,
            CapabilityMethod::SessionRenew,
            MintRestrictions { session: Some(session), ..Default::default() },
            "/session/renew",
            &serde_json::json!({
                "databaseId": database_id, "startupSessionId": session, "leaseMs": lease_ms,
            }),
        )?;
        Ok(())
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
            .put(format!("{}/payload/{}", self.config.base, encode_path(&key)))
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
        // issued for generation N is not write authority in N+1, and a spec
        // omitting either restriction is refused at the issuer
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
            .post(format!("{}/wal/finalize", self.config.base))
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
    /// CURRENT generation, which after a takeover differs from the path
    /// generation being read. The Worker revalidates live authority at use
    /// time, so a fenced/unknown session gets a typed 409 regardless of an
    /// unexpired token.
    fn read_get(
        &self,
        database_id: &str,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<ureq::http::Response<ureq::Body>, L1Error> {
        let (session, generation) = self.actor()?;
        let cap = self.issue(
            database_id,
            CapabilityMethod::WalRead,
            MintRestrictions { session: Some(&session), generation: Some(generation), ..Default::default() },
        )?;
        let mut request = self.agent.get(format!("{}{}", self.config.base, path)).header("x-capability", &cap.token);
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
        // same actor-bound WAL_READ request as read_get: session + the
        // actor's CURRENT generation (R4-SEC-05), never an unbound reader
        let (session, actor_generation) = self.actor()?;
        let cap = self.issue(
            database_id,
            CapabilityMethod::WalRead,
            MintRestrictions { session: Some(&session), generation: Some(actor_generation), ..Default::default() },
        )?;
        let mut response = self
            .agent
            .post(format!("{}/wal/{database_id}/{generation}/iterator", self.config.base))
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
    pub fn scan(
        &self,
        database_id: &str,
        generation: u64,
        query: &ScanQuery<'_>,
    ) -> Result<(u16, ScanOutcome), L1Error> {
        // bounded pagination is enforced BEFORE the request leaves: an
        // over-wide page is a typed client refusal, not a silent clamp
        query.validate()?;
        let mut params = vec![
            ("snapshotId", query.snapshot_id.to_string()),
            ("fromTs", query.from_ts.to_string()),
            ("fromLsn", query.from_lsn.to_string()),
            ("limit", query.limit.to_string()),
        ];
        if let Some(record_type) = query.record_type {
            params.push(("recordType", record_type.to_string()));
        }
        if let Some(max_bytes) = query.max_bytes {
            params.push(("maxBytes", max_bytes.to_string()));
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

    /// Contiguity audit over one generation's tail. DEV-ONLY route: the
    /// managed surface answers 404 here (the local-dev stack lane uses this
    /// to prove the developer-convenience posture still serves it).
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

    /// Full journal verification (`GET /journal/{db}/verify`, F8): the
    /// session-independent recovery/forensics read - its JOURNAL_VERIFY
    /// capability binds no session or generation by design.
    pub fn journal_verify(&self, database_id: &str) -> Result<JournalOutcome, L1Error> {
        let cap = self.issue(database_id, CapabilityMethod::JournalVerify, MintRestrictions::default())?;
        let mut response = self
            .agent
            .get(format!("{}/journal/{database_id}/verify", self.config.base))
            .header("x-capability", &cap.token)
            .call()
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let body: serde_json::Value = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if status != 200 || body["ok"] != serde_json::Value::Bool(true) {
            return Err(L1Error::Protocol { status, body: body.to_string() });
        }
        let length = body["length"]
            .as_u64()
            .ok_or_else(|| L1Error::Decode(format!("journal verdict without length: {body}")))?;
        Ok(JournalOutcome { ok: true, length })
    }

    // -----------------------------------------------------------------
    // R6-PERF-01: the STREAMING data path.
    //
    // Two rules hold across everything below.
    //
    //   1. Nothing here is the default. `read_exact` and `upload_payload`
    //      keep their exact buffered behaviour; a caller switches over by
    //      NAMING a streaming method, never by configuration drift.
    //   2. No streamed byte reaches a consumer before its full digest and
    //      length are proven. The only value carrying streamed bytes out of
    //      this module is `VerifiedPayload`, and `l1_stream` provides no way
    //      to build one that was not verified.
    // -----------------------------------------------------------------

    /// One capability-bearing GET that EXPLICITLY negotiates the streaming
    /// exact-read variant (`accept: application/octet-stream`). A wildcard
    /// accept does not select it at the Worker, and this client never sends
    /// one: the shape it parses is the shape it asked for.
    fn read_get_stream(&self, database_id: &str, path: &str) -> Result<ureq::http::Response<ureq::Body>, L1Error> {
        let (session, generation) = self.actor()?;
        let cap = self.issue(
            database_id,
            CapabilityMethod::WalRead,
            MintRestrictions { session: Some(&session), generation: Some(generation), ..Default::default() },
        )?;
        self.agent
            .get(format!("{}{}", self.config.base, path))
            .header("x-capability", &cap.token)
            .header("accept", PAYLOAD_STREAM_MEDIA_TYPE)
            .call()
            .map_err(|e| L1Error::Http(e.to_string()))
    }

    /// Streaming exact read. The record's catalogued identity travels in
    /// headers and the payload IS the body: no JSON envelope, no base64
    /// expansion, no whole-record buffer on either side.
    ///
    /// The order of operations is the safety property:
    ///
    ///   1. every declared bound is checked against the response METADATA
    ///      first - content type, digest shape, the length against both the
    ///      caller's spool policy and `MAX_RECORD_BYTES`, `content-digest`
    ///      against `x-payload-sha256`, the echoed lsn against the one
    ///      asked for. An oversize or self-contradicting response is
    ///      refused with the body unread and unallocated;
    ///   2. bytes are pumped into a WRITE-ONLY spool;
    ///   3. only after the full length and full SHA-256 match does the
    ///      spool publish a `VerifiedPayload`.
    ///
    /// The Worker's documented residual hazard - a consumer observing a
    /// corrupt prefix before the in-band abort - therefore cannot be
    /// realised through this API: the prefix exists only inside a spool
    /// that has no reader and is destroyed on every refusal path.
    pub fn read_exact_streaming(
        &self,
        database_id: &str,
        generation: u64,
        lsn: u64,
        policy: SpoolPolicy<'_>,
        options: &mut StreamOptions<'_>,
    ) -> Result<StreamedRead, L1Error> {
        let mut response = self.read_get_stream(database_id, &format!("/wal/{database_id}/{generation}/{lsn}"))?;
        let status = response.status().as_u16();
        if status != 200 {
            // every refusal - 404 NOT_FOUND, 409 SESSION_NOT_ACTIVE from a
            // fence, 413 over-cap, 500 integrity - is still a JSON body, and
            // it carries NO payload bytes
            let body = response.body_mut().read_to_string().unwrap_or_default();
            return Err(L1Error::Protocol { status, body });
        }
        let header =
            |name: &str| response.headers().get(name).and_then(|value| value.to_str().ok()).map(str::to_string);
        let inconsistent =
            |detail: String| L1Error::Stream(StreamError::Integrity(IntegrityFault::HeaderInconsistent(detail)));
        // content negotiation must have ACTUALLY happened: a JSON answer to
        // an octet-stream request is a protocol change, never a silent
        // fallback into the buffered shape
        let content_type = header("content-type").unwrap_or_default();
        if content_type.split(';').next().unwrap_or_default().trim() != PAYLOAD_STREAM_MEDIA_TYPE {
            return Err(inconsistent(format!("content-type {content_type:?} is not the negotiated stream")));
        }
        let digest = header("x-payload-sha256").ok_or_else(|| inconsistent("no x-payload-sha256".into()))?;
        let declared = header("x-payload-length")
            .ok_or_else(|| inconsistent("no x-payload-length".into()))
            .and_then(|raw| parse_wire_u64(&raw).map_err(inconsistent))?;
        if let Some(content_length) = header("content-length") {
            let framed = parse_wire_u64(&content_length).map_err(inconsistent)?;
            if framed != declared {
                return Err(inconsistent(format!("content-length {framed} contradicts x-payload-length {declared}")));
            }
        }
        // RFC 9530 content-digest must agree with the hex header: two
        // independent statements of the same fact, and a server that
        // disagrees with itself is refused before its bytes are touched
        let content_digest = header("content-digest").ok_or_else(|| inconsistent("no content-digest".into()))?;
        let encoded = content_digest
            .strip_prefix("sha-256=:")
            .and_then(|rest| rest.strip_suffix(':'))
            .ok_or_else(|| inconsistent(format!("content-digest {content_digest:?} is not RFC 9530 sha-256")))?;
        let decoded = base64_decode(encoded).map_err(inconsistent)?;
        if hex(&<[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| inconsistent(format!("content-digest carries {} bytes, not 32", decoded.len())))?)
            != digest
        {
            return Err(inconsistent(format!("content-digest {content_digest} contradicts x-payload-sha256 {digest}")));
        }
        let echoed_lsn = header("x-append-lsn")
            .ok_or_else(|| inconsistent("no x-append-lsn".into()))
            .and_then(|raw| parse_wire_u64(&raw).map_err(inconsistent))?;
        if echoed_lsn != lsn {
            return Err(inconsistent(format!("response is for lsn {echoed_lsn}, not {lsn}")));
        }
        let type_sequence = header("x-type-sequence")
            .ok_or_else(|| inconsistent("no x-type-sequence".into()))
            .and_then(|raw| parse_wire_u64(&raw).map_err(inconsistent))?;
        let record_type: u8 = header("x-record-type")
            .ok_or_else(|| inconsistent("no x-record-type".into()))?
            .parse()
            .map_err(|_| inconsistent("x-record-type is not a u8".into()))?;
        let meta = RecordMeta {
            append_lsn: echoed_lsn,
            type_sequence,
            record_type,
            payload_digest: digest.clone(),
            payload_length: declared,
        };
        // bound check BEFORE the body: an over-cap record is refused with
        // nothing allocated and nothing read
        let limit = policy.max_bytes();
        if declared > limit {
            return Err(L1Error::Stream(StreamError::Oversize { declared, limit }));
        }
        // `declared + 1` so a server that sends MORE than it declared is
        // caught as an overrun instead of being silently truncated into a
        // matching prefix
        let mut reader = response.body_mut().with_config().limit(declared.saturating_add(1)).reader();
        let payload = l1_stream::ingest(&mut reader, policy, &digest, declared, options)?;
        Ok(StreamedRead { meta, payload })
    }

    /// Upload one payload from a REWINDABLE source: the process never holds
    /// the record, and nothing is base64-expanded in either direction.
    ///
    /// Two passes are structural, not a shortcut. The PUT_PAYLOAD
    /// capability binds the exact content digest and a byte budget, and the
    /// issuer refuses a spec without them, so the digest must exist before
    /// the token does. Pass one measures the source in `STREAM_CHUNK_BYTES`
    /// of memory and REFUSES an over-bound record before issuance; pass two
    /// transmits under a `VerifyingReader` that re-proves the same digest
    /// and length as the bytes leave, so a source that changed between the
    /// passes aborts the request rather than storing bytes the receipt does
    /// not describe.
    ///
    /// `content-length` is sent explicitly: the Worker refuses an
    /// undeclared body with 411 CONTENT_LENGTH_REQUIRED (an unbounded
    /// stream cannot be admitted against a byte budget), so a chunked
    /// upload is not a thing this client may attempt.
    pub fn upload_payload_streaming(
        &self,
        database_id: &str,
        source: &dyn PayloadSource,
        max_bytes: u64,
    ) -> Result<UploadReceipt, L1Error> {
        let measured = l1_stream::fingerprint(source, max_bytes.min(MAX_RECORD_BYTES))?;
        let cap = self.issue(
            database_id,
            CapabilityMethod::PutPayload,
            MintRestrictions { digest: Some(&measured.digest), max_bytes: Some(measured.length), ..Default::default() },
        )?;
        let canonical = format!("p/{database_id}/{}", measured.digest);
        let key = match cap.key {
            Some(key) if key == canonical => key,
            other => {
                return Err(L1Error::Decode(format!(
                    "issuer key {other:?} is not the canonical {canonical:?}; refusing to upload"
                )));
            }
        };
        let body = VerifyingReader::new(source.open().map_err(StreamError::io_public)?, measured.clone());
        let mut response = self
            .agent
            .put(format!("{}/payload/{}", self.config.base, encode_path(&key)))
            .header("x-capability", &cap.token)
            .header("content-type", PAYLOAD_STREAM_MEDIA_TYPE)
            .header("content-length", measured.length.to_string())
            .send(ureq::SendBody::from_owned_reader(body))
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
                if k == key && d == measured.digest && l == measured.length =>
            {
                Ok(UploadReceipt {
                    key,
                    digest: measured.digest,
                    length: l,
                    deduplicated: deduplicated.unwrap_or(false),
                })
            }
            _ => Err(L1Error::Protocol { status, body: format!("upload receipt disagrees: {raw}") }),
        }
    }

    /// BOUNDED streaming replay: walk the physical LSN range of one
    /// generation, stream each record through a spool, and hand the
    /// consumer only PROVEN bytes - apply first, acknowledge second, both
    /// strictly after verification.
    ///
    /// The walk is bounded on every axis (`ReplayBounds`) and the cut is
    /// the authority's own head at entry, so it cannot chase a moving tail.
    /// Any refusal - integrity, cancellation, fence, transport - returns
    /// the report of what HAD been applied plus the typed error, and the
    /// record in flight is reported in `aborted_at_lsn` having been neither
    /// applied nor acknowledged.
    ///
    /// NOTE on shape: this walks exact reads rather than `/scan`, because
    /// `/scan` has no metadata-only variant - its wire contract inlines
    /// base64 payloads, so driving a streaming replay from it would make
    /// the authority buffer and base64-expand exactly the bytes the
    /// streaming path exists to avoid.
    pub fn replay_streaming(
        &self,
        database_id: &str,
        generation: u64,
        from_lsn: u64,
        bounds: ReplayBounds,
        policy: SpoolPolicy<'_>,
        consumer: &mut dyn crate::l1_stream::RecordConsumer,
    ) -> Result<ReplayReport, (ReplayReport, L1Error)> {
        let mut report = ReplayReport::default();
        if let Err(error) = bounds.validate() {
            return Err((report, L1Error::Stream(error)));
        }
        let head = match self.head(database_id, generation) {
            Ok(head) => head,
            Err(error) => return Err((report, error)),
        };
        let head_lsn = match head.head_lsn {
            WalPosition::Empty => return Ok(report),
            WalPosition::At(lsn) => lsn,
        };
        let mut lsn = from_lsn;
        while lsn <= head_lsn {
            if report.applied >= bounds.max_records {
                break;
            }
            report.aborted_at_lsn = Some(lsn);
            let mut options = StreamOptions::default();
            let read = match self.read_exact_streaming(database_id, generation, lsn, policy, &mut options) {
                Ok(read) => read,
                Err(error) => return Err((report, error)),
            };
            if read.meta.payload_length > bounds.max_record_bytes {
                return Err((
                    report,
                    L1Error::Stream(StreamError::Oversize {
                        declared: read.meta.payload_length,
                        limit: bounds.max_record_bytes,
                    }),
                ));
            }
            // FIRST proven, THEN applied, THEN acknowledged. A consumer
            // refusal leaves the record unacknowledged.
            if let Err(detail) = consumer.apply(&read.meta, &read.payload) {
                return Err((report, L1Error::Stream(StreamError::Io(detail))));
            }
            report.applied += 1;
            report.bytes += read.meta.payload_length;
            report.last_applied_lsn = Some(lsn);
            if let Err(detail) = consumer.acknowledge(&read.meta) {
                return Err((report, L1Error::Stream(StreamError::Io(detail))));
            }
            report.acknowledged += 1;
            report.aborted_at_lsn = None;
            // O(record), not O(stream): the cache entry goes as soon as the
            // record it held has been applied and acknowledged
            if let Err(error) = read.payload.discard() {
                return Err((report, L1Error::Stream(StreamError::Io(error.to_string()))));
            }
            lsn += 1;
        }
        Ok(report)
    }

    /// Raw probe against the WORKER surface: exact method/path/body/headers,
    /// returning (status, parsed JSON or Null). This is the adversarial and
    /// posture-probe surface for suites and stack lanes (dev-route 404
    /// matrices, forged-token presentations) - product code paths never use
    /// it.
    pub fn probe(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
        headers: &[(&str, &str)],
    ) -> Result<(u16, serde_json::Value), L1Error> {
        let url = format!("{}{}", self.config.base, path);
        let mut response = match (method, body) {
            ("GET", _) => {
                let mut request = self.agent.get(&url);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                request.call()
            }
            ("POST", Some(json)) => {
                let mut request = self.agent.post(&url);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                request.send_json(json)
            }
            ("POST", None) => {
                let mut request = self.agent.post(&url);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                request.send_empty()
            }
            (other, _) => return Err(L1Error::Decode(format!("probe method {other:?} unsupported"))),
        }
        .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let raw = response.body_mut().read_to_string().map_err(|e| L1Error::Http(e.to_string()))?;
        let parsed = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        Ok((status, parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The issuance spec is the typed seam between MintRestrictions and the
    /// issuer's wire format: generation MUST be a JSON number (the issuer
    /// binds its canonical decimal string form into the token), and absent
    /// restrictions must be truly ABSENT - an issuer treating null as "no
    /// restriction" versus "restriction present but empty" is exactly the
    /// wider-token drift R4-SEC-03 named.
    #[test]
    fn issuance_spec_encodes_restrictions_exactly() {
        let spec = issuance_spec(
            "p-1",
            "db-1",
            CapabilityMethod::WalFinalize,
            &MintRestrictions { session: Some("sess-a"), generation: Some(u64::MAX), ..Default::default() },
        );
        assert_eq!(spec["method"], "WAL_FINALIZE");
        assert_eq!(spec["databaseId"], "db-1");
        assert_eq!(spec["session"], "sess-a");
        assert_eq!(spec["generation"], serde_json::json!(u64::MAX), "generation is a JSON number");
        for absent in ["digest", "maxBytes", "tenantId"] {
            assert!(spec.get(absent).is_none(), "{absent} must be absent, not null");
        }
    }

    #[test]
    fn issuance_spec_carries_payload_and_tenant_restrictions() {
        let spec = issuance_spec(
            "p-1",
            "db-1",
            CapabilityMethod::PutPayload,
            &MintRestrictions {
                digest: Some("ab"),
                max_bytes: Some(7),
                tenant_id: Some("tenant-b"),
                ..Default::default()
            },
        );
        assert_eq!(spec["method"], "PUT_PAYLOAD");
        assert_eq!(spec["digest"], "ab");
        assert_eq!(spec["maxBytes"], 7);
        assert_eq!(spec["tenantId"], "tenant-b");
        assert!(spec.get("session").is_none() && spec.get("generation").is_none());
    }

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
