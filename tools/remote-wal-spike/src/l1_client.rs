//! TB-P4 spike wiring to the L1 local stack: the same remote-WAL protocol the
//! deterministic in-process lanes exercise, spoken over real HTTP to the
//! control plane running on workerd (`wrangler dev --local`), with payloads
//! travelling through the (local) R2 data path.
//!
//! This is the transport skeleton the fork's TB-P4 client builds on: every
//! response is a typed outcome, ambiguity is resolved by re-submitting the
//! identical operation, and nothing here can delete or overwrite.

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum L1Error {
    Http(String),
    Protocol { status: u16, body: String },
    Decode(String),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeHttpRequest {
    pub database_id: String,
    pub generation: u64,
    pub startup_session_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub sequencing_kind: String,
    /// TypeDB durability record type (u8) — catalogued server-side so
    /// type-filtered replay is an index scan, not a payload fetch per record.
    pub record_type: u8,
    pub logical_key: Option<String>,
    pub payload_key: String,
    pub payload_digest: String,
    pub payload_length: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeHttpOutcome {
    pub ok: bool,
    pub append_lsn: Option<u64>,
    pub type_sequence: Option<u64>,
    pub control_seq: Option<u64>,
    pub replayed: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadOutcome {
    pub key: String,
    pub sha256hex: String,
    pub length: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactReadOutcome {
    pub ok: bool,
    pub error: Option<String>,
    pub payload_key: Option<String>,
    pub payload_digest: Option<String>,
    pub type_sequence: Option<u64>,
    pub payload_base64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditOutcome {
    pub contiguous: bool,
    pub count: u64,
    pub max_lsn: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadOutcome {
    pub ok: bool,
    pub head_lsn: i64,
    pub head_type_sequence: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IteratorOutcome {
    pub ok: bool,
    pub head_lsn: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRecord {
    pub append_lsn: u64,
    pub type_sequence: u64,
    pub sequencing_kind: String,
    pub record_type: u8,
    pub payload_key: String,
    pub payload_digest: String,
    pub payload_length: u64,
    pub logical_key: Option<String>,
    pub payload_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOutcome {
    pub ok: bool,
    pub records: Vec<ScanRecord>,
    pub next_from_lsn: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastOutcome {
    pub ok: bool,
    pub error: Option<String>,
    pub record: Option<ScanRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchOutcome {
    pub ok: bool,
    pub error: Option<String>,
    pub results: Option<Vec<FinalizeHttpOutcome>>,
}

pub struct L1Client {
    base: String,
    agent: ureq::Agent,
}

impl L1Client {
    pub fn new(base: impl Into<String>) -> Self {
        // 4xx/5xx are typed protocol outcomes here (409 conflict, 422 data-path
        // rejection, 404 exact miss) - never transport errors
        let config = ureq::config::Config::builder().http_status_as_error(false).build();
        Self { base: base.into(), agent: config.new_agent() }
    }

    pub fn health(&self) -> Result<(), L1Error> {
        let mut response =
            self.agent.get(format!("{}/health", self.base)).call().map_err(|e| L1Error::Http(e.to_string()))?;
        let body: serde_json::Value = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if body["ok"] == serde_json::Value::Bool(true) { Ok(()) } else { Err(L1Error::Protocol { status: 200, body: body.to_string() }) }
    }

    pub fn upload_payload(&self, key: &str, bytes: &[u8]) -> Result<UploadOutcome, L1Error> {
        let mut response = self
            .agent
            .put(format!("{}/payload/{}", self.base, key))
            .send(bytes)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }

    pub fn register_session(&self, database_id: &str, generation: u64, session: &str) -> Result<(), L1Error> {
        self.post_json(
            "/session/register",
            &serde_json::json!({ "databaseId": database_id, "generation": generation, "startupSessionId": session }),
        )
        .map(|_| ())
    }

    pub fn fence_session(&self, database_id: &str, generation: u64, session: &str) -> Result<(), L1Error> {
        self.post_json(
            "/session/fence",
            &serde_json::json!({ "databaseId": database_id, "generation": generation, "startupSessionId": session }),
        )
        .map(|_| ())
    }

    /// Finalize; NEVER treats transport failure as failure of the operation —
    /// the caller resolves ambiguity by re-invoking with the identical request
    /// (the controller replays the original allocation by operation identity).
    pub fn finalize(&self, request: &FinalizeHttpRequest) -> Result<(u16, FinalizeHttpOutcome), L1Error> {
        let mut response = self
            .agent
            .post(format!("{}/wal/finalize", self.base))
            .send_json(request)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let outcome: FinalizeHttpOutcome =
            response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    pub fn read_exact(&self, database_id: &str, generation: u64, lsn: u64) -> Result<(u16, ExactReadOutcome), L1Error> {
        let mut response = self
            .agent
            .get(format!("{}/wal/{}/{}/{}", self.base, database_id, generation, lsn))
            .call()
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let outcome = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    pub fn audit(&self, database_id: &str, generation: u64) -> Result<AuditOutcome, L1Error> {
        let mut response = self
            .agent
            .get(format!("{}/wal/{}/{}/audit", self.base, database_id, generation))
            .call()
            .map_err(|e| L1Error::Http(e.to_string()))?;
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }

    /// WAL head: highest AppendLsn AND highest TypeSequence (the durability
    /// client's `current()`/`previous()` need the latter — the audit's
    /// `maxLsn` is a physical position, not a sequence number).
    pub fn head(&self, database_id: &str, generation: u64) -> Result<HeadOutcome, L1Error> {
        let mut response = self
            .agent
            .get(format!("{}/wal/{}/{}/head", self.base, database_id, generation))
            .call()
            .map_err(|e| L1Error::Http(e.to_string()))?;
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }

    /// Pin a fixed iteration snapshot: pages of one logical iteration are
    /// bounded by the returned head and never observe later appends.
    pub fn open_iterator(&self, database_id: &str, generation: u64) -> Result<IteratorOutcome, L1Error> {
        let mut response = self
            .agent
            .post(format!("{}/wal/{}/{}/iterator", self.base, database_id, generation))
            .send_json(&serde_json::json!({}))
            .map_err(|e| L1Error::Http(e.to_string()))?;
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }

    /// One ordered replay page (physical order, `type_sequence >= from_ts`,
    /// bounded by the pinned `through_lsn`), payloads inline.
    pub fn scan(
        &self,
        database_id: &str,
        generation: u64,
        from_ts: u64,
        from_lsn: u64,
        through_lsn: i64,
        record_type: Option<u8>,
        limit: u32,
    ) -> Result<ScanOutcome, L1Error> {
        let mut url = format!(
            "{}/wal/{}/{}/scan?fromTs={}&fromLsn={}&throughLsn={}&limit={}",
            self.base, database_id, generation, from_ts, from_lsn, through_lsn, limit
        );
        if let Some(rt) = record_type {
            url.push_str(&format!("&recordType={rt}"));
        }
        let mut response = self.agent.get(url).call().map_err(|e| L1Error::Http(e.to_string()))?;
        response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))
    }

    /// Last record of a type in physical order (`find_last_type`); a miss is
    /// a typed 404 outcome, never EOF.
    pub fn last_by_type(
        &self,
        database_id: &str,
        generation: u64,
        record_type: u8,
    ) -> Result<(u16, LastOutcome), L1Error> {
        let mut response = self
            .agent
            .get(format!("{}/wal/{}/{}/last?recordType={}", self.base, database_id, generation, record_type))
            .call()
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let outcome = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    /// All-or-nothing batch finalisation: one transaction on one authority.
    pub fn finalize_batch(&self, requests: &[FinalizeHttpRequest]) -> Result<(u16, BatchOutcome), L1Error> {
        let mut response = self
            .agent
            .post(format!("{}/wal/finalize-batch", self.base))
            .send_json(&serde_json::json!({ "requests": requests }))
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let outcome = response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        Ok((status, outcome))
    }

    /// POST where the only success shape is HTTP 200 with `{"ok": true}`.
    /// Anything else (non-200 status, `ok:false`, missing `ok`) is a typed
    /// protocol error: register/fence callers act on the *effect* having been
    /// applied, so silently accepting an error body would let a caller
    /// believe a fence exists that was never installed.
    fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, L1Error> {
        let mut response = self
            .agent
            .post(format!("{}{}", self.base, path))
            .send_json(body)
            .map_err(|e| L1Error::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let parsed: serde_json::Value =
            response.body_mut().read_json().map_err(|e| L1Error::Decode(e.to_string()))?;
        if status != 200 || parsed["ok"] != serde_json::Value::Bool(true) {
            return Err(L1Error::Protocol { status, body: parsed.to_string() });
        }
        Ok(parsed)
    }
}
