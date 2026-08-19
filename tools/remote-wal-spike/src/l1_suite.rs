//! End-to-end protocol checks for the L1 client against a live control
//! plane (workerd via `wrangler dev`). One suite, two drivers: the
//! `l1-e2e` binary (`cargo run --bin l1-e2e -- [baseUrl]`) and the
//! `l1_stack` integration test both run exactly this, so the proof cannot
//! fork from the client.
//!
//! Fail-closed reporting: every check prints one PASS/FAIL line; a report
//! with zero executed checks, or any FAIL, is a failure.

use std::time::{Duration, Instant};

use crate::l1_client::{
    base64_decode, Budgets, CapabilityMethod, FinalizeHttpRequest, L1Client, L1Error, MintRestrictions,
    ScanQuery, SequencingKind, WalPosition,
};

#[derive(Debug, Default)]
pub struct SuiteReport {
    pub passed: u32,
    pub failed: u32,
}

impl SuiteReport {
    /// Zero executed checks is a failure: a suite that silently ran nothing
    /// must never read as green.
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.passed > 0
    }

    fn check(&mut self, name: &str, ok: bool, detail: &str) {
        if ok {
            self.passed += 1;
            println!("PASS  {name}");
        } else {
            self.failed += 1;
            println!("FAIL  {name} — {detail}");
        }
    }

    /// A required step whose refusal aborts the run: dependent checks would
    /// only cascade noise on top of the real failure.
    fn require<T>(&mut self, name: &str, result: Result<T, L1Error>) -> Option<T> {
        match result {
            Ok(value) => {
                self.check(name, true, "");
                Some(value)
            }
            Err(error) => {
                self.check(name, false, &error.to_string());
                None
            }
        }
    }
}

/// Bounded readiness poll: `wrangler dev` opens its port before the worker
/// answers /health.
pub fn wait_healthy(client: &L1Client, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match client.health() {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() >= deadline => {
                return Err(format!("health never became ok within {timeout:?}: {error}"));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(300)),
        }
    }
}

/// Run the full protocol suite against `database_id` (must be unused: local
/// DO state persists across runs, so drivers pass a unique id per run).
pub fn run(client: &L1Client, database_id: &str) -> SuiteReport {
    let mut report = SuiteReport::default();
    let db = database_id;
    let session = "sess-l1";
    const GEN: u64 = 1;

    // ---- session + mandatory budgets ----------------------------------
    if report.require("session registers (exact SESSION_REGISTER capability, session+generation-bound)",
        client.register_session(db, GEN, session)).is_none() {
        return report;
    }

    // ---- R4-SEC-03/05: under-restricted mints die at ISSUANCE -----------
    // The Worker's issuer enforces REQUIRED_RESTRICTIONS at mint time:
    // removing the generation from a WAL_FINALIZE or WAL_READ mint must
    // fail HERE, before the guarded route is ever reached - a token
    // missing a required restriction would be a WIDER capability.
    let no_gen_finalize = client.issue(db, CapabilityMethod::WalFinalize,
        MintRestrictions { session: Some(session), ..Default::default() });
    report.check(
        "a finalize mint omitting the generation is refused at issuance",
        matches!(&no_gen_finalize,
            Err(L1Error::Issuance { body, .. }) if body.contains("CAPABILITY_RESTRICTION_MISSING")),
        &format!("{no_gen_finalize:?}"),
    );
    let no_gen_read = client.issue(db, CapabilityMethod::WalRead,
        MintRestrictions { session: Some(session), ..Default::default() });
    report.check(
        "a read mint omitting the generation is refused at issuance",
        matches!(&no_gen_read,
            Err(L1Error::Issuance { body, .. }) if body.contains("CAPABILITY_RESTRICTION_MISSING")),
        &format!("{no_gen_read:?}"),
    );

    let payload1: &[u8] = b"l1-commit-record-1";
    let Some(receipt1) = report.require("payload uploads under the issuer-derived key",
        client.upload_payload(db, payload1)) else { return report };
    report.check(
        "upload key is canonical and content-addressed",
        receipt1.key == format!("p/{db}/{}", receipt1.digest) && receipt1.length == payload1.len() as u64,
        &receipt1.key,
    );

    let mut request = FinalizeHttpRequest {
        database_id: db.to_string(),
        generation: GEN,
        startup_session_id: session.to_string(),
        operation_id: "op-1".to_string(),
        sequencing_kind: SequencingKind::Sequenced,
        record_type: 2,
        logical_key: None,
        payload_key: String::new(),
        payload_digest: String::new(),
        payload_length: 0,
    };
    request.payload_from(&receipt1);

    // missing budget row = deny, never unlimited (Q-12)
    match client.finalize(&request) {
        Ok((status, outcome)) => report.check(
            "a database with no budget row denies writes",
            status == 409 && outcome.error.as_deref() == Some("ADMISSION_REJECTED_NO_BUDGET"),
            &format!("status={status} error={:?}", outcome.error),
        ),
        Err(error) => report.check("a database with no budget row denies writes", false, &error.to_string()),
    }
    if report.require("budgets install (session-bound BUDGETS_SET)",
        client.set_budgets(db, session, &Budgets {
            max_unpublished_outbox: 10_000,
            max_payload_length: 1_000_000,
            max_tail_records: 1_000_000,
        })).is_none() {
        return report;
    }

    // ---- finalize + identical-retry replay -----------------------------
    match client.finalize(&request) {
        Ok((status, outcome)) => report.check(
            "finalize allocates lsn 0",
            status == 200 && outcome.ok && outcome.append_lsn == Some(0)
                && outcome.type_sequence == Some(1) && outcome.replayed == Some(false),
            &format!("status={status} outcome={outcome:?}"),
        ),
        Err(error) => report.check("finalize allocates lsn 0", false, &error.to_string()),
    }
    match client.finalize(&request) {
        Ok((status, outcome)) => report.check(
            "identical retry replays the same allocation (replayed:true, same lsn)",
            status == 200 && outcome.ok && outcome.append_lsn == Some(0) && outcome.replayed == Some(true),
            &format!("status={status} outcome={outcome:?}"),
        ),
        Err(error) => report.check("identical retry replays the same allocation", false, &error.to_string()),
    }

    // ---- exact read-back with byte equality ----------------------------
    match client.read_exact(db, GEN, 0) {
        Ok((status, read)) => {
            let bytes = read
                .payload_base64
                .as_deref()
                .map(base64_decode)
                .transpose()
                .unwrap_or_default()
                .unwrap_or_default();
            report.check(
                "exact read returns byte-identical payload",
                status == 200 && read.ok && bytes == payload1
                    && read.payload_digest.as_deref() == Some(receipt1.digest.as_str()),
                &format!("status={status} digest={:?} len={}", read.payload_digest, bytes.len()),
            );
        }
        Err(error) => report.check("exact read returns byte-identical payload", false, &error.to_string()),
    }
    match client.read_exact(db, GEN, 99) {
        Ok((status, miss)) => report.check(
            "exact read miss is typed NOT_FOUND",
            status == 404 && miss.error.as_deref() == Some("NOT_FOUND"),
            &format!("status={status} error={:?}", miss.error),
        ),
        Err(error) => report.check("exact read miss is typed NOT_FOUND", false, &error.to_string()),
    }

    // ---- more records: unsequenced status + a second commit ------------
    let payload2: &[u8] = b"l1-status-record";
    let payload3: &[u8] = b"l1-commit-record-3";
    let mut lsn_after = None;
    if let (Some(receipt2), Some(receipt3)) = (
        report.require("status payload uploads", client.upload_payload(db, payload2)),
        report.require("third payload uploads", client.upload_payload(db, payload3)),
    ) {
        let mut status_request = request.clone();
        status_request.operation_id = "op-2".to_string();
        status_request.sequencing_kind = SequencingKind::Unsequenced;
        status_request.record_type = 1;
        status_request.logical_key = Some("status:l1".to_string());
        status_request.payload_from(&receipt2);
        let mut third = request.clone();
        third.operation_id = "op-3".to_string();
        third.payload_from(&receipt3);
        let statuses = (client.finalize(&status_request), client.finalize(&third));
        match statuses {
            (Ok((s2, o2)), Ok((s3, o3))) => report.check(
                "unsequenced + sequenced records allocate contiguously (lsn 1, 2; ts 1, 2)",
                s2 == 200 && o2.append_lsn == Some(1) && o2.type_sequence == Some(1)
                    && s3 == 200 && o3.append_lsn == Some(2) && o3.type_sequence == Some(2),
                &format!("op-2={o2:?} op-3={o3:?}"),
            ),
            (a, b) => report.check(
                "unsequenced + sequenced records allocate contiguously (lsn 1, 2; ts 1, 2)",
                false,
                &format!("{a:?} / {b:?}"),
            ),
        }
        lsn_after = Some(2u64);
    }

    // ---- head ----------------------------------------------------------
    match client.head(db, GEN) {
        Ok(head) => report.check(
            "head reports exact lsn and type sequence",
            head.ok && head.head_lsn == WalPosition::At(2) && head.head_type_sequence == 2,
            &format!("{head:?}"),
        ),
        Err(error) => report.check("head reports exact lsn and type sequence", false, &error.to_string()),
    }

    // ---- pinned iterator + paged scan ----------------------------------
    if let Some(expected_head) = lsn_after {
        match client.open_iterator(db, GEN) {
            Ok(iterator) => {
                report.check(
                    "iterator pins the head under a server-owned snapshot id",
                    iterator.ok && iterator.head_lsn == WalPosition::At(expected_head)
                        && iterator.snapshot_id.starts_with(&format!("{expected_head}.")),
                    &format!("{iterator:?}"),
                );
                // limit=1 forces pagination: three pages, then None
                let mut collected: Vec<(u64, u64, u8, Vec<u8>)> = Vec::new();
                let mut from_lsn = 0u64;
                let mut pages = 0u32;
                let mut page_error = None;
                // bounded: one page per record plus slack, never an unconditional loop
                while pages < 8 {
                    let query = ScanQuery {
                        snapshot_id: &iterator.snapshot_id,
                        from_ts: 0,
                        from_lsn,
                        record_type: None,
                        limit: 1,
                    };
                    match client.scan(db, GEN, &query) {
                        Ok((200, page)) if page.ok => {
                            pages += 1;
                            for record in &page.records {
                                let bytes = base64_decode(&record.payload_base64).unwrap_or_default();
                                collected.push((record.append_lsn, record.type_sequence, record.record_type, bytes));
                            }
                            match page.next_from_lsn {
                                Some(next) => from_lsn = next,
                                None => break,
                            }
                        }
                        Ok((status, page)) => {
                            page_error = Some(format!("status={status} error={:?}", page.error));
                            break;
                        }
                        Err(error) => {
                            page_error = Some(error.to_string());
                            break;
                        }
                    }
                }
                let expected: Vec<(u64, u64, u8, Vec<u8>)> = vec![
                    (0, 1, 2, payload1.to_vec()),
                    (1, 1, 1, payload2.to_vec()),
                    (2, 2, 2, payload3.to_vec()),
                ];
                report.check(
                    "scan pages through the snapshot in physical order with byte-identical payloads",
                    page_error.is_none() && pages == 3 && collected == expected,
                    &format!(
                        "pages={pages} err={page_error:?} got={:?}",
                        collected.iter().map(|(l, t, r, _)| (*l, *t, *r)).collect::<Vec<_>>()
                    ),
                );
            }
            Err(error) => report.check("iterator pins the head under a server-owned snapshot id", false, &error.to_string()),
        }
    }

    // ---- last-by-type ---------------------------------------------------
    match client.last_by_type(db, GEN, 1) {
        Ok((status, last)) => report.check(
            "last-by-type finds the status record",
            status == 200 && last.ok && last.record.as_ref().map(|r| r.append_lsn) == Some(1),
            &format!("status={status} record={:?}", last.record.as_ref().map(|r| r.append_lsn)),
        ),
        Err(error) => report.check("last-by-type finds the status record", false, &error.to_string()),
    }
    match client.last_by_type(db, GEN, 99) {
        Ok((status, miss)) => report.check(
            "last-by-type miss is typed NOT_FOUND",
            status == 404 && miss.error.as_deref() == Some("NOT_FOUND"),
            &format!("status={status} error={:?}", miss.error),
        ),
        Err(error) => report.check("last-by-type miss is typed NOT_FOUND", false, &error.to_string()),
    }

    // ---- non-canonical payload key refusal (C-P0-07) --------------------
    let mut cross = request.clone();
    cross.operation_id = "op-cross".to_string();
    cross.payload_key = format!("p/other-db/{}", receipt1.digest);
    match client.finalize(&cross) {
        Ok((status, outcome)) => report.check(
            "a non-canonical payload key is refused pre-I/O",
            status == 400 && outcome.error.as_deref() == Some("NON_CANONICAL_PAYLOAD_KEY"),
            &format!("status={status} error={:?}", outcome.error),
        ),
        Err(error) => report.check("a non-canonical payload key is refused pre-I/O", false, &error.to_string()),
    }

    // ---- generation rollover: commit authority follows the session ------
    if report.require("live-actor rollover re-registers into generation 2",
        client.register_session(db, GEN + 1, session)).is_some() {
        let mut stale = request.clone();
        stale.operation_id = "op-stale-gen".to_string();
        match client.finalize(&stale) {
            Ok((status, outcome)) => report.check(
                "the old generation refuses after rollover (SESSION_GENERATION_MISMATCH)",
                status == 409 && outcome.error.as_deref() == Some("SESSION_GENERATION_MISMATCH"),
                &format!("status={status} error={:?}", outcome.error),
            ),
            Err(error) => report.check(
                "the old generation refuses after rollover (SESSION_GENERATION_MISMATCH)",
                false,
                &error.to_string(),
            ),
        }
        let mut current = request.clone();
        current.generation = GEN + 1;
        current.operation_id = "op-gen2".to_string();
        match client.finalize(&current) {
            Ok((status, outcome)) => report.check(
                "the current generation admits the same actor (fresh lsn 0)",
                status == 200 && outcome.ok && outcome.append_lsn == Some(0) && outcome.replayed == Some(false),
                &format!("status={status} outcome={outcome:?}"),
            ),
            Err(error) => report.check("the current generation admits the same actor (fresh lsn 0)",
                false, &error.to_string()),
        }
    }

    // ---- contiguity audit over generation 1 -----------------------------
    match client.audit(db, GEN) {
        Ok(audit) => report.check(
            "generation 1 tail is contiguous (3 records through lsn 2)",
            audit.ok && audit.contiguous && audit.count == 3 && audit.max_lsn == WalPosition::At(2),
            &format!("{audit:?}"),
        ),
        Err(error) => report.check("generation 1 tail is contiguous (3 records through lsn 2)",
            false, &error.to_string()),
    }

    report
}
