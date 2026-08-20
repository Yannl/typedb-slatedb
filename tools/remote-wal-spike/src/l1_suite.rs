//! End-to-end protocol checks for the L1 client against a live control
//! plane (workerd via `wrangler dev`) plus a live PRIVATE ISSUER sidecar.
//! One suite, three drivers: the `l1-e2e` binary, the `l1_stack`
//! integration test (local-dev posture) and the `l1_managed_stack`
//! integration test (managed posture) all run exactly this, so the proof
//! cannot fork from the client - and because the suite touches ONLY routes
//! that exist on the MANAGED surface (R5-SEC-02: provision, the
//! reserve -> attest -> activate lifecycle, payload, finalize, reads,
//! journal verify - never /capability, /session/register, /session/fence,
//! /budgets or the other dev-only routes), a green run on either posture
//! proves the production-shaped protocol, not developer convenience.
//!
//! Fail-closed reporting: every check prints one PASS/FAIL line; a report
//! with zero executed checks, or any FAIL, is a failure.

use std::time::{Duration, Instant};

use crate::{
    l1_client::{
        base64_decode, Budgets, CapabilityMethod, FinalizeHttpRequest, L1Client, L1Error, MintRestrictions, ScanQuery,
        SequencingKind, WalPosition,
    },
    l1_stream::{
        BytesSource, RecordingConsumer, ReplayBounds, SpoolDir, SpoolPolicy, StreamError, StreamOptions,
        SyntheticSource, MAX_RECORD_BYTES, MAX_SCAN_PAGE_RECORDS,
    },
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

    pub fn check(&mut self, name: &str, ok: bool, detail: &str) {
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

/// A private per-run spool directory for the streaming checks. The
/// verify-before-apply path is content-addressed on disk, so each run gets
/// its own 0700 root and never shares cache entries with another run.
fn suite_spool(database_id: &str) -> Option<SpoolDir> {
    SpoolDir::open(std::env::temp_dir().join(format!("l1-suite-spool-{database_id}"))).ok()
}

/// The standard admission budgets the suite provisions databases with.
fn suite_budgets() -> Budgets {
    Budgets { max_unpublished_outbox: 10_000, max_payload_length: 1_000_000, max_tail_records: 1_000_000 }
}

/// Run the full protocol suite against `database_id` (must be unused: local
/// DO state persists across runs, so drivers pass a unique id per run; a
/// sibling `<database_id>-nb` authority is used for the no-budget check).
/// Every route exercised here exists on the MANAGED surface.
pub fn run(client: &L1Client, database_id: &str) -> SuiteReport {
    let mut report = SuiteReport::default();
    let db = database_id;
    let session = "sess-l1-a";
    const GEN: u64 = 1;
    const LEASE_MS: u64 = 10 * 60 * 1000;

    // the client's actor is bound EXPLICITLY for the pre-lifecycle probes;
    // activation re-binds it authoritatively below
    client.bind_actor(session, GEN);

    // ---- R4 PR1 + R5-SEC-02: an unprovisioned authority serves nothing.
    // The private issuer grants a syntactically valid, correctly signed
    // token without knowing provisioning state - the AUTHORITY is what
    // refuses (squat mutant): an authenticated call to an unprovisioned
    // database fails closed at use.
    let pre_provision = client.head(db, GEN);
    report.check(
        "an issuer-granted token against an unprovisioned authority fails closed (DATABASE_UNPROVISIONED)",
        matches!(&pre_provision,
            Err(L1Error::Protocol { status: 403, body }) if body.contains("DATABASE_UNPROVISIONED")),
        &format!("{pre_provision:?}"),
    );

    // verifier-scope mutant: an ordinary CAPABILITY-scope token presented
    // as the provisioning credential must not carry the registry write
    // power (mint/verify scope separation, R5-SEC-03 - the client itself
    // holds NO signing material, so the strongest thing it can present is
    // a token from the wrong scope).
    match client.issue(db, CapabilityMethod::JournalVerify, MintRestrictions::default()) {
        Ok(cap) => {
            let forged = client.provision_with_token(db, &cap.token, None);
            report.check(
                "an ordinary capability-scope token cannot provision (scope separation)",
                matches!(&forged, Err(L1Error::Protocol { status: 403, body })
                    if body.contains("CAPABILITY_KID_MISMATCH")),
                &format!("{forged:?}"),
            );
        }
        Err(error) => report.check(
            "an ordinary capability-scope token cannot provision (scope separation)",
            false,
            &error.to_string(),
        ),
    }

    // ---- R4-SEC-03/05: under-restricted specs die at the ISSUER ---------
    // The issuer enforces REQUIRED_RESTRICTIONS at issuance: omitting the
    // generation from a WAL_FINALIZE or WAL_READ spec must fail HERE,
    // before any token exists - a token missing a required restriction
    // would be a WIDER capability.
    let no_gen_finalize = client.issue(
        db,
        CapabilityMethod::WalFinalize,
        MintRestrictions { session: Some(session), ..Default::default() },
    );
    report.check(
        "a finalize spec omitting the generation is refused at the issuer",
        matches!(&no_gen_finalize,
            Err(L1Error::Issuance { status: 400, body }) if body.contains("CAPABILITY_RESTRICTION_MISSING")),
        &format!("{no_gen_finalize:?}"),
    );
    let no_gen_read =
        client.issue(db, CapabilityMethod::WalRead, MintRestrictions { session: Some(session), ..Default::default() });
    report.check(
        "a read spec omitting the generation is refused at the issuer",
        matches!(&no_gen_read,
            Err(L1Error::Issuance { status: 400, body }) if body.contains("CAPABILITY_RESTRICTION_MISSING")),
        &format!("{no_gen_read:?}"),
    );

    // ---- the provisioning transaction gates EVERYTHING; admission budgets
    // ride it because the managed surface has no budget-admin route -------
    match client.provision(db, Some(&suite_budgets())) {
        Ok(outcome) => report.check(
            "provisioning binds the authority (issuer-granted PROVISION capability, budgets riding)",
            outcome.created,
            &format!("created={}", outcome.created),
        ),
        Err(error) => {
            report.check(
                "provisioning binds the authority (issuer-granted PROVISION capability, budgets riding)",
                false,
                &error.to_string(),
            );
            return report;
        }
    }
    match client.provision(db, Some(&suite_budgets())) {
        Ok(outcome) => report.check(
            "provisioning replay of the same binding is idempotent (created:false)",
            !outcome.created,
            &format!("created={}", outcome.created),
        ),
        Err(error) => report.check(
            "provisioning replay of the same binding is idempotent (created:false)",
            false,
            &error.to_string(),
        ),
    }

    // ---- cross-tenant + audience mutants on the provisioned authority ---
    // a forged tenant-B claim on tenant-A's database reaches only a
    // DIFFERENT (unprovisioned) authority - the binding triple routes
    let forged_tenant = client.issue(
        db,
        CapabilityMethod::WalRead,
        MintRestrictions {
            session: Some(session),
            generation: Some(GEN),
            tenant_id: Some("tenant-b"),
            ..Default::default()
        },
    );
    match forged_tenant {
        Ok(cap) => {
            let cross = client.probe("GET", &format!("/wal/{db}/{GEN}/head"), None, &[("x-capability", &cap.token)]);
            report.check(
                "a forged cross-tenant claim reaches only an unprovisioned authority",
                matches!(&cross, Ok((403, body)) if body["error"] == "DATABASE_UNPROVISIONED"),
                &format!("{cross:?}"),
            );
        }
        Err(error) => report.check(
            "a forged cross-tenant claim reaches only an unprovisioned authority",
            false,
            &error.to_string(),
        ),
    }
    // audience framing: a token for another database refuses at the worker
    // frame, before any DO is contacted
    match client.issue(
        "another-db",
        CapabilityMethod::WalRead,
        MintRestrictions { session: Some(session), generation: Some(GEN), ..Default::default() },
    ) {
        Ok(cap) => {
            let wrong = client.probe("GET", &format!("/wal/{db}/{GEN}/head"), None, &[("x-capability", &cap.token)]);
            report.check(
                "audience framing refuses a wrong-database token at the worker",
                matches!(&wrong, Ok((403, body)) if body["error"] == "CAPABILITY_AUDIENCE_MISMATCH"),
                &format!("{wrong:?}"),
            );
        }
        Err(error) => {
            report.check("audience framing refuses a wrong-database token at the worker", false, &error.to_string())
        }
    }

    // ---- production lifecycle admission (R4-SEC-04 exact actions): the
    // legacy one-call register is a dev route - reserve -> attest ->
    // activate is the ONLY admission path on the managed surface ----------
    if report
        .require(
            "lifecycle: reservation (exact SESSION_RESERVE capability)",
            client.reserve_session(db, GEN, session, "l1-suite-host"),
        )
        .is_none()
    {
        return report;
    }
    if report
        .require(
            "lifecycle: attestation (exact SESSION_ATTEST capability)",
            client.attest_session(db, session, "pn-l1-a"),
        )
        .is_none()
    {
        return report;
    }
    match client.activate_session(db, GEN, session, "pn-l1-a", LEASE_MS) {
        Ok(activation) => report.check(
            "lifecycle: verified activation establishes the actor (nothing to fence yet)",
            activation.fenced_predecessors == 0 && activation.lease_deadline_ms > 0,
            &format!("{activation:?}"),
        ),
        Err(error) => {
            report.check(
                "lifecycle: verified activation establishes the actor (nothing to fence yet)",
                false,
                &error.to_string(),
            );
            return report;
        }
    }
    report.check(
        "lifecycle: lease renewal extends the active actor",
        client.renew_session(db, session, LEASE_MS).is_ok(),
        "renewal refused",
    );

    // ---- Q-12 on the managed surface: a database provisioned WITHOUT
    // budgets denies writes - budgets can only ride provisioning, so a
    // sibling authority proves the fail direction end to end -------------
    {
        let nb = format!("{db}-nb");
        let nb_session = "sess-l1-nb";
        let flow = client
            .provision(&nb, None)
            .and_then(|_| client.reserve_session(&nb, GEN, nb_session, "l1-suite-host"))
            .and_then(|_| client.attest_session(&nb, nb_session, "pn-l1-nb"))
            .and_then(|_| client.activate_session(&nb, GEN, nb_session, "pn-l1-nb", LEASE_MS))
            .and_then(|_| client.upload_payload(&nb, b"l1-nb-record"));
        match flow {
            Ok(receipt) => {
                let mut request = FinalizeHttpRequest {
                    database_id: nb.clone(),
                    generation: GEN,
                    startup_session_id: nb_session.to_string(),
                    operation_id: "op-nb-1".to_string(),
                    sequencing_kind: SequencingKind::Sequenced,
                    record_type: 2,
                    logical_key: None,
                    payload_key: String::new(),
                    payload_digest: String::new(),
                    payload_length: 0,
                };
                request.payload_from(&receipt);
                match client.finalize(&request) {
                    Ok((status, outcome)) => report.check(
                        "a database provisioned without budgets denies writes (no budget row = deny)",
                        status == 409 && outcome.error.as_deref() == Some("ADMISSION_REJECTED_NO_BUDGET"),
                        &format!("status={status} error={:?}", outcome.error),
                    ),
                    Err(error) => report.check(
                        "a database provisioned without budgets denies writes (no budget row = deny)",
                        false,
                        &error.to_string(),
                    ),
                }
            }
            Err(error) => report.check(
                "a database provisioned without budgets denies writes (no budget row = deny)",
                false,
                &format!("no-budget bootstrap failed: {error}"),
            ),
        }
        // the sibling authority's actor state must not leak into the main
        // flow: re-bind the suite's actor explicitly
        client.bind_actor(session, GEN);
    }

    // ---- payload upload + finalize + identical-retry replay -------------
    let payload1: &[u8] = b"l1-commit-record-1";
    let Some(receipt1) =
        report.require("payload uploads under the issuer-derived key", client.upload_payload(db, payload1))
    else {
        return report;
    };
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

    match client.finalize(&request) {
        Ok((status, outcome)) => report.check(
            "finalize allocates lsn 0",
            status == 200
                && outcome.ok
                && outcome.append_lsn == Some(0)
                && outcome.type_sequence == Some(1)
                && outcome.replayed == Some(false),
            &format!("status={status} outcome={outcome:?}"),
        ),
        Err(error) => report.check("finalize allocates lsn 0", false, &error.to_string()),
    }
    match client.finalize(&request) {
        Ok((status, outcome)) => report.check(
            "identical retry under a FRESH token replays the same allocation (replayed:true, same lsn)",
            status == 200 && outcome.ok && outcome.append_lsn == Some(0) && outcome.replayed == Some(true),
            &format!("status={status} outcome={outcome:?}"),
        ),
        Err(error) => {
            report.check("identical retry under a FRESH token replays the same allocation", false, &error.to_string())
        }
    }

    // ---- exact read-back with byte equality ----------------------------
    match client.read_exact(db, GEN, 0) {
        Ok((status, read)) => {
            let bytes =
                read.payload_base64.as_deref().map(base64_decode).transpose().unwrap_or_default().unwrap_or_default();
            report.check(
                "exact read returns byte-identical payload",
                status == 200
                    && read.ok
                    && bytes == payload1
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
                s2 == 200
                    && o2.append_lsn == Some(1)
                    && o2.type_sequence == Some(1)
                    && s3 == 200
                    && o3.append_lsn == Some(2)
                    && o3.type_sequence == Some(2),
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
                    iterator.ok
                        && iterator.head_lsn == WalPosition::At(expected_head)
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
                        max_bytes: None,
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
                let expected: Vec<(u64, u64, u8, Vec<u8>)> =
                    vec![(0, 1, 2, payload1.to_vec()), (1, 1, 1, payload2.to_vec()), (2, 2, 2, payload3.to_vec())];
                report.check(
                    "scan pages through the snapshot in physical order with byte-identical payloads",
                    page_error.is_none() && pages == 3 && collected == expected,
                    &format!(
                        "pages={pages} err={page_error:?} got={:?}",
                        collected.iter().map(|(l, t, r, _)| (*l, *t, *r)).collect::<Vec<_>>()
                    ),
                );
            }
            Err(error) => {
                report.check("iterator pins the head under a server-owned snapshot id", false, &error.to_string())
            }
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

    // ---- R6-PERF-01: the STREAMING data path, end to end ---------------
    // Everything above this point used the DEFAULT buffered route, and it
    // still does: nothing below changes what an unmodified consumer gets.
    // These checks exercise the opt-in `accept: application/octet-stream`
    // variant through the real Worker and the real (local) R2 data path,
    // and they assert the verify-before-apply invariant the streaming
    // route only earns by construction: a consumer sees proven bytes or it
    // sees nothing.
    {
        // client-side bounds refuse BEFORE any authority is requested: an
        // over-ceiling record cannot even reach issuance, so the authority
        // never sees a token minted for bytes it would have to refuse
        let over_ceiling = client.upload_payload_streaming(
            db,
            &SyntheticSource { length: MAX_RECORD_BYTES + 1, seed: 1 },
            MAX_RECORD_BYTES,
        );
        report.check(
            "an over-ceiling record is refused client-side before issuance",
            matches!(&over_ceiling, Err(L1Error::Stream(StreamError::Oversize { limit, .. }))
                if *limit == MAX_RECORD_BYTES),
            &format!("{over_ceiling:?}"),
        );

        // bounded pagination: the Worker CLAMPS an over-wide page, this
        // client REFUSES it - a caller must never believe it asked for a
        // page size it did not get
        let wide = client.scan(
            db,
            GEN,
            &ScanQuery {
                snapshot_id: "0.x",
                from_ts: 0,
                from_lsn: 0,
                record_type: None,
                limit: MAX_SCAN_PAGE_RECORDS + 1,
                max_bytes: None,
            },
        );
        report.check(
            "an over-wide scan page is refused client-side, never silently clamped",
            matches!(&wide, Err(L1Error::Stream(StreamError::Oversize { limit, .. }))
                if *limit == u64::from(MAX_SCAN_PAGE_RECORDS)),
            &format!("{wide:?}"),
        );

        // the streaming UPLOAD path: no complete `&[u8]` anywhere, the
        // digest measured in bounded memory, the body framed by an explicit
        // content-length (the Worker answers 411 to an undeclared body)
        match client.upload_payload_streaming(db, &BytesSource(payload1.to_vec()), MAX_RECORD_BYTES) {
            Ok(streamed) => report.check(
                "streaming upload reaches the same content-addressed key as the buffered route",
                streamed.key == receipt1.key
                    && streamed.digest == receipt1.digest
                    && streamed.length == receipt1.length,
                &format!("{streamed:?}"),
            ),
            Err(error) => report.check(
                "streaming upload reaches the same content-addressed key as the buffered route",
                false,
                &error.to_string(),
            ),
        }
        // a HALF-MEGABYTE synthetic record, generated on demand: the client
        // never holds it, and the receipt proves the authority hashed the
        // same bytes
        let synthetic = SyntheticSource { length: 512 * 1024, seed: 0x51A7E };
        match (
            crate::l1_stream::fingerprint(&synthetic, MAX_RECORD_BYTES),
            client.upload_payload_streaming(db, &synthetic, MAX_RECORD_BYTES),
        ) {
            (Ok(measured), Ok(receipt)) => report.check(
                "a synthetic 512 KiB record uploads from a generator, never from a buffer",
                receipt.digest == measured.digest && receipt.length == measured.length,
                &format!("measured={measured:?} receipt={receipt:?}"),
            ),
            (measured, receipt) => report.check(
                "a synthetic 512 KiB record uploads from a generator, never from a buffer",
                false,
                &format!("{measured:?} / {receipt:?}"),
            ),
        }

        match suite_spool(db) {
            None => report.check("streaming reads open a private spool directory", false, "spool dir unavailable"),
            Some(spool) => {
                let policy = SpoolPolicy::Cache { dir: &spool, max_bytes: MAX_RECORD_BYTES };
                let mut options = StreamOptions { expect_digest: Some(&receipt1.digest), progress: None };
                match client.read_exact_streaming(db, GEN, 0, policy, &mut options) {
                    Ok(read) => {
                        let bytes = read.payload.to_vec().unwrap_or_default();
                        report.check(
                            "streaming exact read returns byte-identical payload under a proven digest",
                            bytes == payload1
                                && read.meta.payload_digest == receipt1.digest
                                && read.meta.payload_length == payload1.len() as u64
                                && read.meta.append_lsn == 0
                                && read.payload.is_cached(),
                            &format!("{:?} len={}", read.meta, bytes.len()),
                        );
                        report.check(
                            "the streaming read published a content-addressed entry only after proof",
                            spool.committed_digests().unwrap_or_default() == vec![receipt1.digest.clone()]
                                && read.payload.reverify().unwrap_or(false),
                            &format!("{:?}", spool.committed_digests()),
                        );
                        let _ = read.payload.discard();
                    }
                    Err(error) => {
                        report.check(
                            "streaming exact read returns byte-identical payload under a proven digest",
                            false,
                            &error.to_string(),
                        );
                        report.check(
                            "the streaming read published a content-addressed entry only after proof",
                            false,
                            "no read",
                        );
                    }
                }

                // a miss on the streaming route is still a typed JSON
                // refusal carrying no bytes at all
                let mut options = StreamOptions::default();
                let miss = client.read_exact_streaming(db, GEN, 99, policy, &mut options);
                report.check(
                    "a streaming exact-read miss is a typed refusal with no bytes",
                    matches!(&miss, Err(L1Error::Protocol { status: 404, body }) if body.contains("NOT_FOUND")),
                    &format!("{miss:?}"),
                );

                // the whole generation replayed through the streaming route
                // with verify-before-apply: applied strictly after proof,
                // acknowledged strictly after applied
                let mut consumer = RecordingConsumer::default();
                let replay = client.replay_streaming(db, GEN, 0, ReplayBounds::default(), policy, &mut consumer);
                let expected: Vec<Vec<u8>> = vec![payload1.to_vec(), payload2.to_vec(), payload3.to_vec()];
                let applied: Vec<Vec<u8>> = consumer.applied.iter().map(|(_, bytes)| bytes.clone()).collect();
                report.check(
                    "a bounded streaming replay applies and acknowledges exactly the durable history",
                    matches!(&replay, Ok(report) if report.applied == 3 && report.acknowledged == 3
                        && report.aborted_at_lsn.is_none())
                        && applied == expected
                        && consumer.acknowledged == vec![0, 1, 2],
                    &format!("{replay:?} acked={:?}", consumer.acknowledged),
                );
                report.check(
                    "the replay released every cache entry it committed (O(record), not O(stream))",
                    spool.committed_digests().unwrap_or_default().is_empty(),
                    &format!("{:?}", spool.committed_digests()),
                );
            }
        }
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

    // ---- generation binding: an actor active in generation 1 holds no
    // authority in generation 2 (no session row exists there) -------------
    let mut wrong_gen = request.clone();
    wrong_gen.generation = GEN + 1;
    wrong_gen.operation_id = "op-wrong-gen".to_string();
    match client.finalize(&wrong_gen) {
        Ok((status, outcome)) => report.check(
            "a finalize claiming an unheld generation is refused (SESSION_UNKNOWN)",
            status == 409 && outcome.error.as_deref() == Some("SESSION_UNKNOWN"),
            &format!("status={status} error={:?}", outcome.error),
        ),
        Err(error) => report.check(
            "a finalize claiming an unheld generation is refused (SESSION_UNKNOWN)",
            false,
            &error.to_string(),
        ),
    }

    // ---- R6-PERF-01 fence-during-stream, PHASE 1: start a streaming
    // replay and stop it, mid-history, having applied exactly one proven
    // record. The takeover below fences this actor underneath the paused
    // replay; PHASE 2 (after the fence) resumes it. ---------------------
    let fence_spool = suite_spool(&format!("{db}-fence"));
    let mut fence_consumer = RecordingConsumer::default();
    if let Some(spool) = fence_spool.as_ref() {
        let paused = client.replay_streaming(
            db,
            GEN,
            0,
            ReplayBounds { max_records: 1, ..ReplayBounds::default() },
            SpoolPolicy::Cache { dir: spool, max_bytes: MAX_RECORD_BYTES },
            &mut fence_consumer,
        );
        report.check(
            "a streaming replay can be paused mid-history with exactly its proven records applied",
            matches!(&paused, Ok(progress) if progress.applied == 1 && progress.acknowledged == 1)
                && fence_consumer.applied.len() == 1
                && fence_consumer.acknowledged == vec![0],
            &format!("{paused:?} acked={:?}", fence_consumer.acknowledged),
        );
    }

    // ---- takeover through the lifecycle: a SUCCESSOR actor reserves the
    // next generation and its verified ACTIVATION - the one fencing
    // transition on the managed surface - fences the incumbent ------------
    let successor = "sess-l1-b";
    let takeover = client
        .reserve_session(db, GEN + 1, successor, "l1-suite-successor")
        .and_then(|_| client.attest_session(db, successor, "pn-l1-b"))
        .and_then(|_| client.activate_session(db, GEN + 1, successor, "pn-l1-b", LEASE_MS));
    match takeover {
        Ok(activation) => {
            report.check(
                "takeover: the successor's verified activation fences the incumbent",
                activation.fenced_predecessors == 1,
                &format!("{activation:?}"),
            );
            // the fenced predecessor's commit authority is gone: an
            // identical-shape finalize by the old actor answers exactly
            // SESSION_FENCED (inv. 38 - no result fields, no attribution)
            let mut stale = request.clone();
            stale.operation_id = "op-stale".to_string();
            match client.finalize(&stale) {
                Ok((status, outcome)) => report.check(
                    "the fenced predecessor cannot finalize (SESSION_FENCED)",
                    status == 409 && outcome.error.as_deref() == Some("SESSION_FENCED"),
                    &format!("status={status} error={:?}", outcome.error),
                ),
                Err(error) => {
                    report.check("the fenced predecessor cannot finalize (SESSION_FENCED)", false, &error.to_string())
                }
            }
            // R4-SEC-05 use-time revalidation: the old actor's READ
            // authority died with the fence too - a fresh, validly signed
            // token for the revoked session is refused at use
            client.bind_actor(session, GEN);
            let stale_read = client.head(db, GEN);
            report.check(
                "the fenced predecessor cannot read (use-time revalidation, 409)",
                matches!(&stale_read, Err(L1Error::Protocol { status: 409, body })
                    if body.contains("SESSION_NOT_ACTIVE")),
                &format!("{stale_read:?}"),
            );
            // R6-PERF-01 fence-during-stream, PHASE 2. The replay above
            // stopped after exactly one applied record; the fence has now
            // committed underneath it. Resuming is refused with a typed 409
            // carrying no bytes (the Worker redeems the read lease BEFORE
            // it hands back a body), and the consumer still holds exactly
            // the one record it proved before the fence - nothing was
            // applied or acknowledged across the fence.
            client.bind_actor(session, GEN);
            if let Some(spool) = fence_spool.as_ref() {
                let resumed = client.replay_streaming(
                    db,
                    GEN,
                    1,
                    ReplayBounds::default(),
                    SpoolPolicy::Cache { dir: spool, max_bytes: MAX_RECORD_BYTES },
                    &mut fence_consumer,
                );
                report.check(
                    "a fence during a streaming replay: the in-flight record is neither applied nor acknowledged",
                    matches!(&resumed, Err((progress, L1Error::Protocol { status: 409, body }))
                        if body.contains("SESSION_NOT_ACTIVE")
                            && progress.applied == 0
                            && progress.acknowledged == 0)
                        && fence_consumer.applied.len() == 1
                        && fence_consumer.acknowledged == vec![0]
                        && spool.committed_digests().unwrap_or_default().is_empty(),
                    &format!(
                        "{resumed:?} applied={} acked={:?}",
                        fence_consumer.applied.len(),
                        fence_consumer.acknowledged
                    ),
                );
            }
            client.bind_actor(successor, GEN + 1);
            // the successor commits in ITS generation from a fresh lsn 0
            let mut current = request.clone();
            current.generation = GEN + 1;
            current.startup_session_id = successor.to_string();
            current.operation_id = "op-gen2".to_string();
            match client.finalize(&current) {
                Ok((status, outcome)) => report.check(
                    "the successor commits in the new generation (fresh lsn 0)",
                    status == 200 && outcome.ok && outcome.append_lsn == Some(0) && outcome.replayed == Some(false),
                    &format!("status={status} outcome={outcome:?}"),
                ),
                Err(error) => {
                    report.check("the successor commits in the new generation (fresh lsn 0)", false, &error.to_string())
                }
            }
            // durable history survives the fence: the CURRENT actor reads
            // generation 1's first record byte-identically
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
                        "durable predecessor history stays readable by the current actor",
                        status == 200 && read.ok && bytes == payload1,
                        &format!("status={status} len={}", bytes.len()),
                    );
                }
                Err(error) => report.check(
                    "durable predecessor history stays readable by the current actor",
                    false,
                    &error.to_string(),
                ),
            }
        }
        Err(error) => report.check(
            "takeover: the successor's verified activation fences the incumbent",
            false,
            &error.to_string(),
        ),
    }

    // ---- journal verification (F8): the chain verifies and holds EXACTLY
    // this bootstrap's authority-moving records - provision, two verified
    // activations, four finalizations (the identical retry replays without
    // a new row; renewals and refusals journal nothing; any dev-route
    // probe a driver ran left zero state) --------------------------------
    match client.journal_verify(db) {
        Ok(journal) => report.check(
            "journal verifies and holds exactly the bootstrap's 7 records",
            journal.ok && journal.length == 7,
            &format!("{journal:?}"),
        ),
        Err(error) => {
            report.check("journal verifies and holds exactly the bootstrap's 7 records", false, &error.to_string())
        }
    }

    report
}
