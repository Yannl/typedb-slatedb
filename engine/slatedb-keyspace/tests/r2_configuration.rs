/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! How the R2 backend is selected and tuned.
//!
//! None of this reaches the network. What is being checked is the part that decides *whether*
//! a deployment talks to R2 at all, and with what spending profile — the part where a mistake
//! is silent rather than loud, because a misconfigured store still starts, still serves reads
//! and writes, and only reveals itself as a lost database or an unexpected invoice.

use std::time::Duration;

use slatedb_keyspace::{
    config::{env, MIN_WAL_FLUSHES_BEFORE_L0_FLUSH},
    Backend, KeyspaceError, R2Credentials, StoreConfig, Tuning,
};

fn credentials() -> R2Credentials {
    R2Credentials {
        account_id: "abc123".to_string(),
        bucket: "knowledge-base".to_string(),
        access_key_id: "AKIAEXAMPLE".to_string(),
        secret_access_key: "s3cr3t-do-not-log".to_string(),
        endpoint: None,
    }
}

/// Every environment case in one test, because environment variables are process-global and
/// `cargo test` runs test functions in parallel threads. Split across several tests these
/// would race and fail intermittently — the kind of flake that gets rerun rather than read.
#[test]
fn the_environment_selects_the_backend() {
    for name in [env::ACCOUNT_ID, env::BUCKET, env::ACCESS_KEY_ID, env::SECRET_ACCESS_KEY, env::ENDPOINT]
    {
        std::env::remove_var(name);
    }

    // Nothing set is not an error: it is how the local lane is selected.
    assert!(R2Credentials::from_env().unwrap().is_none());
    let config = StoreConfig::from_env("/tmp/typedb-test", "db").unwrap();
    assert!(matches!(config.backend, Backend::Local { .. }));

    // A half-configured environment must fail loudly. Falling back to local storage here is
    // the dangerous behaviour: the deployment starts, passes health checks, serves traffic,
    // and loses everything when the container is replaced.
    std::env::set_var(env::ACCOUNT_ID, "abc123");
    std::env::set_var(env::BUCKET, "knowledge-base");
    let error = R2Credentials::from_env().unwrap_err();
    let message = error.to_string();
    assert!(matches!(error, KeyspaceError::Config(_)), "got {error:?}");
    assert!(
        message.contains(env::ACCESS_KEY_ID) && message.contains(env::SECRET_ACCESS_KEY),
        "the error must name the variables that are missing, got: {message}"
    );
    assert!(
        message.contains(env::ACCOUNT_ID) && message.contains(env::BUCKET),
        "and the ones that are set, so the mismatch is obvious: {message}"
    );

    // Completing it selects R2.
    std::env::set_var(env::ACCESS_KEY_ID, "AKIAEXAMPLE");
    std::env::set_var(env::SECRET_ACCESS_KEY, "s3cr3t-do-not-log");
    let found = R2Credentials::from_env().unwrap().expect("R2 should be selected");
    assert_eq!(found.account_id, "abc123");
    assert_eq!(found.bucket, "knowledge-base");

    let config = StoreConfig::from_env("/tmp/typedb-test", "db").unwrap();
    assert!(matches!(config.backend, Backend::ObjectStore { .. }));
    assert!(
        config.tuning.cache_dir.is_some(),
        "the R2 lane must come up with a block cache: without one every read is a billed \
         round trip, and that is not a default worth inheriting by accident"
    );

    for name in [env::ACCOUNT_ID, env::BUCKET, env::ACCESS_KEY_ID, env::SECRET_ACCESS_KEY] {
        std::env::remove_var(name);
    }
}

#[test]
fn credentials_are_never_printed() {
    // Config structs reach logs and error messages by routes nobody plans: a `{:?}` in a
    // tracing span, a panic message, a diagnostic dump. A derived `Debug` would put the
    // secret in all of them.
    let rendered = format!("{:?}", credentials());
    assert!(!rendered.contains("s3cr3t-do-not-log"), "secret key leaked into Debug: {rendered}");
    assert!(!rendered.contains("AKIAEXAMPLE"), "access key leaked into Debug: {rendered}");
    assert!(rendered.contains("knowledge-base"), "non-secret fields should still be legible");
}

#[test]
fn the_r2_endpoint_is_account_scoped_and_overridable() {
    let store = StoreConfig::r2("db", &credentials()).unwrap();
    assert!(matches!(store.backend, Backend::ObjectStore { .. }));

    let mut with_override = credentials();
    with_override.endpoint = Some("https://localhost:9000".to_string());
    assert!(StoreConfig::r2("db", &with_override).is_ok(), "a custom endpoint must be accepted");
}

#[test]
fn the_object_storage_profile_departs_from_the_local_one_where_operations_cost_money() {
    let local = Tuning::local();
    let cloud = Tuning::object_storage();

    // The single largest line item. SlateDB's own documentation puts a 100ms flush interval at
    // roughly $130/month in PUT costs; this is the setting that caps it.
    assert!(
        cloud.flush_interval.unwrap() > local.flush_interval.unwrap(),
        "the cloud profile must flush less often than the local one"
    );
    assert!(
        cloud.flush_interval.unwrap() >= Duration::from_secs(1),
        "a sub-second flush interval on a pay-per-operation store is the default this profile \
         exists to override"
    );

    // Reads: filter everything, and keep a local copy.
    assert!(
        cloud.min_filter_keys < local.min_filter_keys,
        "a bloom filter that avoids one R2 GET has already paid for itself"
    );
    assert!(cloud.compression, "text compresses well and storage is billed by the byte");

    // Background chatter that buys nothing in a single-writer deployment.
    assert!(cloud.manifest_poll_interval > local.manifest_poll_interval);
    assert!(cloud.gc_interval.unwrap() > local.gc_interval.unwrap());

    assert!(cloud.validate().is_ok());
    assert!(local.validate().is_ok());
}

#[test]
fn tuning_that_slatedb_would_reject_is_caught_with_the_field_named() {
    let mut tuning = Tuning::object_storage();
    tuning.max_wal_flushes_before_l0_flush = MIN_WAL_FLUSHES_BEFORE_L0_FLUSH - 1;
    let message = tuning.validate().unwrap_err().to_string();
    assert!(
        message.contains("max_wal_flushes_before_l0_flush"),
        "the operator has to be told which knob is wrong, not just that the database will not \
         open: {message}"
    );

    // A cache directory with no budget is a configuration that looks enabled and caches
    // nothing — the worst outcome, because it reads as protected and bills as unprotected.
    let mut tuning = Tuning::object_storage().with_cache_dir("/tmp/cache");
    tuning.cache_max_bytes = 0;
    assert!(tuning.validate().is_err());
}

#[test]
fn the_tuning_reaches_slatedb_intact() {
    // `to_settings` is a wide struct-to-struct copy, which is exactly the shape where a field
    // silently keeps its default. Compression is the one that bit: gating it on the *slatedb*
    // feature name rather than this crate's compiles, always evaluates false, and leaves the
    // setting quietly off.
    let tuning = Tuning::object_storage().with_cache_dir("/tmp/typedb-cache");
    let settings = tuning.to_settings();

    assert_eq!(settings.flush_interval, tuning.flush_interval);
    assert_eq!(settings.manifest_poll_interval, tuning.manifest_poll_interval);
    assert_eq!(settings.min_filter_keys, tuning.min_filter_keys);
    assert_eq!(settings.l0_sst_size_bytes, tuning.l0_sst_size_bytes);
    assert_eq!(settings.object_store_cache_options.root_folder, tuning.cache_dir);
    assert!(settings.object_store_cache_options.cache_on_flush);
    assert!(settings.object_store_cache_options.cache_on_compaction);

    #[cfg(feature = "compression")]
    assert!(
        settings.compression_codec.is_some(),
        "compression is requested and compiled in, so it must actually be configured"
    );

    assert_eq!(settings.object_store_max_retries, tuning.object_store_max_retries);

    let gc = settings.garbage_collector_options.expect("GC stays on");
    assert_eq!(gc.wal_options.unwrap().interval, tuning.gc_interval);
}

#[test]
fn scans_read_ahead_on_object_storage_but_not_on_local_disk() {
    // SlateDB defaults a scan to one block at a time, fetched serially. On disk that is a
    // page-cache hit. Against R2 it is one network round trip per block, which turns a range
    // scan — how a graph database reads almost everything — into a serial chain of them.
    let local = Tuning::local().scan_options();
    let cloud = Tuning::object_storage().scan_options();

    assert!(
        cloud.read_ahead_bytes >= 256 * 1024,
        "a read-ahead window smaller than a few hundred KB leaves the round trips in place"
    );
    assert!(cloud.max_fetch_tasks > local.max_fetch_tasks, "and they should overlap");
    assert_eq!(
        local.read_ahead_bytes,
        slatedb::config::ScanOptions::default().read_ahead_bytes,
        "the local profile stays on SlateDB's defaults so it rehearses upstream behaviour"
    );
}

#[test]
fn object_store_retries_are_bounded() {
    // SlateDB's default is to retry transient errors forever. Behind a synchronous facade the
    // caller is parked inside `block_on` for the whole time, so "forever" is a query thread
    // that never returns and never reports why.
    assert!(
        Tuning::object_storage().object_store_max_retries.is_some(),
        "an unbounded retry under a blocking API is a hang, not resilience"
    );
}
