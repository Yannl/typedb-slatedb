/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::{
    collections::VecDeque,
    ffi::OsString,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock, TryLockError,
        mpsc::{SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};

use concept::{
    thing::statistics::{Statistics, StatisticsError},
    type_::type_manager::{
        TypeManager,
        type_cache::{TypeCache, TypeCacheCreateError},
    },
};
use concurrency::IntervalRunner;
use diagnostics::{
    diagnostics_manager::DiagnosticsManager,
    metrics::{DataLoadMetrics, DatabaseMetricsSnapshot, FsyncMetrics, SchemaLoadMetrics},
};
use durability::{
    DurabilitySequenceNumber, DurabilityServiceError,
    wal::{WAL, WALError},
};
use encoding::{
    EncodingKeyspace,
    error::EncodingError,
    graph::{
        definition::definition_key_generator::DefinitionKeyGenerator, thing::vertex_generator::ThingVertexGenerator,
        type_::vertex_generator::TypeVertexGenerator,
    },
};
use error::typedb_error;
use fail_point::{UNFINISHED_CHECKPOINT, fail_point};
use function::{FunctionError, function_cache::FunctionCache};
use query::query_cache::QueryCache;
use resource::constants::database::{CHECKPOINT_INTERVAL, STATISTICS_UPDATE_INTERVAL};
use storage::{
    MVCCStorage, StorageDeleteError, StorageOpenError, StorageResetError,
    durability_client::{DurabilityClient, DurabilityClientError, WALClient},
    factory::{
        BackendContext, BackendIdentity, BackendSpec, MarkerVerification, StorageFactoryError, read_backend_marker,
        upgrade_backend_marker_to_v2, verify_backend_marker, write_backend_marker,
    },
    keyspace::rocks_resources::RocksResources,
    recovery::checkpoint::{CheckpointCreateError, CheckpointLoadError, CheckpointReader, CheckpointWriter},
    sequence_number::SequenceNumber,
    snapshot::snapshot_id::SnapshotId,
};
use tracing::{Level, debug, event, trace};

use crate::{
    DatabaseOpenError::FunctionCacheInitialise,
    DatabaseResetError::{
        CorruptionPartialResetKeyGeneratorInUse, CorruptionPartialResetThingVertexGeneratorInUse,
        CorruptionPartialResetTypeVertexGeneratorInUse,
    },
    database_manager::DatabaseManager,
    transaction::TransactionError,
};

#[derive(Debug, Clone)]
pub(super) struct Schema {
    pub(super) thing_statistics: Arc<Statistics>,
    pub(super) type_cache: Arc<TypeCache>,
    pub(super) function_cache: Arc<FunctionCache>,
}

type SchemaWriteTransactionState = (bool, usize, VecDeque<TransactionReservationRequest>);

enum TransactionReservationRequest {
    Write(SyncSender<()>),
    Schema(SyncSender<()>),
}

pub struct Database<D> {
    name: Arc<str>,
    pub(super) path: PathBuf,
    pub(super) storage: Arc<MVCCStorage<D>>,
    pub(super) definition_key_generator: Arc<DefinitionKeyGenerator>,
    pub(super) type_vertex_generator: Arc<TypeVertexGenerator>,
    pub(super) thing_vertex_generator: Arc<ThingVertexGenerator>,

    pub(super) schema: Arc<RwLock<Schema>>,
    pub(super) query_cache: Arc<QueryCache>,
    schema_write_transaction_exclusivity: Mutex<SchemaWriteTransactionState>,
    _statistics_updater: IntervalRunner,
    /// R-03: the interval checkpointer is scheduled ONLY on a backend whose
    /// policy permits it (the classic RocksDB lane). On the remote/SlateDB lane
    /// it is `None` — that lane takes controller-frozen global cuts only, and
    /// TypeDB's fixture exporter must never be reachable through the automatic
    /// interval path. The startup attestation proves this field matches the
    /// backend policy.
    _checkpointer: Option<IntervalRunner>,
    /// O-01: last successfully-sampled (storage_in_bytes, storage_key_count).
    /// A metrics scrape that fails (object-store outage) serves this typed stale
    /// value rather than panicking or fabricating a fresh count.
    metrics_last_good: Mutex<Option<(u64, u64)>>,
    /// R4-STOR-01: the immutable backend identity this database was opened
    /// under (from the per-open [`BackendContext`], verified against the
    /// persisted marker). Bound into every checkpoint this database exports,
    /// so a cut can never be restored under a different configuration.
    backend_identity: BackendIdentity,
}

impl<D> fmt::Debug for Database<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database").field("name", &self.name).field("path", &self.path).finish_non_exhaustive()
    }
}

impl<D> Database<D> {
    const TRY_LOCK_SLEEP_INTERVAL: Duration = Duration::from_millis(10);

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn name_arc(&self) -> Arc<str> {
        self.name.clone()
    }

    // Must be called before serving write transactions in case the storage was modified with
    // instances that WERE NOT generated by this server (manual storage modification / replication).
    pub fn prepare_for_writes(&self) -> Result<(), EncodingError> {
        self.thing_vertex_generator.sync_from_storage(self.storage.clone())
    }

    pub(super) fn reserve_write_transaction(&self, timeout_millis: u64) -> Result<(), TransactionError> {
        let (mut guard, timeout_left) =
            self.try_acquire_schema_write_transaction_lock(Duration::from_millis(timeout_millis))?;
        let (has_schema_transaction, running_write_transactions, ref mut notify_queue) = *guard;

        if has_schema_transaction || !notify_queue.is_empty() {
            let (sender, receiver) = sync_channel::<()>(0);
            notify_queue.push_back(TransactionReservationRequest::Write(sender));
            drop(guard);
            receiver.recv_timeout(timeout_left).map_err(|source| TransactionError::Timeout { source })?;
        } else {
            guard.1 = running_write_transactions + 1;
            drop(guard);
        }
        Ok(())
    }

    pub(super) fn reserve_schema_transaction(&self, timeout_millis: u64) -> Result<(), TransactionError> {
        let (mut guard, timeout_left) =
            self.try_acquire_schema_write_transaction_lock(Duration::from_millis(timeout_millis))?;
        let (has_schema_transaction, running_write_transactions, ref mut notify_queue) = *guard;

        if has_schema_transaction || running_write_transactions > 0 || !notify_queue.is_empty() {
            let (sender, receiver) = sync_channel::<()>(0);
            notify_queue.push_back(TransactionReservationRequest::Schema(sender));
            drop(guard);
            receiver.recv_timeout(timeout_left).map_err(|source| TransactionError::Timeout { source })?;
        } else {
            guard.0 = true;
            drop(guard);
        }
        Ok(())
    }

    pub(super) fn release_write_transaction(&self) {
        let mut guard = self
            .schema_write_transaction_exclusivity
            .lock()
            .expect("The exclusive access should already be acquired in `reserve`");
        guard.1 -= 1;
        if guard.1 == 0 {
            Self::fulfill_reservation_requests(&mut guard)
        }
    }

    pub(super) fn release_schema_transaction(&self) {
        let mut guard = self
            .schema_write_transaction_exclusivity
            .lock()
            .expect("The exclusive access should already be acquired in `reserve`");
        guard.0 = false;
        Self::fulfill_reservation_requests(&mut guard)
    }

    fn try_acquire_schema_write_transaction_lock(
        &self,
        timeout: Duration,
    ) -> Result<(MutexGuard<'_, SchemaWriteTransactionState>, Duration), TransactionError> {
        let start_time = Instant::now();
        let guard = loop {
            match self.schema_write_transaction_exclusivity.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => {
                    if start_time.elapsed() >= timeout {
                        return Err(TransactionError::WriteExclusivityTimeout {});
                    }
                    std::thread::sleep(Self::TRY_LOCK_SLEEP_INTERVAL);
                }
                Err(TryLockError::Poisoned(err)) => panic!(
                    "Encountered a poisoned lock while trying to acquire exclusive schema write transaction access: {}",
                    err
                ),
            }
        };

        let elapsed = start_time.elapsed();
        let remaining_timeout = if timeout < elapsed { Duration::from_millis(0) } else { timeout - elapsed };

        Ok((guard, remaining_timeout))
    }

    fn fulfill_reservation_requests(
        guard: &mut MutexGuard<'_, (bool, usize, VecDeque<TransactionReservationRequest>)>,
    ) {
        let (has_schema_transaction, running_write_transactions, notify_queue) = &mut **guard;

        loop {
            let (next_schema, next_write) = match notify_queue.front() {
                Some(TransactionReservationRequest::Schema(_)) => (true, false),
                Some(TransactionReservationRequest::Write(_)) => (false, true),
                None => (false, false),
            };

            if next_schema {
                if *running_write_transactions > 0 {
                    // wait for the write transactions to finish, leave the request in the queue
                    break;
                }
                let TransactionReservationRequest::Schema(notifier) =
                    notify_queue.pop_front().expect("Expected the next schema request")
                else {
                    panic!("Expected the next schema request: the queue cannot be changed")
                };
                if notifier.send(()).is_ok() {
                    // fulfill exactly 1 awaiting schema request
                    *has_schema_transaction = true;
                    break;
                }
            } else if next_write {
                let TransactionReservationRequest::Write(notifier) =
                    notify_queue.pop_front().expect("Expected the next write request")
                else {
                    panic!("Expected the next write request: the queue cannot be changed")
                };
                if notifier.send(()).is_ok() {
                    // fulfill as many write requests as possible
                    *running_write_transactions += 1;
                }
            } else {
                break;
            }
        }
    }
}

impl<D: DurabilityClient> Database<D> {
    pub fn commit_record_exists(
        &self,
        open_sequence_number: DurabilitySequenceNumber,
        snapshot_id: SnapshotId,
    ) -> Result<bool, DatabaseOpenError> {
        self.storage
            .commit_record_exists(open_sequence_number, snapshot_id)
            .map_err(|typedb_source| DatabaseOpenError::DurabilityClientRead { typedb_source })
    }
}

impl Database<WALClient> {
    pub fn open(
        path: &Path,
        diagnostics_manager: &DiagnosticsManager,
        rocks_resources: &RocksResources,
    ) -> Result<Database<WALClient>, DatabaseOpenError> {
        use DatabaseOpenError::InvalidUnicodeName;

        let file_name = path.file_name().unwrap();
        let name = file_name.to_str().ok_or_else(|| InvalidUnicodeName { name: file_name.to_owned() })?;
        let wal_metrics = diagnostics_manager.wal_metrics(name, DatabaseManager::is_internal_database(name));

        // R4-STOR-00: ONE immutable backend context per database open,
        // resolved here — the single admission point — and passed explicitly
        // through marker verification, WAL construction, MVCC/keyspace open,
        // background-task policy, and checkpoint identity binding. No lower
        // layer re-reads the environment; the factory's process witness turns
        // a mid-process environment change into a typed refusal (with the
        // tree untouched), never a half-old/half-new open.
        let context =
            BackendContext::resolve_from_env().map_err(|source| DatabaseOpenError::StorageFactory { source })?;

        if path.exists() {
            Self::load(path, name, wal_metrics, rocks_resources, &context)
        } else {
            Self::create(path, name, wal_metrics, rocks_resources, &context)
        }
    }

    fn create(
        path: &Path,
        name: impl AsRef<str>,
        wal_metrics: FsyncMetrics,
        rocks_resources: &RocksResources,
        context: &BackendContext,
    ) -> Result<Database<WALClient>, DatabaseOpenError> {
        use DatabaseOpenError::{Encoding, FunctionCacheInitialise, StorageOpen, TypeCacheInitialise, WALOpen};

        let name = name.as_ref();

        // S-01/R4-STOR-00: the backend identity was resolved ONCE by the
        // caller (`Database::open`) BEFORE any filesystem, WAL, or
        // object-namespace touch — a not-yet-available lane (U3/U4) or an
        // unknown profile refused there, leaving the database tree
        // non-existent. Here the SAME context binds the directory (marker),
        // WAL, MVCC storage, task policy, and checkpoint identity.
        let factory = context.factory();
        create_backend_bound_directory(path, name, Ok(context.identity().clone()))?;

        let wal = factory.create_wal(path, wal_metrics).map_err(|error| match error {
            StorageFactoryError::WalOpen { source } => WALOpen { source },
            other => DatabaseOpenError::StorageFactory { source: other },
        })?;
        let mut wal_client = WALClient::new(wal);
        wal_client.register_record_type::<Statistics>();

        let storage = Arc::new(
            MVCCStorage::create_with_context::<EncodingKeyspace>(name, path, wal_client, rocks_resources, context)
                .map_err(|error| StorageOpen { typedb_source: error })?,
        );
        let definition_key_generator = Arc::new(DefinitionKeyGenerator::new());
        let type_vertex_generator = Arc::new(TypeVertexGenerator::new());
        let thing_vertex_generator =
            Arc::new(ThingVertexGenerator::load(storage.clone()).map_err(|err| Encoding { source: err })?);
        let thing_statistics = Arc::new(Statistics::new(storage.snapshot_watermark()));

        let type_cache = Arc::new(
            TypeCache::new(storage.clone(), SequenceNumber::MIN)
                .map_err(|error| TypeCacheInitialise { typedb_source: error })?,
        );

        let function_cache = Arc::new(
            FunctionCache::new(
                storage.clone(),
                &TypeManager::new(definition_key_generator.clone(), type_vertex_generator.clone(), None),
                SequenceNumber::MIN,
            )
            .map_err(|error| FunctionCacheInitialise { typedb_source: *error })?,
        );

        let schema = Arc::new(RwLock::new(Schema { thing_statistics, type_cache, function_cache }));
        let schema_txn_lock = Arc::new(RwLock::default());

        let query_cache = Arc::new(QueryCache::new());
        let update_statistics = make_update_statistics_fn(
            name.to_owned(),
            storage.clone(),
            schema.clone(),
            schema_txn_lock.clone(),
            query_cache.clone(),
        );
        let checkpoint_fn = make_checkpoint_fn(
            name.to_owned(),
            path.to_owned(),
            SequenceNumber::MIN,
            storage.clone(),
            context.identity().clone(),
        );

        // R-03: schedule the interval checkpointer ONLY if the backend policy
        // permits it (the classic lane). On the remote lane it is not scheduled
        // — controller-frozen cuts only — and the startup attestation proves it.
        let policy = BackgroundTaskPolicy::for_backend(context.spec());
        let checkpointer =
            policy.interval_checkpointer.then(|| IntervalRunner::new(checkpoint_fn, CHECKPOINT_INTERVAL));
        attest_task_inventory(policy, TaskInventory { interval_checkpointer_scheduled: checkpointer.is_some() })
            .map_err(|source| DatabaseOpenError::ForbiddenBackgroundWorker { name: name.to_owned(), source })?;

        Ok(Database::<WALClient> {
            name: Arc::<str>::from(name),
            path: path.to_owned(),
            storage,
            definition_key_generator,
            type_vertex_generator,
            thing_vertex_generator,
            schema,
            query_cache,
            schema_write_transaction_exclusivity: Mutex::new((false, 0, VecDeque::with_capacity(100))),
            _statistics_updater: IntervalRunner::new(update_statistics, STATISTICS_UPDATE_INTERVAL),
            _checkpointer: checkpointer,
            metrics_last_good: Mutex::new(None),
            backend_identity: context.identity().clone(),
        })
    }

    fn load(
        path: &Path,
        name: impl AsRef<str>,
        wal_metrics: FsyncMetrics,
        rocks_resources: &RocksResources,
        context: &BackendContext,
    ) -> Result<Database<WALClient>, DatabaseOpenError> {
        use DatabaseOpenError::{
            CheckpointCreate, CheckpointLoad, DurabilityClientRead, Encoding, NotADatabase, StatisticsInitialise,
            StorageOpen, TypeCacheInitialise, WALOpen,
        };
        let name = name.as_ref();
        event!(
            Level::TRACE,
            "Loading database '{}', at path '{:?}' (absolute path: '{:?}').",
            &name,
            path,
            std::path::absolute(path)
        );

        // S-01/R4-STOR-01: the backend identity was resolved ONCE by the
        // caller (`Database::open`); VERIFY it — every field, not just the
        // kind — against the database's persisted marker BEFORE touching the
        // WAL or storage tree. A missing marker (ambiguous/unmarked database)
        // demands an explicit migration; ANY mismatch (kind, endpoint,
        // bucket, prefix, policy, protocol) is a typed refusal that leaves
        // the tree, WAL, and object namespace byte-identical — never a
        // silent cross-engine or cross-configuration open.
        let resolved_identity = context.identity();
        let persisted_marker =
            read_backend_marker(path).map_err(|source| DatabaseOpenError::StorageFactory { source })?;
        match &persisted_marker {
            // a marked database: verify the full identity BEFORE any touch.
            Some(marker) => {
                let verification = verify_backend_marker(resolved_identity, Some(marker))
                    .map_err(|source| DatabaseOpenError::StorageFactory { source })?;
                if verification == MarkerVerification::LegacyV1Verified {
                    // R4-STOR-01: the documented ONE-TIME upgrade — a legacy
                    // v1 (kind-only) marker whose kind verified against the
                    // resolved identity is rewritten in place, atomically, as
                    // the full v2 identity. This is the single sanctioned
                    // marker replacement; every subsequent open verifies the
                    // full v2 identity.
                    upgrade_backend_marker_to_v2(path, resolved_identity).map_err(|source| {
                        DatabaseOpenError::DirectoryCreate { name: name.to_owned(), source: Arc::new(source) }
                    })?;
                }
            }
            // no marker: distinguish a real-but-unmarked database (a migration
            // case — refuse) from a stray non-database directory (NotADatabase,
            // so the manager's scan skips it as before). The WAL directory's
            // presence is the database indicator, checked without opening it.
            None => {
                if path.join(WAL::WAL_DIR_NAME).exists() {
                    return Err(DatabaseOpenError::StorageFactory {
                        source: StorageFactoryError::BackendMarkerMissing,
                    });
                }
            }
        }
        let factory = context.factory();

        event!(Level::TRACE, "Loading database '{}' WAL.", &name);
        let wal = match factory.load_wal(path, wal_metrics) {
            Ok(wal) => wal,
            Err(StorageFactoryError::WalOpen {
                source: DurabilityServiceError::WAL { source: WALError::LoadDirectoryMissing { .. } },
            }) => {
                return Err(NotADatabase { name: name.to_owned() });
            }
            Err(StorageFactoryError::WalOpen { source }) => return Err(WALOpen { source }),
            Err(other) => return Err(DatabaseOpenError::StorageFactory { source: other }),
        };

        let wal_last_sequence_number = wal.previous();

        let mut wal_client = WALClient::new(wal);
        wal_client.register_record_type::<Statistics>();

        event!(Level::TRACE, "Loading last database '{}' checkpoint", &name);
        // R4-STOR-10: enumerate EVERY digest-verified checkpoint candidate,
        // newest first, and let storage recovery walk them with typed
        // fallback (newest ahead/corrupt/uncovered -> next older -> full WAL
        // replay with proven coverage) instead of pinning recovery to the
        // single newest cut.
        let checkpoints = CheckpointReader::enumerate_verified::<EncodingKeyspace>(path)
            .map_err(|err| CheckpointLoad { name: name.to_string(), typedb_source: err })?;
        let (storage, restored_checkpoint_watermark) = MVCCStorage::load_with_recovery_fallback::<EncodingKeyspace>(
            &name,
            path,
            wal_client,
            checkpoints,
            rocks_resources,
            context,
        )
        .map_err(|error| StorageOpen { typedb_source: error })?;
        let storage = Arc::new(storage);
        let definition_key_generator = Arc::new(DefinitionKeyGenerator::new());
        let type_vertex_generator = Arc::new(TypeVertexGenerator::new());
        let thing_vertex_generator =
            Arc::new(ThingVertexGenerator::load(storage.clone()).map_err(|err| Encoding { source: err })?);

        event!(Level::TRACE, "Finding last database '{}' statistics WAL entry", &name);
        let mut thing_statistics = storage
            .durability()
            .find_last_unsequenced_type::<Statistics>()
            .map_err(|typedb_source| DurabilityClientRead { typedb_source })?
            .unwrap_or_else(|| Statistics::new(SequenceNumber::MIN));
        event!(
            Level::TRACE,
            "Synchronising database '{}' statistics from seq nr '{}'",
            &name,
            thing_statistics.sequence_number
        );
        thing_statistics.may_synchronise(&storage).map_err(|err| StatisticsInitialise { typedb_source: err })?;
        if thing_statistics.sequence_number > thing_statistics.last_durable_write_sequence_number {
            thing_statistics
                .durably_write(storage.durability())
                .map_err(|err| StatisticsInitialise { typedb_source: err })?;
        }
        event!(Level::TRACE, "Thing statistics: {:?}", thing_statistics);
        let thing_statistics = Arc::new(thing_statistics);

        let type_cache = Arc::new(
            TypeCache::new(storage.clone(), wal_last_sequence_number)
                .map_err(|error| TypeCacheInitialise { typedb_source: error })?,
        );

        let function_cache = Arc::new(
            FunctionCache::new(
                storage.clone(),
                &TypeManager::new(definition_key_generator.clone(), type_vertex_generator.clone(), None),
                wal_last_sequence_number,
            )
            .map_err(|error| FunctionCacheInitialise { typedb_source: *error })?,
        );

        let schema = Arc::new(RwLock::new(Schema { thing_statistics, type_cache, function_cache }));
        let schema_txn_lock = Arc::new(RwLock::default());

        // R4-STOR-10: the catch-up decision below reasons about the cut that
        // was actually RESTORED (which, under fallback, may be older than the
        // newest on disk), not the newest directory listing entry. A full-WAL
        // recovery reports MIN — everything since the beginning is uncovered
        // by any checkpoint.
        let checkpoint_sequence_number = restored_checkpoint_watermark.unwrap_or(SequenceNumber::MIN);

        let query_cache = Arc::new(QueryCache::new());
        let update_statistics = make_update_statistics_fn(
            name.to_owned(),
            storage.clone(),
            schema.clone(),
            schema_txn_lock.clone(),
            query_cache.clone(),
        );
        let checkpoint_fn = make_checkpoint_fn(
            name.to_owned(),
            path.to_owned(),
            checkpoint_sequence_number,
            storage.clone(),
            context.identity().clone(),
        );

        // R-03/R-04: construct with NO periodic checkpointer yet, so the
        // synchronous startup catch-up below runs BEFORE any periodic task —
        // periodic tasks are started only after startup catch-up, and never at
        // all on the controller-frozen lane.
        let mut database = Database::<WALClient> {
            name: Arc::<str>::from(name),
            path: path.to_owned(),
            storage,
            definition_key_generator,
            type_vertex_generator,
            thing_vertex_generator,
            schema,
            query_cache,
            schema_write_transaction_exclusivity: Mutex::new((false, 0, VecDeque::with_capacity(100))),
            _statistics_updater: IntervalRunner::new(update_statistics, STATISTICS_UPDATE_INTERVAL),
            _checkpointer: None,
            metrics_last_good: Mutex::new(None),
            backend_identity: context.identity().clone(),
        };

        // startup catch-up checkpoint (an explicit, one-shot cut — not the
        // automatic interval path) runs while no periodic task is scheduled —
        // and ONLY on a lane whose policy permits a local exporter cut
        // (R4-STOR-11): on the remote-shaped lanes the Slate checkpoint
        // function is a conformance fixture that must never be wired into a
        // production path, and cuts are controller-owned.
        let policy = BackgroundTaskPolicy::for_backend(context.spec());
        let catchup_outcome = run_startup_catchup_checkpoint(
            &policy,
            checkpoint_sequence_number < wal_last_sequence_number,
            || database.checkpoint(),
        )
        .map_err(|err| CheckpointCreate { name: name.to_string(), source: err })?;
        if catchup_outcome == StartupCatchup::DeferredToController {
            // Correctness-safe: recovery has already replayed the WAL into
            // the live keyspaces, so skipping the cut loses no durability —
            // it only leaves recovery time and WAL retention unbounded until
            // a controller-owned cut lands. Record that loudly.
            event!(
                Level::INFO,
                "Database '{}' started with its WAL ahead of the newest usable checkpoint on a remote-shaped \
                 backend. The startup catch-up checkpoint was skipped: remote checkpoints are controller-owned \
                 and the local exporter is a conformance fixture. Recovery replayed the WAL; a controller-owned \
                 cut is required to bound future recovery time.",
                &name
            );
        }

        // NOW, after catch-up, start the interval checkpointer if — and only if
        // — the backend policy permits it, and attest the result.
        database._checkpointer = policy
            .interval_checkpointer
            .then(|| IntervalRunner::new_with_initial_delay(checkpoint_fn, CHECKPOINT_INTERVAL, CHECKPOINT_INTERVAL));
        attest_task_inventory(
            policy,
            TaskInventory { interval_checkpointer_scheduled: database._checkpointer.is_some() },
        )
        .map_err(|source| DatabaseOpenError::ForbiddenBackgroundWorker { name: name.to_owned(), source })?;

        database.prepare_for_writes().map_err(|typedb_source| DatabaseOpenError::Encoding { source: typedb_source })?;
        event!(Level::TRACE, "Finished loading database '{}'", &name);
        Ok(database)
    }

    fn checkpoint(&self) -> Result<(), CheckpointCreateError> {
        checkpoint_storage(&self.name, &self.path, &self.storage, &self.backend_identity)
    }

    #[allow(clippy::drop_non_drop)]
    pub fn delete(self) -> Result<(), DatabaseDeleteError> {
        trace!("Deleting database '{}'.", &self.name);
        drop(self._statistics_updater);
        drop(self._checkpointer);
        drop(Arc::into_inner(self.schema).expect("Cannot get exclusive ownership of inner of Arc<Schema>."));
        drop(Arc::into_inner(self.query_cache).expect("Cannot get exclusive ownership of inner of Arc<QueryCache>."));
        drop(
            Arc::into_inner(self.type_vertex_generator)
                .expect("Cannot get exclusive ownership of inner of Arc<TypeVertexGenerator>"),
        );
        drop(
            Arc::into_inner(self.thing_vertex_generator)
                .expect("Cannot get exclusive ownership of inner of Arc<ThingVertexGenerator>"),
        );
        drop(
            Arc::into_inner(self.definition_key_generator)
                .expect("Cannot get exclusive ownership of inner of Arc<DefinitionKeyGenerator>"),
        );
        Arc::into_inner(self.storage)
            .expect("Cannot get exclusive ownership of inner of Arc<MVCCStorage>.")
            .delete_storage()
            .map_err(|err| DatabaseDeleteError::StorageDelete { typedb_source: err })?;
        let path = self.path;
        fs::remove_dir_all(path).map_err(|err| DatabaseDeleteError::DirectoryDelete { source: Arc::new(err) })?;
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), DatabaseResetError> {
        use DatabaseResetError::CorruptionPartialResetStorageInUse;

        self.reserve_schema_transaction(Duration::from_secs(60).as_millis() as u64)
            .map_err(|typedb_source| DatabaseResetError::Transaction { typedb_source })?; // exclusively lock out other write or schema transactions;
        let mut locked_schema = self.schema.write().unwrap();

        match Arc::get_mut(&mut self.storage) {
            None => return Err(DatabaseResetError::StorageInUse {}),
            Some(storage) => {
                storage.reset().map_err(|err| CorruptionPartialResetStorageInUse { typedb_source: err })?
            }
        }
        match Arc::get_mut(&mut self.definition_key_generator) {
            None => return Err(CorruptionPartialResetKeyGeneratorInUse {}),
            Some(definition_key_generator) => definition_key_generator.reset(),
        }
        match Arc::get_mut(&mut self.type_vertex_generator) {
            None => return Err(CorruptionPartialResetTypeVertexGeneratorInUse {}),
            Some(type_vertex_generator) => type_vertex_generator.reset(),
        }
        match Arc::get_mut(&mut self.thing_vertex_generator) {
            None => return Err(CorruptionPartialResetThingVertexGeneratorInUse {}),
            Some(thing_vertex_generator) => thing_vertex_generator.reset(),
        }

        let thing_statistics = Arc::get_mut(&mut locked_schema.thing_statistics).unwrap();
        thing_statistics.reset(self.storage.snapshot_watermark());

        self.query_cache.force_reset(&Statistics::new(SequenceNumber::MIN));

        self.release_schema_transaction();
        Ok(())
    }

    pub fn get_metrics(&self) -> DatabaseMetricsSnapshot {
        // Storage estimates are read FIRST, holding no schema lock (donor
        // A6): the key-count estimate can touch the object store, and holding
        // the schema read-lock across it would block every schema transaction
        // for the duration of a remote round trip. These reads depend only on
        // `self.storage`, never on `self.schema`, so hoisting them out is
        // free. (The remote key-count scan is itself bounded by the storage
        // engine's staleness memo.)
        // O-01: a diagnostics scrape must NEVER panic the process. A failed
        // storage sample (e.g. a brief object-store outage on the remote lane)
        // serves the last-good pair as typed stale state instead of the old
        // `.expect` that aborted the whole scrape; a cold failure serves the
        // honest zero default, never a fabricated post-failure count.
        let (storage_in_bytes, storage_key_count) = resolve_storage_metrics(
            self.storage.estimate_size_in_bytes().ok(),
            self.storage.estimate_key_count().ok(),
            &self.metrics_last_good,
        );
        let schema = self.schema.read().expect("Expected database schema lock acquisition");
        DatabaseMetricsSnapshot {
            schema: SchemaLoadMetrics { type_count: schema.type_cache.get_types_count() },
            data: DataLoadMetrics {
                entity_count: schema.thing_statistics.total_entity_count,
                relation_count: schema.thing_statistics.total_relation_count,
                attribute_count: schema.thing_statistics.total_attribute_count,
                has_count: schema.thing_statistics.total_has_count,
                role_count: schema.thing_statistics.total_role_count,
                storage_in_bytes,
                storage_key_count,
            },
        }
    }
}

/// R-03: which background workers a backend's policy permits. Derived from the
/// typed [`BackendSpec`] (NOT the conformance profile), so background scheduling
/// is part of the backend contract rather than an unconditional default. On the
/// remote/SlateDB lane TypeDB's INTERVAL checkpointer is forbidden — that lane
/// takes controller-frozen global cuts only; the classic RocksDB lane runs it
/// exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackgroundTaskPolicy {
    pub interval_checkpointer: bool,
    /// R4-STOR-11: whether STARTUP may take the one-shot catch-up checkpoint
    /// when the WAL is ahead of the newest usable cut. True only on the local
    /// conformance lanes (classic RocksDB; SlateDB over local-fs, whose
    /// exporter is the sanctioned single-actor conformance fixture). False on
    /// every remote-shaped lane: the Slate checkpoint function documents "Do
    /// not wire it into any production path", and remote cuts are
    /// controller-owned — a WAL-ahead remote startup proceeds WITHOUT a
    /// catch-up cut (recovery has already replayed the WAL, so this is a
    /// durability no-op; only recovery time/retention are affected) and logs
    /// that a controller-owned cut is required.
    pub startup_catchup_checkpointer: bool,
}

impl BackgroundTaskPolicy {
    pub(crate) fn for_backend(spec: &BackendSpec) -> Self {
        match spec {
            BackendSpec::Classic => Self { interval_checkpointer: true, startup_catchup_checkpointer: true },
            // the remote lane's fixture exporter must never be automatically
            // reachable — controller-frozen cuts only. The interval
            // checkpointer is forbidden on EVERY Slate lane; the one-shot
            // startup catch-up remains permitted solely on the local-fs
            // conformance lane (U2), and is fail-closed for any other object
            // store profile (s3/U2S3 today, anything remote-shaped tomorrow).
            BackendSpec::SlateDbR2(spec) => Self {
                interval_checkpointer: false,
                startup_catchup_checkpointer: spec.object_store_profile == "local-fs",
            },
        }
    }
}

/// R4-STOR-11: outcome of the startup catch-up checkpoint decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupCatchup {
    /// WAL ahead on a permitted (local conformance) lane: the cut ran.
    Ran,
    /// The newest usable checkpoint already covers the WAL head.
    NotNeeded,
    /// WAL ahead on a remote-shaped lane: the cut is controller-owned, so
    /// startup proceeds without one. Recovery already replayed the WAL —
    /// correctness is unaffected; the caller logs that a controller cut is
    /// required to bound recovery time.
    DeferredToController,
}

/// R4-STOR-11: the ONLY seam through which startup reaches a checkpoint
/// exporter. The `checkpoint` closure is invoked if and only if the WAL is
/// ahead AND the backend policy permits a startup catch-up cut — so on a
/// remote-shaped backend the (conformance-fixture) Slate exporter is
/// structurally unreachable from startup. The reachability test proves it by
/// passing a closure that panics if called.
fn run_startup_catchup_checkpoint<E>(
    policy: &BackgroundTaskPolicy,
    wal_ahead_of_checkpoint: bool,
    checkpoint: impl FnOnce() -> Result<(), E>,
) -> Result<StartupCatchup, E> {
    if !wal_ahead_of_checkpoint {
        return Ok(StartupCatchup::NotNeeded);
    }
    if !policy.startup_catchup_checkpointer {
        return Ok(StartupCatchup::DeferredToController);
    }
    checkpoint()?;
    Ok(StartupCatchup::Ran)
}

/// R-03: the background workers actually scheduled for a database instance. The
/// startup attestation compares this against the backend policy and proves the
/// forbidden workers are absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskInventory {
    pub interval_checkpointer_scheduled: bool,
}

/// R-03: prove no background worker the policy forbids is actually scheduled. On
/// the controller-frozen (remote) lane a scheduled interval checkpointer is a
/// typed refusal — the "forbidden interval-checkpoint worker is absent"
/// attestation. Re-enabling the automatic remote checkpoint (scheduling it in
/// defiance of the policy) fails this attestation: the R-03 mutant a named test
/// kills.
pub(crate) fn attest_task_inventory(
    policy: BackgroundTaskPolicy,
    inventory: TaskInventory,
) -> Result<(), ForbiddenWorkerError> {
    if !policy.interval_checkpointer && inventory.interval_checkpointer_scheduled {
        return Err(ForbiddenWorkerError::IntervalCheckpointerOnControllerFrozenLane);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForbiddenWorkerError {
    IntervalCheckpointerOnControllerFrozenLane,
}

impl fmt::Display for ForbiddenWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntervalCheckpointerOnControllerFrozenLane => {
                write!(f, "the interval checkpointer is forbidden on the controller-frozen lane")
            }
        }
    }
}

impl std::error::Error for ForbiddenWorkerError {}

/// O-01: resolve the two storage metrics totally — never panicking, never
/// fabricating a fresh count after a failure. On success both values update the
/// last-good memo and are returned fresh. On ANY sampling failure the last-good
/// pair is served as typed stale state (or `(0, 0)` if nothing was ever sampled
/// — the genuine no-measurement default, not a fabricated post-failure count).
/// The old `get_metrics` called `.expect` on each sample and panicked the whole
/// scrape when the object store was briefly unavailable.
fn resolve_storage_metrics(
    sampled_bytes: Option<u64>,
    sampled_keys: Option<u64>,
    last_good: &Mutex<Option<(u64, u64)>>,
) -> (u64, u64) {
    let mut guard = last_good.lock().unwrap();
    match (sampled_bytes, sampled_keys) {
        (Some(bytes), Some(keys)) => {
            *guard = Some((bytes, keys));
            (bytes, keys)
        }
        // a failed (partial or total) sample serves the last consistent pair,
        // or the honest zero default if none has ever succeeded.
        _ => guard.unwrap_or((0, 0)),
    }
}

fn make_checkpoint_fn(
    database_name: String,
    path: PathBuf,
    mut prev_checkpoint: SequenceNumber,
    storage: Arc<MVCCStorage<WALClient>>,
    backend_identity: BackendIdentity,
) -> impl FnMut() {
    move || {
        let watermark = storage.snapshot_watermark();
        if prev_checkpoint < watermark {
            if let Err(error) = checkpoint_storage(&database_name, &path, &storage, &backend_identity) {
                // Fail-stop, not unwind: this closure runs on a detached
                // interval thread, where a panic kills only the checkpointer
                // and the server keeps serving with checkpoints silently
                // stopped — unbounded WAL growth and unbounded recovery time.
                // Checkpointing is a correctness task; a loud stop that
                // recovers from the WAL on restart is the lesser harm.
                logger::error!("{}", checkpoint_failure_fatal_message(&database_name, &error));
                std::process::abort();
            }
            prev_checkpoint = watermark;
        }
    }
}

/// The FATAL message for a periodic-checkpoint failure. Extracted so the
/// error branch is unit-testable: the branch itself ends in `process::abort`,
/// which no test can cross.
/// S-01 create ordering: resolve the backend identity, and ONLY on success
/// create the database directory and persist the marker atomically. The
/// ORDERING is the invariant — a backend refusal (unknown profile /
/// not-yet-available lane) must leave `path` non-existent, so no directory,
/// WAL, or object namespace is ever created beside another backend's files
/// before the refusal. Extracted as a pure function (the resolution result is
/// an argument, not read from the process-global env) so the "no touch before
/// refusal" ordering is hermetically unit-testable and its mutant — creating
/// the directory before the refusal — fails a named test.
fn create_backend_bound_directory(
    path: &Path,
    name: &str,
    resolved: Result<BackendIdentity, StorageFactoryError>,
) -> Result<(), DatabaseOpenError> {
    create_backend_bound_directory_with(path, name, resolved, write_backend_marker)
}

/// The parameterised body of [`create_backend_bound_directory`] (the marker
/// writer is injected so the failure-cleanup contract is hermetically
/// testable). R4-STOR-02 ownership rule: `fs::create_dir` fails with
/// `AlreadyExists` unless THIS call created the directory, so its success is
/// the proof of ownership — and on a marker-write failure the directory is
/// removed if and only if this attempt owns it AND it is still empty
/// (`fs::remove_dir` refuses a non-empty directory atomically, so nothing
/// another actor put there can ever be deleted). A pre-existing directory is
/// never touched by the failure path.
fn create_backend_bound_directory_with(
    path: &Path,
    name: &str,
    resolved: Result<BackendIdentity, StorageFactoryError>,
    write_marker: impl FnOnce(&Path, &BackendIdentity) -> io::Result<()>,
) -> Result<(), DatabaseOpenError> {
    use DatabaseOpenError::DirectoryCreate;
    // resolve FIRST — refuse before any filesystem touch.
    let identity = resolved.map_err(|source| DatabaseOpenError::StorageFactory { source })?;
    // only now touch the filesystem... (success == this attempt owns the dir)
    fs::create_dir(path).map_err(|source| DirectoryCreate { name: name.to_string(), source: Arc::new(source) })?;
    // ...and bind the database to its backend identity before any
    // keyspace/WAL data lands, so a later open can detect a cross-engine or
    // cross-configuration mismatch.
    if let Err(source) = write_marker(path, &identity) {
        // R4-STOR-02: no stray directory on a pre-WAL failure. This attempt
        // created `path` (ownership proven above) and nothing else has been
        // written into it (a failed marker write cleans its own temp file),
        // so remove it — `remove_dir` is the atomic emptiness check: it
        // refuses a non-empty directory, so anything that raced content into
        // the directory survives. Best-effort: the marker error is the one
        // reported either way.
        let _ = fs::remove_dir(path);
        return Err(DirectoryCreate { name: name.to_string(), source: Arc::new(source) });
    }
    Ok(())
}

fn checkpoint_failure_fatal_message(database_name: &str, error: &impl fmt::Debug) -> String {
    format!(
        "FATAL: periodic checkpoint for database '{database_name}' failed: {error:?}. A silently dead \
         checkpointer is worse than a stopped server; aborting so the database recovers from the WAL on restart."
    )
}

/// The (non-fatal) message for a periodic statistics-update failure.
/// Statistics are an observational optimisation, not a correctness task:
/// the updater logs, skips this round, and retries on the next interval.
fn statistics_failure_message(database_name: &str, error: &impl fmt::Debug) -> String {
    format!(
        "Periodic statistics update for database '{database_name}' failed: {error:?}. Keeping the \
         previous statistics; the update will be retried on the next interval."
    )
}

fn checkpoint_storage(
    database_name: &str,
    path: &Path,
    storage: &MVCCStorage<WALClient>,
    backend_identity: &BackendIdentity,
) -> Result<(), CheckpointCreateError> {
    debug!("Starting checkpoint for database {database_name}");
    let checkpoint = CheckpointWriter::new(path)?;
    storage.checkpoint(&checkpoint)?;
    // R4-STOR-01: bind this database's backend identity into the cut BEFORE
    // finish() seals the tree — the digest-bound COMPLETE manifest then
    // covers the identity file, and restore refuses this cut under any other
    // backend configuration.
    checkpoint.add_identity(backend_identity)?;
    fail_point!(UNFINISHED_CHECKPOINT);
    checkpoint.finish()?;
    debug!("Finished checkpoint for database {database_name}");
    Ok(())
}

fn make_update_statistics_fn(
    database_name: String,
    storage: Arc<MVCCStorage<WALClient>>,
    schema: Arc<RwLock<Schema>>,
    schema_txn_lock: Arc<RwLock<()>>,
    query_cache: Arc<QueryCache>,
) -> impl Fn() {
    move || {
        if storage.snapshot_watermark() > schema.read().unwrap().thing_statistics.sequence_number {
            let _schema_txn_guard = schema_txn_lock.read().unwrap(); // prevent Schema txns from opening during statistics update
            let mut new_statistics = (*schema.read().unwrap().thing_statistics).clone();
            debug!("Starting updating statistics for database {database_name}");
            if let Err(error) = new_statistics.may_synchronise(&storage) {
                // non-correctness task: a failed sync must not kill the
                // updater thread (an `expect` here silently ended every
                // future update) — log, keep the previous statistics, retry
                // on the next interval
                logger::error!("{}", statistics_failure_message(&database_name, &error));
                return;
            }
            let new_statistics = Arc::new(new_statistics);
            query_cache.set_statistics_and_invalidate_outdated(new_statistics.clone());
            schema.write().unwrap().thing_statistics = new_statistics;
            debug!("Finished updating statistics for database {}", database_name.as_str());
        }
    }
}

#[cfg(test)]
mod interval_task_failure_tests {
    //! S-P0-05 controls: the interval-thread failure branches. The branches
    //! themselves end in `process::abort` (checkpoint) or an early return
    //! (statistics), so the testable surface is the extracted policy: the
    //! checkpoint message is FATAL and names the database (matching the
    //! fail-stop doctrine for correctness-task failure); the statistics
    //! message is explicitly a keep-going retry.

    use super::{checkpoint_failure_fatal_message, statistics_failure_message};

    #[test]
    fn checkpoint_failure_is_fatal_and_names_the_database() {
        let message = checkpoint_failure_fatal_message("orders-db", &"disk unplugged");
        assert!(message.starts_with("FATAL:"), "correctness-task failure must be marked FATAL: {message}");
        assert!(message.contains("orders-db"), "the message must name the database: {message}");
        assert!(message.contains("disk unplugged"), "the message must carry the cause: {message}");
        assert!(message.contains("abort"), "the message must state the fail-stop consequence: {message}");
    }

    #[test]
    fn statistics_failure_is_a_logged_retry_not_a_stop() {
        let message = statistics_failure_message("orders-db", &"sync raced a reset");
        assert!(!message.contains("FATAL"), "statistics are not a correctness task: {message}");
        assert!(message.contains("orders-db"), "the message must name the database: {message}");
        assert!(message.contains("retried"), "the message must state that the updater keeps running: {message}");
    }
}

#[cfg(test)]
mod background_task_policy_tests {
    //! R-03: background tasks are part of the backend policy. The interval
    //! checkpointer runs on the classic lane and is FORBIDDEN on the remote
    //! (controller-frozen) lane, and a startup attestation proves the forbidden
    //! worker is absent.

    use storage::factory::{BackendSpec, SlateDbR2Spec};

    use super::{BackgroundTaskPolicy, ForbiddenWorkerError, TaskInventory, attest_task_inventory};

    pub(super) fn slate_local_fs_spec() -> BackendSpec {
        BackendSpec::SlateDbR2(SlateDbR2Spec {
            object_store_profile: "local-fs",
            materialisation_policy: "fresh-per-open-no-inplace",
            cache_policy: "none",
            protocol_versions: "fv1",
        })
    }

    pub(super) fn slate_s3_spec() -> BackendSpec {
        BackendSpec::SlateDbR2(SlateDbR2Spec {
            object_store_profile: "s3",
            materialisation_policy: "fresh-per-open-no-inplace",
            cache_policy: "none",
            protocol_versions: "fv1",
        })
    }

    #[test]
    fn the_classic_lane_runs_the_interval_checkpointer() {
        let policy = BackgroundTaskPolicy::for_backend(&BackendSpec::Classic);
        assert!(policy.interval_checkpointer, "the classic lane runs the interval checkpointer");
        // a classic database that scheduled it attests cleanly
        assert!(
            attest_task_inventory(policy, TaskInventory { interval_checkpointer_scheduled: true }).is_ok(),
            "the classic lane may schedule the interval checkpointer"
        );
    }

    #[test]
    fn the_slatedb_lane_forbids_the_interval_checkpointer_and_attests_when_absent() {
        for spec in [slate_local_fs_spec(), slate_s3_spec()] {
            let policy = BackgroundTaskPolicy::for_backend(&spec);
            assert!(!policy.interval_checkpointer, "every Slate lane takes controller-frozen cuts only");
            // the real remote-lane inventory (worker absent) passes the attestation
            assert!(
                attest_task_inventory(policy, TaskInventory { interval_checkpointer_scheduled: false }).is_ok(),
                "the remote lane with no interval checkpointer scheduled attests cleanly"
            );
        }
    }

    #[test]
    fn re_enabling_the_automatic_remote_checkpoint_fails_attestation() {
        // R-03 mutant catcher: scheduling the interval checkpointer on the
        // controller-frozen lane (re-enabling the automatic remote checkpoint)
        // is a typed attestation failure. The mutant that schedules it in
        // defiance of the policy is caught HERE.
        let policy = BackgroundTaskPolicy::for_backend(&slate_local_fs_spec());
        let result = attest_task_inventory(policy, TaskInventory { interval_checkpointer_scheduled: true });
        assert_eq!(
            result,
            Err(ForbiddenWorkerError::IntervalCheckpointerOnControllerFrozenLane),
            "an interval checkpointer on the remote lane must fail the startup attestation"
        );
    }
}

#[cfg(test)]
mod startup_catchup_policy_tests {
    //! R4-STOR-11: the startup catch-up checkpoint is part of the backend
    //! policy. The local conformance lanes (classic RocksDB, SlateDB over
    //! local-fs) keep the WAL-ahead catch-up cut; every remote-shaped lane
    //! (s3 today, any non-local-fs object store profile tomorrow) defers to a
    //! controller-owned cut, so the Slate conformance-fixture exporter is
    //! structurally unreachable from a production-shaped startup.

    use std::cell::Cell;

    use storage::factory::BackendSpec;

    use super::{
        BackgroundTaskPolicy, StartupCatchup,
        background_task_policy_tests::{slate_local_fs_spec, slate_s3_spec},
        run_startup_catchup_checkpoint,
    };

    #[test]
    fn the_local_lanes_permit_the_startup_catchup() {
        for spec in [BackendSpec::Classic, slate_local_fs_spec()] {
            let policy = BackgroundTaskPolicy::for_backend(&spec);
            assert!(
                policy.startup_catchup_checkpointer,
                "the local conformance lanes keep the startup catch-up checkpoint: {spec:?}"
            );
        }
    }

    #[test]
    fn the_remote_shaped_lane_forbids_the_startup_catchup() {
        let policy = BackgroundTaskPolicy::for_backend(&slate_s3_spec());
        assert!(
            !policy.startup_catchup_checkpointer,
            "R4-STOR-11: a remote-shaped lane must not take a local startup catch-up cut"
        );
    }

    #[test]
    fn a_remote_shaped_wal_ahead_startup_cannot_reach_the_checkpoint_exporter() {
        // Reachability proof: the closure below stands in for the checkpoint
        // exporter (the only startup path to the Slate conformance fixture)
        // and panics if invoked. On the remote-shaped lane with the WAL ahead,
        // the seam must return the typed deferral WITHOUT invoking it.
        let policy = BackgroundTaskPolicy::for_backend(&slate_s3_spec());
        let outcome = run_startup_catchup_checkpoint(&policy, true, || -> Result<(), ()> {
            panic!("the checkpoint exporter (conformance fixture) was reached from a remote-shaped startup")
        })
        .expect("deferral is not an error");
        assert_eq!(
            outcome,
            StartupCatchup::DeferredToController,
            "a WAL-ahead remote-shaped startup defers to a controller-owned cut"
        );
    }

    #[test]
    fn the_u2_local_lane_wal_ahead_startup_still_takes_the_catchup_cut() {
        // positive control for the reachability proof: the same seam DOES run
        // the exporter on the local conformance lane.
        let policy = BackgroundTaskPolicy::for_backend(&slate_local_fs_spec());
        let ran = Cell::new(false);
        let outcome = run_startup_catchup_checkpoint(&policy, true, || -> Result<(), ()> {
            ran.set(true);
            Ok(())
        })
        .expect("the catch-up cut succeeds");
        assert_eq!(outcome, StartupCatchup::Ran, "the U2 local lane runs the startup catch-up");
        assert!(ran.get(), "the exporter closure must actually have been invoked on the local lane");
    }

    #[test]
    fn no_catchup_runs_when_the_wal_is_not_ahead() {
        // WAL not ahead: no lane runs the exporter, remote or local.
        for spec in [BackendSpec::Classic, slate_local_fs_spec(), slate_s3_spec()] {
            let policy = BackgroundTaskPolicy::for_backend(&spec);
            let outcome = run_startup_catchup_checkpoint(&policy, false, || -> Result<(), ()> {
                panic!("no catch-up may run when the checkpoint already covers the WAL head")
            })
            .expect("not needed is not an error");
            assert_eq!(outcome, StartupCatchup::NotNeeded);
        }
    }

    #[test]
    fn a_failing_catchup_cut_propagates_its_typed_error() {
        // the permitted lane still propagates the exporter's typed failure —
        // the deferral path is not a blanket error swallow.
        let policy = BackgroundTaskPolicy::for_backend(&BackendSpec::Classic);
        let result = run_startup_catchup_checkpoint(&policy, true, || Err("disk unplugged"));
        assert_eq!(result, Err("disk unplugged"), "a failing catch-up cut is a typed error, not a silent skip");
    }
}

#[cfg(test)]
mod metrics_totality_tests {
    //! O-01: metrics are total and typed — a failed storage sample never panics
    //! and never fabricates a fresh count.

    use std::sync::Mutex;

    use super::resolve_storage_metrics;

    #[test]
    fn a_cold_failure_is_the_zero_default_not_a_panic() {
        // "metrics before registration / during outage" — no successful sample
        // has ever run. The result is the honest zero default, and crucially NO
        // panic (the old `.expect` aborted the scrape here).
        let last_good = Mutex::new(None);
        let (bytes, keys) = resolve_storage_metrics(None, None, &last_good);
        assert_eq!((bytes, keys), (0, 0), "a cold failure serves the zero default");
    }

    #[test]
    fn a_successful_sample_updates_last_good() {
        let last_good = Mutex::new(None);
        let resolved = resolve_storage_metrics(Some(4096), Some(12), &last_good);
        assert_eq!(resolved, (4096, 12));
        assert_eq!(*last_good.lock().unwrap(), Some((4096, 12)), "a successful sample is memoised as last-good");
    }

    #[test]
    fn a_failure_after_a_success_serves_the_stale_last_good() {
        // "during an object-store outage: typed stale, no fabricated count".
        let last_good = Mutex::new(None);
        resolve_storage_metrics(Some(4096), Some(12), &last_good);
        let during_outage = resolve_storage_metrics(None, None, &last_good);
        assert_eq!(during_outage, (4096, 12), "an outage serves the last consistent pair, not a fabricated count");
    }

    #[test]
    fn a_partial_failure_does_not_fabricate() {
        // one sample succeeds, the other fails: serve the last consistent pair
        // (or zero), never a mix that pairs a fresh value with a fabricated one.
        let last_good = Mutex::new(None);
        let (bytes, keys) = resolve_storage_metrics(Some(9999), None, &last_good);
        assert_eq!((bytes, keys), (0, 0), "a partial failure with no history serves the zero default, not (9999, ?)");
    }
}

#[cfg(test)]
mod backend_seam_ordering_tests {
    //! S-01: the backend identity is resolved BEFORE any filesystem touch on
    //! the create path, and persisted atomically. The ordering is the
    //! invariant a cross-engine open depends on — its mutant (create the
    //! directory before the refusal) fails `no_directory_is_created_before_a_backend_refusal`.
    //! R4-STOR-02: a marker-write failure removes the just-created directory
    //! if and only if this attempt owns it and it is empty — no stray
    //! directory a later open could misclassify, and never someone else's
    //! directory or contents.

    use storage::factory::{
        BackendIdentity, BackendMarker, BackendSpec, PersistedBackendMarker, StorageFactoryError, read_backend_marker,
    };
    use test_utils::create_tmp_dir;

    use super::{create_backend_bound_directory, create_backend_bound_directory_with};

    #[test]
    fn no_directory_is_created_before_a_backend_refusal() {
        // the mutant catcher: a refusing resolution (as a not-yet-available
        // lane would produce) must leave the database path non-existent — no
        // directory, marker, WAL, or object namespace created before the
        // refusal.
        let base = create_tmp_dir("dbo-s01-refusal");
        let path = base.join("must-not-exist");
        let refused = create_backend_bound_directory(
            &path,
            "must-not-exist",
            Err(StorageFactoryError::BackendNotYetAvailable { profile: "U4" }),
        );
        assert!(refused.is_err(), "a not-yet-available backend must refuse");
        assert!(
            !path.exists(),
            "S-01: no database directory may be created before the backend refusal (mutant: resolve moved after mkdir)",
        );
    }

    #[test]
    fn a_resolved_backend_creates_the_directory_and_persists_the_marker_atomically() {
        // positive: a resolved backend creates the directory and binds it with
        // a durable, readable full-identity marker.
        let base = create_tmp_dir("dbo-s01-create");
        let path = base.join("orders-db");
        let identity = BackendIdentity::from_spec(&BackendSpec::Classic);
        create_backend_bound_directory(&path, "orders-db", Ok(identity.clone()))
            .expect("a resolved backend must create the directory");
        assert!(path.exists(), "the database directory must be created");
        let persisted = read_backend_marker(&path).unwrap().expect("the marker must be persisted and readable");
        assert_eq!(persisted, PersistedBackendMarker::V2(identity), "the marker persists the FULL v2 identity");
    }

    #[test]
    fn a_marker_write_failure_leaves_no_stray_directory() {
        // R4-STOR-02: this attempt created the directory, the marker write
        // failed, nothing else was written -> the directory is removed, so
        // the next Database::open cannot classify a half-created tree.
        let base = create_tmp_dir("dbo-r4stor02-cleanup");
        let path = base.join("orders-db");
        let identity = BackendIdentity::from_spec(&BackendSpec::Classic);
        let failed = create_backend_bound_directory_with(&path, "orders-db", Ok(identity), |_, _| {
            Err(std::io::Error::other("injected marker-write failure"))
        });
        assert!(failed.is_err(), "the marker failure must surface as the typed open error");
        assert!(
            !path.exists(),
            "R4-STOR-02: a pre-WAL marker failure must remove the directory this attempt created",
        );
    }

    #[test]
    fn a_marker_failure_never_removes_a_directory_this_attempt_did_not_create() {
        // ownership guard: the path already exists (with content), so
        // fs::create_dir fails, ownership is NOT established, and neither the
        // directory nor its contents are touched.
        let base = create_tmp_dir("dbo-r4stor02-foreign");
        let path = base.join("existing");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("precious"), b"do-not-delete").unwrap();
        let identity = BackendIdentity::from_spec(&BackendSpec::Classic);
        let failed = create_backend_bound_directory_with(&path, "existing", Ok(identity), |_, _| {
            unreachable!("the marker writer must not run when the directory could not be created")
        });
        assert!(failed.is_err(), "an already-existing path must refuse the create");
        assert!(path.exists(), "the pre-existing directory must survive");
        assert_eq!(
            std::fs::read(path.join("precious")).unwrap(),
            b"do-not-delete",
            "the pre-existing directory's contents must be untouched",
        );
    }

    #[test]
    fn a_marker_failure_never_removes_a_directory_that_gained_content() {
        // emptiness guard: this attempt owns the directory, but by the time
        // the marker write fails another actor has placed a file inside —
        // `remove_dir` (the atomic emptiness check) must leave it standing.
        let base = create_tmp_dir("dbo-r4stor02-nonempty");
        let path = base.join("orders-db");
        let path_for_writer = path.to_owned();
        let identity = BackendIdentity::from_spec(&BackendSpec::Classic);
        let failed = create_backend_bound_directory_with(&path, "orders-db", Ok(identity), move |_, _| {
            std::fs::write(path_for_writer.join("racer"), b"raced-in").unwrap();
            Err(std::io::Error::other("injected marker-write failure"))
        });
        assert!(failed.is_err());
        assert!(path.exists(), "a directory that gained content must never be removed by cleanup");
        assert_eq!(std::fs::read(path.join("racer")).unwrap(), b"raced-in");
    }

    #[test]
    fn the_marker_discriminant_still_maps_kinds_exactly() {
        // the kind mapping the ordering invariant depends on
        assert_eq!(BackendIdentity::from_spec(&BackendSpec::Classic).kind, BackendMarker::Classic);
    }
}

typedb_error! {
    pub DatabaseOpenError(component = "Database open", prefix = "DBO") {
        InvalidUnicodeName(1, "Could not open database: invalid unicode name '{name:?}'.", name: OsString),
        DirectoryRead(2, "Error while reading directory for '{name}'.", name: String, source: Arc<io::Error>),
        DirectoryCreate(3, "Error creating directory for '{name}'", name: String, source: Arc<io::Error>),
        StorageOpen(4, "Error opening storage layer.", typedb_source: StorageOpenError),
        WALOpen(5, "Error opening WAL.", source: DurabilityServiceError),
        DurabilityClientOpen(6, "Error opening durability client.", typedb_source: DurabilityClientError),
        DurabilityClientRead(7, "Error reading from durability client.", typedb_source: DurabilityClientError),
        CheckpointLoad(8, "Error loading checkpoint for database '{name}'.", name: String, typedb_source: CheckpointLoadError),
        CheckpointCreate(9, "Error creating checkpoint for database '{name}'.", name: String, source: CheckpointCreateError),
        Encoding(10, "Data encoding error.", source: EncodingError),
        StatisticsInitialise(11, "Error initialising statistics manager.", typedb_source: StatisticsError),
        TypeCacheInitialise(12, "Error initialising type cache.", typedb_source: TypeCacheCreateError),
        FunctionCacheInitialise(13, "Error initialising function cache.", typedb_source: FunctionError),
        FileDelete(14, "Error while deleting file for '{name}'", name: String, source: Arc<io::Error>),
        DirectoryDelete(15, "Error while deleting directory of '{name}'", name: String, source: Arc<io::Error>),
        NotADatabase(16, "Directory '{name}' already exists and does not contain a database.", name: String),
        PrepareForWrites(17, "Failed to prepare database '{name}' for writes. In-memory allocators may collide with storage on the next allocation.", name: String, source: EncodingError),
        StorageFactory(18, "Error resolving storage backend profile.", source: StorageFactoryError),
        ForbiddenBackgroundWorker(19, "Database '{name}' scheduled a background worker its backend policy forbids: {source:?}. The controller-frozen (remote) lane takes global cuts only and must not run TypeDB's interval checkpointer.", name: String, source: ForbiddenWorkerError),
    }
}

typedb_error! {
    pub DatabaseCreateError(component = "Database create", prefix = "DBC") {
        InvalidName(1, "Cannot create database since '{name}' is not a valid database name.", name: String),
        InternalDatabaseCreationProhibited(2, "Creating an internal database is prohibited."),
        DatabaseOpen(3, "Database open error.", typedb_source: DatabaseOpenError),
        WriteAccessDenied(4, "Cannot access databases for writing."),
        ReadAccessDenied(5, "Cannot access databases for reading."),
        AlreadyExists(6, "Database '{name}' already exists.", name: String),
        AlreadyExistsAndCleanupBlocked(7, "Database '{name}' already exists. Error while removing the imported duplicate.", name: String, typedb_source: DatabaseDeleteError),
        IsBeingImported(8, "Cannot create database '{name}' since it is being imported.", name: String),
        IsNotBeingImported(9, "Internal error: database '{name}' is not being imported.", name: String),
        DirectoryWrite(10, "Error while writing to data directory for '{name}'.", name: String, source: Arc<io::Error>),
        DatabaseMove(11, "Error while moving database {name} while finalization.", name: String),
    }
}

typedb_error! {
    pub DatabaseDeleteError(component = "Database delete", prefix = "DBD") {
        DoesNotExist(1, "Cannot delete database since it does not exist."),
        InUse(2, "Cannot delete database since it is in use."),
        StorageDelete(3, "Error while deleting storage resources.", typedb_source: StorageDeleteError),
        DirectoryDelete(4, "Error deleting directory.", source: Arc<io::Error>),
        InternalDatabaseDeletionProhibited(5, "Deleting an internal database is prohibited"),
        WriteAccessDenied(6, "Cannot access databases for writing."),
        DatabaseIsNotBeingImported(7, "Internal error: database '{name}' is not being imported.", name: String),
    }
}

typedb_error! {
    pub DatabaseResetError(component = "Database reset", prefix = "DBR") {
        DatabaseDelete(1, "Cannot delete database.", typedb_source: DatabaseDeleteError),
        DatabaseCreate(2, "Cannot create database.", typedb_source: DatabaseCreateError),
        Transaction(3, "Transaction error.", typedb_source: TransactionError),
        InUse(4, "Database cannot be reset since it is in use."),
        StorageInUse(5, "Database cannot be reset since the storage is in use."),
        CorruptionPartialResetStorageInUse(
            6,
            "Corruption warning: database reset failed partway because the storage is still in use.",
            typedb_source: StorageResetError
        ),
        CorruptionPartialResetKeyGeneratorInUse(
            7,
            "Corruption warning: Database reset failed partway because the schema key generator is still in use."
        ),
        CorruptionPartialResetTypeVertexGeneratorInUse(
            8,
            "Corruption warning: Database reset failed partway because the type key generator is still in use."
        ),
        CorruptionPartialResetThingVertexGeneratorInUse(
            9,
            "Corruption warning: Database reset failed partway because the instance key generator is still in use."
        ),
        CorruptionPartialResetQuertyCacheInUse(
            10,
            "Corruption warning: Database reset failed partway because the query cache is still in use."
        ),
    }
}
