# BT-P3 direct-constructor inventory

Every WAL/MVCCStorage construction site in the fork, with routing classification.

| file | line | site | classification |
|---|---|---|---|
| database/database.rs | 301 | `MVCCStorage::create::<EncodingKeyspace>(name, path, wal_client, rocks_resources)` | ROUTED (production path; WAL construction now via StorageFactory; MVCCStorage::create/load are the storage-layer entry the factory will re-point at TB-P7) |
| database/database.rs | 394 | `MVCCStorage::load::<EncodingKeyspace>(&name, path, wal_client, &checkpoint, rocks_resource` | ROUTED (production path; WAL construction now via StorageFactory; MVCCStorage::create/load are the storage-layer entry the factory will re-point at TB-P7) |
| database/tools/read_wal.rs | 111 | `let wal = WAL::load(path, FsyncMetrics::disabled()).unwrap();` | MAINTENANCE-TOOL (offline WAL inspection) |
| database/tools/read_wal.rs | 131 | `let wal = WAL::load(path, FsyncMetrics::disabled()).unwrap();` | MAINTENANCE-TOOL (offline WAL inspection) |
| database/tools/replay_wal.rs | 53 | `let source_wal = WAL::load(cli.source_directory, FsyncMetrics::disabled()).unwrap();` | MAINTENANCE-TOOL (offline WAL replay) |
| database/tools/replay_wal.rs | 67 | `let mut target_wal = WALClient::new(WAL::load(cli.target_directory, FsyncMetrics::disabled` | MAINTENANCE-TOOL (offline WAL replay) |
| durability/benches/throughput.rs | 34 | `let mut wal = WAL::create(directory, FsyncMetrics::disabled()).unwrap();` | BENCH |
| durability/wal.rs | 821 | `let mut wal = WAL::create(directory, FsyncMetrics::disabled()).unwrap();` | SELF (WAL implementation + its unit tests) |
| durability/wal.rs | 828 | `let mut wal = WAL::load(directory, FsyncMetrics::disabled()).unwrap();` | SELF (WAL implementation + its unit tests) |
| durability/tests/common/test_common.rs | 31 | `let mut wal = WAL::create(directory, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (durability crate test helper; edits prohibited outside port ledger) |
| durability/tests/common/test_common.rs | 37 | `let mut wal = WAL::load(directory, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (durability crate test helper; edits prohibited outside port ledger) |
| storage/benches/bench_mvcc_storage.rs | 124 | `MVCCStorage::create::<TestKeyspaceSet>(` | BENCH |
| storage/benches/bench_mvcc_storage.rs | 127 | `WALClient::new(WAL::create(storage_path, FsyncMetrics::disabled()).unwrap()),` | BENCH |
| storage/benches/bench_rocks_impl/rocks_database.rs | 120 | `let wal = WAL::create(&path, FsyncMetrics::disabled()).unwrap();` | BENCH |
| storage/storage.rs | 822 | `WALClient::new(WAL::create(storage_path.join(WAL::WAL_DIR_NAME), FsyncMetrics::disabled())` | SELF (storage unit tests construct WAL directly; upstream test code) |
| storage/storage.rs | 849 | `WALClient::new(WAL::load(storage_path.join(WAL::WAL_DIR_NAME), FsyncMetrics::disabled()).u` | SELF (storage unit tests construct WAL directly; upstream test code) |
| storage/storage.rs | 879 | `WALClient::new(WAL::create(storage_path.join(WAL::WAL_DIR_NAME), FsyncMetrics::disabled())` | SELF (storage unit tests construct WAL directly; upstream test code) |
| storage/storage.rs | 998 | `WALClient::new(WAL::create(storage_path.join(WAL::WAL_DIR_NAME), FsyncMetrics::disabled())` | SELF (storage unit tests construct WAL directly; upstream test code) |
| storage/storage.rs | 1013 | `WALClient::new(WAL::load(storage_path.join(WAL::WAL_DIR_NAME), FsyncMetrics::disabled()).u` | SELF (storage unit tests construct WAL directly; upstream test code) |
| storage/factory.rs | 109 | `WAL::create(directory, metrics).map_err(|source| StorageFactoryError::WalOpen { source })` | FACTORY (the BT-P3 central decision point) |
| storage/factory.rs | 114 | `WAL::load(directory, metrics).map_err(|source| StorageFactoryError::WalOpen { source })` | FACTORY (the BT-P3 central decision point) |
| storage/tests/test_utils_storage/lib.rs | 53 | `let storage = MVCCStorage::create::<KS>("storage", path, WALClient::new(wal), &resources)?` | ROUTED (shared test utility; WAL via factory; load_storage receives caller WAL) |
| storage/tests/test_utils_storage/lib.rs | 69 | `let storage = MVCCStorage::load::<KS>("storage", path, WALClient::new(wal), &checkpoint, &` | ROUTED (shared test utility; WAL via factory; load_storage receives caller WAL) |
| storage/tests/test_storage.rs | 129 | `WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| storage/tests/test_isolation.rs | 698 | `WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| storage/tests/test_recovery.rs | 49 | `WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| storage/tests/test_recovery.rs | 99 | `WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap(),` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| storage/tests/test_recovery.rs | 138 | `let wal_result = WAL::load(&storage_path, FsyncMetrics::disabled());` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| storage/tests/test_recovery.rs | 165 | `let wal_result = WAL::load(&storage_path, FsyncMetrics::disabled());` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| storage/tests/test_recovery.rs | 194 | `let wal_result = WAL::load(&storage_path, FsyncMetrics::disabled());` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/benches/benchmark.rs | 45 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | BENCH |
| encoding/tests/test_utils_encoding.rs | 19 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_utils_encoding.rs | 22 | `MVCCStorage::create::<EncodingKeyspace>("db_storage", &storage_path, WALClient::new(wal), ` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_attribute_vertex.rs | 430 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_attribute_vertex.rs | 454 | `let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_attribute_vertex.rs | 475 | `let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_attribute_vertex.rs | 503 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_attribute_vertex.rs | 545 | `let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_attribute_vertex.rs | 595 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_type_vertex.rs | 137 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_type_vertex.rs | 152 | `let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_type_vertex.rs | 173 | `let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_type_vertex.rs | 196 | `let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| encoding/tests/test_type_vertex.rs | 234 | `let wal = WAL::load(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (direct construction inside an upstream test; profile switching for these lands via port ledger at TB-P7/BT-P5) |
| function/function_manager.rs | 625 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (cfg(test) unit test) |
| compiler/annotation/mod.rs | 387 | `let wal = WAL::create(&storage_path, FsyncMetrics::disabled()).unwrap();` | UPSTREAM-TEST-PINNED (cfg(test) unit test) |

Unclassified: 0 (gate satisfied)

Profile matrix: U0/U1 available (RocksDB + file WAL oracle); U2/U3/U4 fail closed with StorageFactoryError::ProfileUnavailable. Selection env: TYPEDB_STORAGE_PROFILE (invalid values are a typed error, never a silent default).
