use slatedb::config::{PutOptions, Settings, WriteOptions};
use slatedb::object_store::memory::InMemory;
use slatedb::object_store::ObjectStore;
use slatedb::Db;
use std::sync::Arc;

fn posture() -> Settings {
    let mut s = Settings::default();
    s.wal_enabled = false;
    s.flush_interval = None;
    s.compactor_options = None;
    s.garbage_collector_options = None;
    s.compression_codec = None;
    s.l0_max_ssts = 1_000_000;
    s.l0_max_ssts_per_key = 1_000_000;
    s.object_store_max_retries = Some(4);
    s
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    eprintln!("start");
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    eprintln!("opening raw store...");
    let db = Db::builder("dbg", store)
        .with_settings(posture())
        .build()
        .await
        .unwrap();
    eprintln!("open ok");
    db.put_with_options(
        b"k",
        b"v",
        &PutOptions::default(),
        &WriteOptions {
            await_durable: false,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    eprintln!("put ok");
    db.flush().await.unwrap();
    eprintln!("flush ok");
    db.close().await.unwrap();
    eprintln!("close ok");
}
