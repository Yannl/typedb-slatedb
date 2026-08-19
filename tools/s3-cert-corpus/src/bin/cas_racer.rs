//! Multi-PROCESS conditional-create racer (R5-LOCAL-01).
//!
//! The in-test races share one OS process; the audit demands independent
//! processes because a broken provider can appear correct under a single
//! client library instance. `run-corpus.sh` launches N of these, each
//! with its own process/connection pool, synchronized by a start-file
//! barrier created AFTER all racers are polling — every precondition
//! check overlaps every other body.
//!
//! Usage: cas_racer <key> <writer-id> <start-file>
//!   (S3_CERT_* env as for the corpus)
//!
//! Exit codes:
//!   0  won the create AND verified the stored bytes are its own
//!   3  typed loser (AlreadyExists precondition)
//!   4  won the create but the stored bytes are NOT its own (changed-byte
//!      overwrite — the decisive provider defect)
//!   1  any other error

use bytes::Bytes;
use object_store::{Error as StoreError, ObjectStoreExt, PutMode, PutOptions, PutPayload};
use object_store::path::Path as ObjectPath;
use s3_cert_corpus::target_from_env;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: cas_racer <key> <writer-id> <start-file>");
        std::process::exit(2);
    }
    let key = ObjectPath::from(args[1].as_str());
    let writer_id: u32 = args[2].parse().expect("writer-id u32");
    let start_file = &args[3];

    let target = target_from_env().expect("S3_CERT_* env must be set");
    let mut body = vec![0u8; 1_048_576];
    for (j, b) in body.iter_mut().enumerate() {
        *b = ((writer_id as usize).wrapping_mul(151) ^ j.wrapping_mul(29)) as u8;
    }
    let body = Bytes::from(body);

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let code = rt.block_on(async move {
        // start-file barrier: poll tightly until the runner releases us
        while !std::path::Path::new(start_file).exists() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let opts = PutOptions { mode: PutMode::Create, ..Default::default() };
        match target.store.put_opts(&key, PutPayload::from(body.clone()), opts).await {
            Ok(_) => {
                // changed-byte verification: the winner's stored bytes must
                // be exactly its own body
                match target.store.get(&key).await {
                    Ok(got) => match got.bytes().await {
                        Ok(stored) if stored == body => 0,
                        Ok(_) => 4,
                        Err(e) => { eprintln!("winner readback failed: {e}"); 1 }
                    },
                    Err(e) => { eprintln!("winner GET failed: {e}"); 1 }
                }
            }
            Err(StoreError::AlreadyExists { .. }) => 3,
            Err(other) => { eprintln!("untyped loser: {other}"); 1 }
        }
    });
    std::process::exit(code);
}
