/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! One bounded runtime for every store in the process, instead of one per database.
//!
//! # The defect this closes
//!
//! [`crate::KeyspaceSet`] originally built a multi-threaded Tokio runtime per open store.
//! Each such runtime is a fixed pool of worker threads plus a reactor; a server hosting N
//! databases therefore ran N reactors and N×cores worker threads, none of which knew about
//! the others. Thread count — and with it stack memory and scheduler pressure — scaled with
//! open databases rather than with the machine, and no admission decision could be made
//! globally because no component owned the whole picture.
//!
//! [`StorageRuntime`] is that owner: a process-wide, explicitly bounded runtime that every
//! store shares. Opening a hundred databases adds no threads. The scan-admission semaphore
//! lives here too, so "how many full-store scans may run at once" is a process-level answer
//! rather than a per-database accident.
//!
//! A store can still be given a private runtime through
//! [`crate::KeyspaceSet::open_with_runtime`] — tests isolate with it — but the default path
//! shares [`StorageRuntime::shared`].

use std::sync::{Arc, OnceLock};

use crate::error::KeyspaceError;

/// Ceiling on worker threads for the process-wide default runtime.
///
/// Storage bridging is I/O-shaped: workers spend their time parked on object-store round
/// trips, not computing. A handful of threads keeps many requests in flight; matching the
/// core count of a large machine would add stacks, not throughput.
pub const DEFAULT_MAX_WORKER_THREADS: usize = 4;

/// Concurrent full-store statistics scans admitted process-wide.
///
/// A statistics scan reads the entire store, which against an object store is a sustained
/// network transfer. One in flight is useful; many in flight compete with the reads real
/// queries need. Two allows one slow scan to overlap one fresh request without letting a
/// diagnostics loop fan out into a fleet of them.
pub const SCAN_ADMISSION_LIMIT: usize = 2;

/// The process-wide bounded runtime and resource owner every store bridges onto.
pub struct StorageRuntime {
    runtime: tokio::runtime::Runtime,
    /// Admission for full-store scans; see [`SCAN_ADMISSION_LIMIT`].
    scan_permits: tokio::sync::Semaphore,
}

impl StorageRuntime {
    /// Build a runtime with an explicit worker-thread bound.
    pub fn with_worker_threads(workers: usize) -> Result<Arc<Self>, KeyspaceError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers.max(1))
            .thread_name("slatedb-keyspace")
            .enable_all()
            .build()
            .map_err(|error| KeyspaceError::open(format!("could not build storage runtime: {error}")))?;
        Ok(Arc::new(Self { runtime, scan_permits: tokio::sync::Semaphore::new(SCAN_ADMISSION_LIMIT) }))
    }

    /// The process-wide shared runtime, built on first use.
    ///
    /// Bounded at `min(cores, `[`DEFAULT_MAX_WORKER_THREADS`]`)` workers. Panics only if the
    /// first construction fails, which means the process cannot spawn threads at all.
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<StorageRuntime>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
                Self::with_worker_threads(cores.min(DEFAULT_MAX_WORKER_THREADS))
                    .expect("the process cannot spawn threads for the shared storage runtime")
            })
            .clone()
    }

    pub(crate) fn tokio(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }

    /// Try to admit one full-store scan. `None` means the process-wide limit is reached and
    /// the caller should fall back to its stale-cache policy rather than queue.
    pub(crate) fn try_admit_scan(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.scan_permits.try_acquire().ok()
    }
}

impl std::fmt::Debug for StorageRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageRuntime")
            .field("scan_permits_available", &self.scan_permits.available_permits())
            .finish()
    }
}
