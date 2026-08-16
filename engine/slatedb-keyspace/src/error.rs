/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Errors are kept coarse on purpose: they mirror the operation that failed, matching
//! upstream's `KeyspaceError` variants (`Put`, `Get`, `BatchWrite`, `Iterate`) so the
//! substitution does not change what callers can distinguish.

#[derive(Debug, Clone, thiserror::Error)]
pub enum KeyspaceError {
    #[error("opening the keyspace set failed: {0}")]
    Open(String),
    #[error("put failed: {0}")]
    Put(String),
    #[error("get failed: {0}")]
    Get(String),
    #[error("batch write failed: {0}")]
    Write(String),
    #[error("iteration failed: {0}")]
    Iterate(String),
}
