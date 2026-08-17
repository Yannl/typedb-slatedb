/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Exact store identities, replacing convention-shaped prefixes.
//!
//! # The defect this closes
//!
//! The first cut of this crate addressed a store by a caller-supplied string prefix —
//! typically the final path component of a database directory. That is a *convention*, and
//! every collision it permits is silent: two databases that happen to share a name, two
//! generations of the same database after a destroy/recreate, two scratch materialization
//! attempts racing, or a stale actor from a previous deployment writing into a prefix the
//! current deployment now owns. In every case the failure is not an error but interleaved
//! bytes — two SlateDB manifests fencing each other inside one prefix, each believing the
//! other is a crashed instance of itself.
//!
//! [`StoreIdentity`] makes the prefix a function of every coordinate that must differ between
//! two stores that are allowed to coexist:
//!
//! | coordinate | separates |
//! |---|---|
//! | `environment` | prod from staging from test, sharing a bucket |
//! | `database_id` | two databases, regardless of display name |
//! | `generation` | two lives of one database across destroy/recreate |
//! | `materialization` | two scratch/rebuild attempts of one generation |
//! | `keyspace_schema_version` | two incompatible physical layouts |
//! | `format_digest` | two incompatible storage formats/configurations |
//!
//! # Why no-prefix-of-another matters, not just inequality
//!
//! Object stores namespace by *string prefix*, so `db-1` and `db-10` being unequal is not
//! enough — a `LIST` under `db-1` must not see `db-10`'s objects. Every segment here is
//! either fixed-width (UUIDs, zero-padded integers, fixed-length digest) or terminated by
//! `/`, so no identity's prefix is a string prefix of a different identity's. The unit tests
//! prove both properties over the collision cases named above.

use uuid::Uuid;

use crate::error::KeyspaceError;

/// Fixed length demanded of [`StoreIdentity::format_digest`], hex characters.
///
/// 16 hex characters = 64 bits of a content digest: enough that two distinct configurations
/// colliding is not a practical concern, short enough to keep object keys readable. Fixed
/// rather than variable length so the digest segment cannot make one identity's prefix a
/// string prefix of another's.
pub const FORMAT_DIGEST_LEN: usize = 16;

/// The immutable identity of one materialized store.
///
/// Construct with [`StoreIdentity::new`], which validates every component; the fields are
/// private so a validated identity cannot be mutated into an unvalidated one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreIdentity {
    environment: String,
    database_id: Uuid,
    generation: u64,
    materialization: Uuid,
    keyspace_schema_version: u32,
    format_digest: String,
}

impl StoreIdentity {
    /// Validate and build an identity.
    ///
    /// `environment` must be non-empty, at most 32 characters, drawn from `[a-z0-9-]`, and
    /// must not begin or end with `-`. `format_digest` must be exactly
    /// [`FORMAT_DIGEST_LEN`] lowercase hex characters — the leading 64 bits of a content
    /// digest over the source/config/format tuple the store was written under.
    pub fn new(
        environment: &str,
        database_id: Uuid,
        generation: u64,
        materialization: Uuid,
        keyspace_schema_version: u32,
        format_digest: &str,
    ) -> Result<Self, KeyspaceError> {
        if environment.is_empty() || environment.len() > 32 {
            return Err(KeyspaceError::config(format!(
                "environment must be 1..=32 characters, got {}",
                environment.len()
            )));
        }
        if !environment.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || environment.starts_with('-')
            || environment.ends_with('-')
        {
            return Err(KeyspaceError::config(format!(
                "environment {environment:?} must match [a-z0-9]([a-z0-9-]*[a-z0-9])?; it \
                 becomes an object-store path segment and anything looser invites collisions \
                 and escaping bugs"
            )));
        }
        if format_digest.len() != FORMAT_DIGEST_LEN
            || !format_digest.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        {
            return Err(KeyspaceError::config(format!(
                "format_digest must be exactly {FORMAT_DIGEST_LEN} lowercase hex characters, \
                 got {format_digest:?}; a variable-length segment would let one identity's \
                 prefix be a string prefix of another's"
            )));
        }
        Ok(Self {
            environment: environment.to_string(),
            database_id,
            generation,
            materialization,
            keyspace_schema_version,
            format_digest: format_digest.to_string(),
        })
    }

    pub fn environment(&self) -> &str {
        &self.environment
    }

    pub fn database_id(&self) -> Uuid {
        self.database_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn materialization(&self) -> Uuid {
        self.materialization
    }

    pub fn keyspace_schema_version(&self) -> u32 {
        self.keyspace_schema_version
    }

    pub fn format_digest(&self) -> &str {
        &self.format_digest
    }

    /// The identity of the *next* generation of the same database.
    ///
    /// A destroy/recreate must move to a fresh generation rather than reusing the prefix;
    /// this is the only sanctioned way to derive it. A fresh materialization id is taken
    /// because a new generation is by definition a new materialization attempt.
    pub fn next_generation(&self) -> Self {
        Self {
            generation: self.generation + 1,
            materialization: Uuid::new_v4(),
            ..self.clone()
        }
    }

    /// The identity of a fresh materialization attempt of the same generation.
    ///
    /// Used for scratch rebuilds: two attempts at materializing the same logical state must
    /// not share bytes, or the loser's partial output becomes the winner's corruption.
    pub fn new_attempt(&self) -> Self {
        Self { materialization: Uuid::new_v4(), ..self.clone() }
    }

    /// The canonical object-store prefix. Deterministic, collision-free, and not a string
    /// prefix of any other identity's prefix — see the module docs for why both hold.
    pub fn prefix(&self) -> String {
        format!(
            "env-{}/db-{}/gen-{:020}/mat-{}/ks-{:010}/fmt-{}",
            self.environment,
            self.database_id,
            self.generation,
            self.materialization,
            self.keyspace_schema_version,
            self.format_digest,
        )
    }
}

impl std::fmt::Display for StoreIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.prefix())
    }
}
