/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! What this engine is — and is not — qualified for, stated as data.
//!
//! A green test suite is a claim about the paths the suite exercises, and it is silent about
//! the paths that do not exist. The two gaps below are real, they are invisible to every
//! passing test, and hiding them behind an engine-level green is precisely the failure mode
//! the V16 brief's review process exists to catch. So the engine states them itself, in a
//! form a control plane can read and refuse on.
//!
//! # Checkpoint/restore is not production-qualified
//!
//! [`crate::KeyspaceSet::checkpoint`] produces a *SlateDB-native* checkpoint whose pin
//! expires after [`crate::CHECKPOINT_LIFETIME`] (one hour). That is the right shape for what
//! it protects — an engine-internal copy window — and the wrong shape for a release
//! checkpoint, which must not depend on any expiry, must be rooted in a controller-owned
//! record rather than in the mutable store it describes, and must be verifiable globally
//! (brief: the controller-rooted, non-expiring, globally verified checkpoint contribution
//! protocol). None of that exists here. A restore path from object storage is likewise
//! rejected rather than implemented; see `local_directory` on [`crate::KeyspaceSet`].
//!
//! # Compaction is an external obligation this engine does not discharge
//!
//! The in-process compactor is disabled by contract (an unfenced reachability mutation), and
//! no external compactor exists yet. Until one does, L0 growth is bounded by refusal —
//! [`crate::config::SAFE_L0_CEILING`] — which means the engine has a bounded write budget
//! per store lifetime, not indefinite operation.

/// Whether one capability of the engine may be relied on in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureStatus {
    /// Implemented, tested, and safe to rely on within its documented contract.
    Qualified,
    /// Deliberately not implemented to the production contract. The engine must be excluded
    /// from production qualification wherever this capability is required.
    Unimplemented {
        /// Why, stated so a reader does not have to trust — or re-derive — the reasoning.
        reason: &'static str,
    },
}

impl FeatureStatus {
    pub fn is_qualified(&self) -> bool {
        matches!(self, FeatureStatus::Qualified)
    }
}

/// The engine's production-qualification statement, one entry per capability with a
/// qualification gap or a non-obvious boundary.
#[derive(Debug, Clone, Copy)]
pub struct ProductionQualification {
    /// Point-in-time capture and restore to the release-checkpoint contract.
    pub checkpoint_restore: FeatureStatus,
    /// Indefinite operation under write load (requires compaction).
    pub sustained_writes: FeatureStatus,
    /// Everyday keyspace reads/writes within the attested posture.
    pub keyspace_operations: FeatureStatus,
}

/// The current, honest statement. Update this *with* the implementation, never ahead of it.
pub fn production_qualification() -> ProductionQualification {
    ProductionQualification {
        checkpoint_restore: FeatureStatus::Unimplemented {
            reason: "native checkpoint pins expire after one hour and are rooted in the \
                     store's own mutable manifest; the release-checkpoint contract requires a \
                     controller-rooted, non-expiring, globally verified checkpoint \
                     contribution, and restore from object storage is refused rather than \
                     implemented",
        },
        sustained_writes: FeatureStatus::Unimplemented {
            reason: "compaction is contractually external (unfenced reachability mutation) \
                     and no external compactor exists; L0 is capped at SAFE_L0_CEILING, so \
                     each store has a bounded write budget, not indefinite operation",
        },
        keyspace_operations: FeatureStatus::Qualified,
    }
}

impl ProductionQualification {
    /// Whether the engine may be qualified for production *as a whole*.
    ///
    /// False until every capability is [`FeatureStatus::Qualified`]. There is deliberately no
    /// override: a deployment that does not need checkpoints should consume
    /// [`Self::keyspace_operations`] directly and record that decision itself.
    pub fn is_production_qualified(&self) -> bool {
        self.checkpoint_restore.is_qualified()
            && self.sustained_writes.is_qualified()
            && self.keyspace_operations.is_qualified()
    }

    /// Every unimplemented capability with its reason, for logs and startup attestations.
    pub fn gaps(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        for (name, status) in [
            ("checkpoint_restore", self.checkpoint_restore),
            ("sustained_writes", self.sustained_writes),
            ("keyspace_operations", self.keyspace_operations),
        ] {
            if let FeatureStatus::Unimplemented { reason } = status {
                out.push((name, reason));
            }
        }
        out
    }
}
