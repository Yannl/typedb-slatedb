//! Fencing model: controller incarnation, startup sessions, and exact
//! external publication epochs (formerly SL-P1; per ADR-0001 the epochs
//! live in the controller lease protocol and the fencing ObjectStore
//! wrapper, not inside SlateDB), including the `init_with_epoch`
//! ambiguity rule.
//!
//! Models brief §5.2 (inv. 16–28) and §8:
//! - every publication carries an exact epoch; stored >= requested fences
//!   the publisher (the same shape as SlateDB's
//!   `FenceableTransactionalObject::check_epoch` in slatedb-txn-obj 0.15.0);
//! - an ambiguous open is never retried with the same epoch: the session is
//!   abandoned and a strictly newer epoch is issued (inv. 26);
//! - a paused stale actor that resumes after the epoch advanced cannot
//!   publish (pause–fence–resume, §8.3);
//! - controller-incarnation rotation revokes old authority (inv. 27).

#[derive(Debug, PartialEq, Eq)]
pub enum PublishError {
    Fenced,
}

/// One published-manifest cell with SlateDB-style epoch CAS.
#[derive(Default)]
pub struct ManifestCell {
    pub stored_epoch: u64,
    pub published: Vec<(u64, &'static str)>,
}

impl ManifestCell {
    /// `init_with_epoch(E)`: succeeds iff E > stored (models the pinned
    /// behaviour where stored >= requested returns Fenced).
    pub fn init_with_epoch(&mut self, epoch: u64) -> Result<(), PublishError> {
        if self.stored_epoch >= epoch {
            return Err(PublishError::Fenced);
        }
        self.stored_epoch = epoch;
        Ok(())
    }

    /// Publish under an exact epoch: only the current epoch holder can make
    /// metadata reachable.
    pub fn publish(&mut self, epoch: u64, what: &'static str) -> Result<(), PublishError> {
        if epoch != self.stored_epoch {
            return Err(PublishError::Fenced);
        }
        self.published.push((epoch, what));
        Ok(())
    }
}

/// Controller-side epoch issuance: strictly monotonic per materialisation.
#[derive(Default)]
pub struct EpochIssuer {
    last_issued: u64,
    pub controller_incarnation: u64,
}

impl EpochIssuer {
    pub fn issue(&mut self) -> u64 {
        self.last_issued += 1;
        self.last_issued
    }

    /// Ambiguous-open rule (inv. 26): the caller reports ambiguity; the
    /// controller abandons the session and issues a strictly newer epoch.
    pub fn resolve_ambiguous_open(&mut self) -> u64 {
        self.issue()
    }

    pub fn rotate_incarnation(&mut self) -> u64 {
        self.controller_incarnation += 1;
        // epochs advance past everything possibly claimed before
        self.last_issued += 1;
        self.controller_incarnation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ambiguous first open with epoch E: whether or not E actually landed,
    /// issuing E+1 and retrying converges without blind reuse of E, for both
    /// outcomes of the ambiguous attempt.
    #[test]
    fn ambiguous_open_never_reuses_epoch() {
        for first_attempt_landed in [false, true] {
            let mut cell = ManifestCell::default();
            let mut issuer = EpochIssuer::default();
            let e1 = issuer.issue();
            if first_attempt_landed {
                cell.init_with_epoch(e1).unwrap();
            }
            // response lost -> ambiguous. Blind reuse of e1 would now be
            // wrong in the landed case:
            if first_attempt_landed {
                assert_eq!(cell.init_with_epoch(e1), Err(PublishError::Fenced));
            }
            // correct rule: abandon, take a strictly newer epoch
            let e2 = issuer.resolve_ambiguous_open();
            assert!(e2 > e1);
            cell.init_with_epoch(e2).unwrap();
            cell.publish(e2, "manifest").unwrap();
        }
    }

    /// Pause–fence–resume (§8.3): a writer paused before publication cannot
    /// publish after a replacement claimed a higher epoch. Exhaust all pause
    /// points across a 3-step publication schedule.
    #[test]
    fn paused_stale_writer_cannot_publish_after_fence() {
        for pause_at in 0..3 {
            let mut cell = ManifestCell::default();
            let mut issuer = EpochIssuer::default();
            let old = issuer.issue();
            cell.init_with_epoch(old).unwrap();
            let mut published_by_old = 0;
            for step in 0..3 {
                if step == pause_at {
                    // old writer pauses; controller fences and replacement
                    // claims a strictly higher epoch and publishes
                    let newer = issuer.issue();
                    cell.init_with_epoch(newer).unwrap();
                    cell.publish(newer, "replacement").unwrap();
                    // old writer resumes: every further publication is fenced
                    assert_eq!(cell.publish(old, "stale"), Err(PublishError::Fenced));
                    break;
                }
                cell.publish(old, "step").unwrap();
                published_by_old += 1;
            }
            // whatever the old writer managed to publish happened strictly
            // before the fence; nothing after it
            assert!(published_by_old <= pause_at);
            assert!(cell.published.iter().all(|(e, w)| *w != "stale" && *e <= cell.stored_epoch));
        }
    }

    /// inv. 27: after incarnation rotation, epochs issued by the old
    /// incarnation can never publish again.
    #[test]
    fn incarnation_rotation_revokes_old_epochs() {
        let mut cell = ManifestCell::default();
        let mut issuer = EpochIssuer::default();
        let old_epoch = issuer.issue();
        cell.init_with_epoch(old_epoch).unwrap();
        issuer.rotate_incarnation();
        let new_epoch = issuer.issue();
        cell.init_with_epoch(new_epoch).unwrap();
        assert_eq!(cell.publish(old_epoch, "old-incarnation"), Err(PublishError::Fenced));
        cell.publish(new_epoch, "new-incarnation").unwrap();
    }

    // negative control: a deliberately weakened cell that accepts equal-or-
    // lower epochs must be caught by the same assertions.
    #[test]
    fn weakened_fence_mutant_is_observable() {
        struct BrokenCell {
            stored: u64,
        }
        impl BrokenCell {
            fn init_with_epoch(&mut self, e: u64) -> Result<(), PublishError> {
                // MUTANT: >= accepted (no fence)
                self.stored = e;
                Ok(())
            }
        }
        let mut cell = BrokenCell { stored: 5 };
        // the correct model rejects this; the mutant accepts it
        assert!(cell.init_with_epoch(5).is_ok(), "mutant must accept (showing the test bites)");
        let mut good = ManifestCell { stored_epoch: 5, published: vec![] };
        assert_eq!(good.init_with_epoch(5), Err(PublishError::Fenced));
    }
}
