//! Control journal + recovery anchor model: contiguous authenticated event
//! chain, snapshot reconstruction, and anti-rollback.
//!
//! Models brief §7.4, §7.7, §7.10 and §6.9:
//! - ControlSeq is contiguous; every event names the previous digest
//!   (inv. 5–6 applied to control history);
//! - recovery rejects a head below the newest trusted anchor, any gap,
//!   or a competing valid body at the same position (inv. 110);
//! - duplicate control positions with competing bodies quarantine
//!   (inv. 13).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlEvent {
    pub seq: u64,
    pub body: u64,        // stands in for canonical CBOR body
    pub prev_digest: u64, // digest chain
}

fn digest(seq: u64, body: u64, prev: u64) -> u64 {
    // toy but deterministic mixing; adequate for model divergence detection
    seq.wrapping_mul(0x9E3779B97F4A7C15) ^ body.rotate_left(17) ^ prev.rotate_left(31)
}

#[derive(Default)]
pub struct Journal {
    pub events: Vec<ControlEvent>,
    pub head_digest: u64,
}

impl Journal {
    pub fn append(&mut self, body: u64) -> &ControlEvent {
        let seq = self.events.len() as u64 + 1;
        let ev = ControlEvent { seq, body, prev_digest: self.head_digest };
        self.head_digest = digest(seq, body, self.head_digest);
        self.events.push(ev);
        self.events.last().unwrap()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryAnchor {
    pub minimum_seq: u64,
    pub minimum_head_digest: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Gap { at: u64 },
    ChainMismatch { at: u64 },
    BelowAnchor { head: u64, anchor: u64 },
    CompetingBodies { at: u64 },
}

/// Validate a candidate history against the digest chain and the newest
/// trusted anchor (brief §7.10 steps 3–5).
pub fn validate_history(events: &[ControlEvent], anchor: Option<RecoveryAnchor>) -> Result<u64, RecoveryError> {
    let mut prev = 0u64;
    let mut last_seq = 0u64;
    for (i, ev) in events.iter().enumerate() {
        let expected_seq = i as u64 + 1;
        if ev.seq != expected_seq {
            return Err(RecoveryError::Gap { at: expected_seq });
        }
        if ev.prev_digest != prev {
            return Err(RecoveryError::ChainMismatch { at: ev.seq });
        }
        prev = digest(ev.seq, ev.body, prev);
        last_seq = ev.seq;
    }
    if let Some(a) = anchor {
        if last_seq < a.minimum_seq {
            return Err(RecoveryError::BelowAnchor { head: last_seq, anchor: a.minimum_seq });
        }
        // digest at the anchor position must match the anchored digest
        if digest_of_prefix(events, a.minimum_seq as usize) != a.minimum_head_digest {
            return Err(RecoveryError::ChainMismatch { at: a.minimum_seq });
        }
    }
    Ok(last_seq)
}

/// Chain digest of the first `n` events — what an anchor at position `n`
/// binds. Shared by validation and by anchor construction in tests.
pub fn digest_of_prefix(events: &[ControlEvent], n: usize) -> u64 {
    let mut d = 0u64;
    for ev in events.iter().take(n) {
        d = digest(ev.seq, ev.body, d);
    }
    d
}

/// Detect competing valid bodies at one position across two candidate
/// histories (inv. 13: quarantine).
pub fn detect_competition(a: &[ControlEvent], b: &[ControlEvent]) -> Result<(), RecoveryError> {
    for (x, y) in a.iter().zip(b.iter()) {
        if x.seq == y.seq && x.body != y.body {
            return Err(RecoveryError::CompetingBodies { at: x.seq });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(n: u64) -> Journal {
        let mut j = Journal::default();
        for i in 0..n {
            j.append(1000 + i);
        }
        j
    }

    #[test]
    fn valid_history_replays() {
        let j = journal(10);
        assert_eq!(validate_history(&j.events, None), Ok(10));
    }

    /// inv. 110: recovery rejects any interior gap — exhaust every
    /// single-event deletion position. Deleting the LAST event is pure
    /// truncation: structurally valid without an anchor (that is exactly the
    /// suffix-deletion window the RecoveryAnchor exists to close, §6.9), so
    /// it is asserted under an anchor instead.
    #[test]
    fn any_gap_is_rejected() {
        for hole in 0..9usize {
            let j = journal(10);
            let mut ev = j.events.clone();
            ev.remove(hole);
            assert!(validate_history(&ev, None).is_err(), "hole at {hole} must fail");
        }
        // tail truncation: caught only by the anchor
        let j = journal(10);
        let anchor = RecoveryAnchor { minimum_seq: 10, minimum_head_digest: j.head_digest };
        let truncated = &j.events[..9];
        assert!(validate_history(truncated, Some(anchor)).is_err());
        assert_eq!(
            validate_history(truncated, None),
            Ok(9),
            "un-anchored truncation is structurally valid - documents why anchors are mandatory"
        );
    }

    /// inv. 110: recovery rejects any single-event body tamper (chain break)
    /// — exhaust every tamper position.
    #[test]
    fn any_tamper_is_rejected() {
        for pos in 0..10usize {
            let j = journal(10);
            let mut ev = j.events.clone();
            ev[pos].body ^= 1;
            let r = validate_history(&ev, None);
            if pos == 9 {
                // tail tamper breaks nothing structurally without an anchor:
                // the chain to 9 is intact and event 10's own digest is only
                // checked by the NEXT link or the anchor. Anchor-at-head
                // catches it:
                let anchor = RecoveryAnchor { minimum_seq: 10, minimum_head_digest: j.head_digest };
                assert!(validate_history(&ev, Some(anchor)).is_err());
            } else {
                assert!(r.is_err(), "tamper at {pos} must fail");
            }
        }
    }

    /// Anti-rollback (inv. 110, §6.9): a valid-looking truncated history
    /// below the newest trusted anchor is rejected — exhaust every
    /// truncation length.
    #[test]
    fn rollback_below_anchor_is_rejected() {
        let j = journal(10);
        let anchor = RecoveryAnchor { minimum_seq: 8, minimum_head_digest: digest_of_prefix(&j.events, 8) };
        for keep in 0..8usize {
            let ev = &j.events[..keep];
            assert_eq!(
                validate_history(ev, Some(anchor)),
                Err(RecoveryError::BelowAnchor { head: keep as u64, anchor: 8 }),
                "truncation to {keep} must be rejected"
            );
        }
        // at or above the anchor: accepted
        for keep in 8..=10usize {
            assert!(validate_history(&j.events[..keep], Some(anchor)).is_ok());
        }
    }

    /// inv. 13: competing valid bodies at one position quarantine.
    #[test]
    fn competing_heads_quarantine() {
        let a = journal(6).events;
        let mut b = a.clone();
        b[3].body ^= 7;
        assert_eq!(detect_competition(&a, &b), Err(RecoveryError::CompetingBodies { at: 4 }));
    }

    // negative control: the validator itself must be falsifiable — feeding
    // it an unrelated but internally consistent chain with a forged anchor
    // digest must fail, proving the anchor check bites.
    #[test]
    fn forged_anchor_digest_is_caught() {
        let j = journal(5);
        let forged = RecoveryAnchor { minimum_seq: 5, minimum_head_digest: 0xDEAD };
        assert_eq!(validate_history(&j.events, Some(forged)), Err(RecoveryError::ChainMismatch { at: 5 }));
    }
}
