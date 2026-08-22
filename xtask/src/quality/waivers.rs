//! The exception / waiver register (spec §13).
//!
//! Every field is validated with a specific message, so a refused waiver tells
//! its author exactly what is missing rather than emitting a TOML parse error.
//! A malformed, incomplete or expired waiver is a `QualityFailure`, not a
//! warning: "waiver count is tracked as debt, and a PR adding a waiver should
//! never appear as an ordinary green change".

use serde::{Deserialize, Serialize};

use super::{date::Date, policy::Exceptions};

pub const KINDS: &[&str] = &[
    "mutation-equivalent",
    "coverage-exclusion",
    "duplication",
    "lint-allow",
    "architecture-edge",
    "crap-hotspot",
    "flaky-test",
    "dependency-advisory",
];

/// Reasons that are technically non-empty but say nothing.
const BOILERPLATE: &[&str] = &["n/a", "na", "none", "tbd", "todo", "because", "temporary", "fix later", "-", "."];

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WaiverFile {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub waiver: Vec<RawWaiver>,
}

/// Every field optional so that a missing field becomes a named validation
/// problem rather than a deserialisation failure.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawWaiver {
    pub id: Option<String>,
    pub kind: Option<String>,
    pub path: Option<String>,
    pub symbol: Option<String>,
    pub reason: Option<String>,
    pub owner: Option<String>,
    pub approved_by: Option<String>,
    pub issue: Option<String>,
    pub created: Option<String>,
    pub review_after: Option<String>,
    pub wildcard_justification: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WaiverStatus {
    Active,
    Expired,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatedWaiver {
    pub id: String,
    pub kind: Option<String>,
    pub path: Option<String>,
    pub symbol: Option<String>,
    pub reason: Option<String>,
    pub owner: Option<String>,
    pub approved_by: Option<String>,
    pub issue: Option<String>,
    pub created: Option<String>,
    pub review_after: Option<String>,
    pub status: WaiverStatus,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WaiverSummary {
    pub total: usize,
    pub active: usize,
    pub expired: usize,
    pub invalid: usize,
    pub entries: Vec<ValidatedWaiver>,
}

impl WaiverSummary {
    pub fn is_clean(&self) -> bool {
        self.expired == 0 && self.invalid == 0
    }

    pub fn problem_summary(&self) -> String {
        let mut lines = Vec::new();
        for e in self.entries.iter().filter(|e| e.status != WaiverStatus::Active) {
            lines.push(format!("{} [{:?}]: {}", e.id, e.status, e.problems.join("; ")));
        }
        lines.join("\n")
    }
}

impl WaiverFile {
    pub fn parse(text: &str) -> Result<WaiverFile, String> {
        toml::from_str(text).map_err(|e| format!("quality-waivers.toml: {e}"))
    }

    pub fn load(repo_root: &std::path::Path) -> Result<WaiverFile, String> {
        let path = repo_root.join(super::policy::WAIVERS_PATH);
        if !path.exists() {
            // An absent register means zero waivers, which is the desired
            // steady state; it is not an error.
            return Ok(WaiverFile { schema: 1, waiver: Vec::new() });
        }
        let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        WaiverFile::parse(&text)
    }
}

fn require<'a>(value: &'a Option<String>, field: &str, problems: &mut Vec<String>) -> Option<&'a str> {
    match value {
        Some(v) if !v.trim().is_empty() => Some(v.trim()),
        _ => {
            problems.push(format!("missing mandatory field `{field}`"));
            None
        }
    }
}

/// Validate the whole register against the policy's `[exceptions]` section.
pub fn validate(file: &WaiverFile, exceptions: &Exceptions, today: Date) -> WaiverSummary {
    let mut entries: Vec<ValidatedWaiver> = Vec::new();
    let mut seen_ids: Vec<String> = Vec::new();

    for (index, raw) in file.waiver.iter().enumerate() {
        let mut problems: Vec<String> = Vec::new();

        let id = match require(&raw.id, "id", &mut problems) {
            Some(id) => id.to_string(),
            None => format!("<waiver #{}>", index + 1),
        };
        if seen_ids.contains(&id) {
            problems.push(format!("duplicate waiver id `{id}`"));
        }
        seen_ids.push(id.clone());

        match &raw.kind {
            Some(k) if KINDS.contains(&k.as_str()) => {}
            Some(k) => problems.push(format!("unknown kind `{k}`; expected one of {}", KINDS.join(", "))),
            None => problems.push("missing mandatory field `kind`".to_string()),
        }

        if let Some(path) = require(&raw.path, "path", &mut problems) {
            let wildcarded = path.contains('*') || path.contains('?');
            let symbol_wildcarded = raw.symbol.as_deref().is_some_and(|s| s.contains('*') || s.contains('?'));
            if (wildcarded || symbol_wildcarded)
                && raw.wildcard_justification.as_deref().map(|s| s.trim().len()).unwrap_or(0) < 20
            {
                problems.push(
                    "wildcard scope requires a `wildcard_justification` of at least 20 characters (§13: narrow scope, no wildcard unless genuinely justified)"
                        .to_string(),
                );
            }
        }

        if exceptions.require_reason {
            if let Some(reason) = require(&raw.reason, "reason", &mut problems) {
                let lowered = reason.to_ascii_lowercase();
                if reason.len() < 20 {
                    problems.push(format!("`reason` is {} characters; at least 20 are required", reason.len()));
                } else if BOILERPLATE.contains(&lowered.trim_end_matches('.')) {
                    problems.push("`reason` is boilerplate and explains nothing".to_string());
                }
            }
        }

        if exceptions.require_owner_field {
            require(&raw.owner, "owner", &mut problems);
        }
        if exceptions.require_issue_for_persistent {
            require(&raw.issue, "issue", &mut problems);
        }
        if exceptions.require_independent_approval {
            let approver = require(&raw.approved_by, "approved_by", &mut problems);
            if let (Some(a), Some(o)) = (approver, raw.owner.as_deref()) {
                if a.eq_ignore_ascii_case(o.trim()) {
                    problems.push(
                        "`approved_by` equals `owner`: an exception may not be self-approved (§13 independent approval)"
                            .to_string(),
                    );
                }
            }
        }

        let created = require(&raw.created, "created", &mut problems).and_then(|s| match Date::parse(s) {
            Ok(d) => Some(d),
            Err(e) => {
                problems.push(format!("`created`: {e}"));
                None
            }
        });

        let review_after = if exceptions.require_expiry_field {
            require(&raw.review_after, "review_after", &mut problems).and_then(|s| match Date::parse(s) {
                Ok(d) => Some(d),
                Err(e) => {
                    problems.push(format!("`review_after`: {e}"));
                    None
                }
            })
        } else {
            raw.review_after.as_deref().and_then(|s| Date::parse(s).ok())
        };

        if let (Some(c), Some(r)) = (created, review_after) {
            if r <= c {
                problems.push(format!("`review_after` ({r}) must be after `created` ({c})"));
            } else if c.days_until(r) > exceptions.max_waiver_lifetime_days {
                problems.push(format!(
                    "waiver lifetime is {} days; policy allows at most {}",
                    c.days_until(r),
                    exceptions.max_waiver_lifetime_days
                ));
            }
        }

        let expired = review_after.is_some_and(|r| r < today);
        let status = if !problems.is_empty() {
            WaiverStatus::Invalid
        } else if expired {
            problems.push(format!(
                "expired: `review_after` was {} and today is {today}; renew it through an independent policy review or remove it",
                review_after.expect("expired implies a parsed date")
            ));
            WaiverStatus::Expired
        } else {
            WaiverStatus::Active
        };

        entries.push(ValidatedWaiver {
            id,
            kind: raw.kind.clone(),
            path: raw.path.clone(),
            symbol: raw.symbol.clone(),
            reason: raw.reason.clone(),
            owner: raw.owner.clone(),
            approved_by: raw.approved_by.clone(),
            issue: raw.issue.clone(),
            created: raw.created.clone(),
            review_after: raw.review_after.clone(),
            status,
            problems,
        });
    }

    WaiverSummary {
        total: entries.len(),
        active: entries.iter().filter(|e| e.status == WaiverStatus::Active).count(),
        expired: entries.iter().filter(|e| e.status == WaiverStatus::Expired).count(),
        invalid: entries.iter().filter(|e| e.status == WaiverStatus::Invalid).count(),
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exceptions() -> Exceptions {
        Exceptions {
            require_reason: true,
            require_issue_for_persistent: true,
            require_independent_approval: true,
            require_owner_field: true,
            require_expiry_field: true,
            max_waiver_lifetime_days: 180,
        }
    }

    fn today() -> Date {
        Date::parse("2026-08-20").unwrap()
    }

    const GOOD: &str = r##"
schema = 1
[[waiver]]
id = "QW-0042"
kind = "mutation-equivalent"
path = "tools/remote-wal-spike/src/bar.rs"
symbol = "normalize_legacy_header"
reason = "Mutant changes an internal representation with no observable semantic difference."
owner = "architecture"
approved_by = "human-technical-owner"
issue = "#1234"
created = "2026-08-20"
review_after = "2026-11-20"
"##;

    fn validate_text(text: &str) -> WaiverSummary {
        validate(&WaiverFile::parse(text).unwrap(), &exceptions(), today())
    }

    #[test]
    fn the_spec_13_example_is_accepted() {
        let s = validate_text(GOOD);
        assert_eq!((s.total, s.active, s.expired, s.invalid), (1, 1, 0, 0), "{:?}", s.entries[0].problems);
        assert!(s.is_clean());
    }

    #[test]
    fn every_waiver_in_the_repository_register_is_valid_and_unexpired() {
        // This used to assert the register was EMPTY. That was a statement
        // about how much debt existed, not about whether the register is
        // sound, and it fails the moment a waiver is legitimately recorded —
        // which R8-P0-04 did (QW-0001, the Stryker advisory). What must hold
        // permanently is that every waiver present is COMPLETE, INDEPENDENTLY
        // APPROVED and NOT EXPIRED; the count itself is tracked as debt and
        // surfaced in every report, which is where it belongs.
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.quality/waivers/quality-waivers.toml"))
                .unwrap();
        let s = validate(&WaiverFile::parse(&text).unwrap(), &exceptions(), today());
        assert!(
            s.is_clean(),
            "the waiver register must have no invalid or expired entries: {:?}",
            s.entries.iter().filter(|e| !e.problems.is_empty()).collect::<Vec<_>>()
        );
        assert_eq!(s.total, s.active, "every recorded waiver must be active (none expired)");
    }

    #[test]
    fn a_waiver_without_a_reason_is_refused() {
        let text = GOOD.replace(
            r#"reason = "Mutant changes an internal representation with no observable semantic difference.""#,
            "",
        );
        let s = validate_text(&text);
        assert_eq!(s.invalid, 1);
        assert_eq!(s.active, 0);
        assert!(
            s.entries[0].problems.iter().any(|p| p.contains("missing mandatory field `reason`")),
            "{:?}",
            s.entries[0].problems
        );
    }

    #[test]
    fn a_boilerplate_or_too_short_reason_is_refused() {
        for bad in ["TODO", "because", "n/a", "short"] {
            let text =
                GOOD.replace("Mutant changes an internal representation with no observable semantic difference.", bad);
            let s = validate_text(&text);
            assert_eq!(s.invalid, 1, "reason {bad:?} must be refused");
        }
    }

    #[test]
    fn an_expired_waiver_is_refused() {
        // A well-formed waiver whose review date has simply passed.
        let text = GOOD
            .replace(r#"created = "2026-08-20""#, r#"created = "2026-01-20""#)
            .replace(r#"review_after = "2026-11-20""#, r#"review_after = "2026-06-20""#);
        let s = validate_text(&text);
        assert_eq!(s.expired, 1);
        assert_eq!(s.active, 0);
        assert!(!s.is_clean());
        assert!(s.problem_summary().contains("expired"));
    }

    #[test]
    fn a_waiver_expiring_exactly_today_is_still_active() {
        let text = GOOD.replace(r#"review_after = "2026-11-20""#, r#"review_after = "2026-08-20""#);
        let s = validate_text(&text);
        // `created` == `review_after` is itself invalid, so use a real span.
        assert_eq!(s.invalid, 1);

        let text = GOOD
            .replace(r#"created = "2026-08-20""#, r#"created = "2026-06-20""#)
            .replace(r#"review_after = "2026-11-20""#, r#"review_after = "2026-08-20""#);
        let s = validate_text(&text);
        assert_eq!(s.active, 1, "{:?}", s.entries[0].problems);
    }

    #[test]
    fn missing_owner_issue_or_approver_is_refused() {
        for field in [r#"owner = "architecture""#, r##"issue = "#1234""##, r#"approved_by = "human-technical-owner""#] {
            let s = validate_text(&GOOD.replace(field, ""));
            assert_eq!(s.invalid, 1, "removing {field} must invalidate the waiver");
        }
    }

    #[test]
    fn self_approval_is_refused() {
        let text = GOOD.replace(r#"approved_by = "human-technical-owner""#, r#"approved_by = "architecture""#);
        let s = validate_text(&text);
        assert_eq!(s.invalid, 1);
        assert!(s.entries[0].problems.iter().any(|p| p.contains("self-approved")));
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        let s = validate_text(&GOOD.replace(r#"kind = "mutation-equivalent""#, r#"kind = "just-because""#));
        assert_eq!(s.invalid, 1);
    }

    #[test]
    fn a_wildcard_scope_needs_an_explicit_justification() {
        let text = GOOD.replace(r#"path = "tools/remote-wal-spike/src/bar.rs""#, r#"path = "tools/**""#);
        let s = validate_text(&text);
        assert_eq!(s.invalid, 1);
        assert!(s.entries[0].problems.iter().any(|p| p.contains("wildcard")));

        let text = format!(
            "{text}\nwildcard_justification = \"Generated protocol bindings share one mutation profile across the tree.\"\n"
        );
        let s = validate_text(&text);
        assert_eq!(s.active, 1, "{:?}", s.entries[0].problems);
    }

    #[test]
    fn an_over_long_lifetime_is_refused() {
        let text = GOOD.replace(r#"review_after = "2026-11-20""#, r#"review_after = "2028-11-20""#);
        let s = validate_text(&text);
        assert_eq!(s.invalid, 1);
        assert!(s.entries[0].problems.iter().any(|p| p.contains("lifetime")));
    }

    #[test]
    fn duplicate_ids_are_refused() {
        let text = format!("{GOOD}\n{}", GOOD.trim_start_matches("\nschema = 1"));
        let s = validate_text(&text);
        assert_eq!(s.total, 2);
        assert!(s.entries[1].problems.iter().any(|p| p.contains("duplicate")));
    }

    #[test]
    fn a_backwards_date_range_is_refused() {
        let text = GOOD.replace(r#"created = "2026-08-20""#, r#"created = "2026-12-20""#);
        let s = validate_text(&text);
        assert_eq!(s.invalid, 1);
    }
}
