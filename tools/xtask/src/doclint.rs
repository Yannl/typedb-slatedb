//! `cargo xtask doc-lint` — the document/schema/patch/gate linter required by Phase A.
//!
//! The contract is normative, so its internal consistency is itself a gate: a patch id
//! referenced by the playbook but absent from the brief, or a gate cited by a review
//! action that no phase produces, is a hole in the proof chain.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{bail, Result};
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct DocLintReport {
    pub documents: Vec<DocumentRecord>,
    /// Patch ids used in the playbook but never defined in the brief, and vice versa.
    pub patch_ids: SymbolAudit,
    pub gate_ids: SymbolAudit,
    pub schemas_valid: Vec<String>,
    pub findings: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct SymbolAudit {
    pub in_brief: Vec<String>,
    pub in_playbook: Vec<String>,
    pub playbook_only: Vec<String>,
    pub brief_only: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DocumentRecord {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub lines: usize,
}

fn ids(text: &str, pattern: &regex_lite::Regex) -> BTreeSet<String> {
    pattern
        .find_iter(text)
        .into_iter()
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Minimal regex support, so the linter carries no heavyweight dependency.
mod regex_lite {
    /// Matches ids of the shape `<PREFIX>-P<digits>` or `G<digits>`.
    pub struct Regex {
        kind: Kind,
    }
    enum Kind {
        Patch,
        Gate,
    }
    impl Regex {
        pub fn patch() -> Self {
            Self { kind: Kind::Patch }
        }
        pub fn gate() -> Self {
            Self { kind: Kind::Gate }
        }
        pub fn find_iter<'a>(&self, text: &'a str) -> Vec<Match<'a>> {
            let bytes = text.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                let start = i;
                match self.kind {
                    Kind::Patch => {
                        // <UPPER>{2,3}-P<digit>+
                        let mut j = i;
                        while j < bytes.len() && bytes[j].is_ascii_uppercase() {
                            j += 1;
                        }
                        let letters = j - i;
                        if (2..=3).contains(&letters)
                            && bytes.get(j) == Some(&b'-')
                            && bytes.get(j + 1) == Some(&b'P')
                            && bytes.get(j + 2).is_some_and(u8::is_ascii_digit)
                        {
                            let mut k = j + 2;
                            while k < bytes.len() && bytes[k].is_ascii_digit() {
                                k += 1;
                            }
                            // Reject when glued to a preceding word character.
                            let prev_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
                            if prev_ok {
                                out.push(Match { text: &text[start..k] });
                            }
                            i = k;
                            continue;
                        }
                    }
                    Kind::Gate => {
                        if bytes[i] == b'G' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
                            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
                            let mut k = i + 1;
                            while k < bytes.len() && bytes[k].is_ascii_digit() {
                                k += 1;
                            }
                            let next_ok = bytes.get(k).is_none_or(|b| !b.is_ascii_alphanumeric());
                            if prev_ok && next_ok {
                                out.push(Match { text: &text[i..k] });
                            }
                            i = k;
                            continue;
                        }
                    }
                }
                i += 1;
            }
            out
        }
    }
    pub struct Match<'a> {
        text: &'a str,
    }
    impl<'a> Match<'a> {
        pub fn as_str(&self) -> &'a str {
            self.text
        }
    }
}

pub fn run(repo_root: &Path) -> Result<()> {
    let contract = repo_root.join("contract");
    let mut report = DocLintReport::default();

    let mut files: Vec<_> = std::fs::read_dir(&contract)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();

    let mut texts: BTreeMap<String, String> = BTreeMap::new();
    for path in &files {
        let bytes = std::fs::read(path)?;
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        report.documents.push(DocumentRecord {
            path: name.clone(),
            sha256: source_lock::hash_file(path)?,
            bytes: bytes.len() as u64,
            lines: bytes.iter().filter(|&&b| b == b'\n').count(),
        });
        if let Ok(text) = String::from_utf8(bytes) {
            texts.insert(name, text);
        }
    }

    let brief = texts
        .get("typedb-r2-implementation-brief-v16.md")
        .cloned()
        .unwrap_or_default();
    let playbook = texts
        .get("typedb-r2-v16-implementation-playbook.md")
        .cloned()
        .unwrap_or_default();
    if brief.is_empty() || playbook.is_empty() {
        bail!("contract/ is missing the brief or the playbook");
    }

    let patch = regex_lite::Regex::patch();
    let gate = regex_lite::Regex::gate();

    let audit = |a: BTreeSet<String>, b: BTreeSet<String>| SymbolAudit {
        playbook_only: b.difference(&a).cloned().collect(),
        brief_only: a.difference(&b).cloned().collect(),
        in_brief: a.into_iter().collect(),
        in_playbook: b.into_iter().collect(),
    };
    report.patch_ids = audit(ids(&brief, &patch), ids(&playbook, &patch));
    report.gate_ids = audit(ids(&brief, &gate), ids(&playbook, &gate));

    // Every patch id the playbook schedules must be defined by the brief; the reverse is
    // allowed, because the brief also names patches for phases beyond the authorised set.
    for id in &report.patch_ids.playbook_only {
        report
            .findings
            .push(format!("patch id {id} is scheduled by the playbook but never defined in the brief"));
    }
    for id in &report.gate_ids.playbook_only {
        report
            .findings
            .push(format!("gate {id} is referenced by the playbook but never defined in the brief"));
    }

    // Schemas must parse and be usable as validators.
    for (name, text) in &texts {
        if !name.ends_with(".json") {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                report.findings.push(format!("{name} is not valid JSON: {e}"));
                continue;
            }
        };
        if value.get("$schema").is_some() {
            match jsonschema::validator_for(&value) {
                Ok(_) => report.schemas_valid.push(name.clone()),
                Err(e) => report.findings.push(format!("{name} is not a compilable schema: {e}")),
            }
        }
    }

    let out_dir = repo_root.join("docs/evidence/phase-a");
    std::fs::create_dir_all(&out_dir)?;
    let out = out_dir.join("doc-lint.json");
    std::fs::write(&out, serde_json::to_string_pretty(&report)? + "\n")?;

    println!("documents linted   : {}", report.documents.len());
    println!("patch ids (brief)  : {}", report.patch_ids.in_brief.len());
    println!("patch ids (playbook): {}", report.patch_ids.in_playbook.len());
    println!("gates (brief)      : {}", report.gate_ids.in_brief.len());
    println!("schemas compiled   : {}", report.schemas_valid.len());
    println!("findings           : {}", report.findings.len());
    for f in &report.findings {
        println!("   - {f}");
    }
    println!("written: {}", out.display());

    if !report.findings.is_empty() {
        bail!("document lint found {} inconsistency/ies", report.findings.len());
    }
    Ok(())
}
