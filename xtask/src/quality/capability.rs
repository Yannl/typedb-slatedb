//! The controller's half of the ONE environment model (R8-P1-07).
//!
//! The round-8 audit found a missing native header surfacing as
//! `QualityFailure`: a Rust child exited nonzero, the classifier saw a nonzero
//! exit with no recognised substring, and the report said the code was broken.
//! Recognising the message would only relocate the fragility — a compiler that
//! words the error differently, or a different missing component, lands in the
//! same wrong half of the report.
//!
//! So capability is decided BEFORE the code under test is invoked, and it is
//! decided structurally: a header by compiling it, a shared library by loading
//! it, a namespace by entering one, a socket by binding one. The declarations
//! live in `.quality/capabilities.toml` and the probes in
//! `tools/quality/capabilities.py`; `tools/dev/doctor.py` runs the same probes,
//! which is what makes "doctor and the gate agree on readiness" a property
//! rather than a coincidence.
//!
//! This module does not probe anything itself. It runs the probe runner once
//! per invocation and answers, per gate, "may this run".

use std::{collections::BTreeMap, path::Path, process::Command};

/// One probed capability, as the runner reported it.
#[derive(Debug, Clone)]
pub struct Capability {
    pub id: String,
    pub ok: bool,
    pub detail: String,
    pub why: String,
    pub remediation: String,
}

/// Why a gate may not run.
#[derive(Debug, Clone)]
pub struct Unmet {
    /// Human-readable statement of what is missing.
    pub detail: String,
    /// Exactly what to do about it.
    pub remediation: String,
}

#[derive(Debug, Clone)]
pub enum Preflight {
    /// The probes ran. `requires` is the inventory's gate map, carried back
    /// with the results so the controller never parses the inventory a second
    /// time — one file, one reader, one answer.
    Probed { requires: BTreeMap<String, Vec<String>>, caps: BTreeMap<String, Capability> },
    /// The probe runner itself could not answer. That is not permission to
    /// proceed: an environment model that cannot be consulted is an unknown
    /// environment, and every gate is infrastructure until it can be.
    Unavailable(String),
    /// Deliberately not run — unit tests that exercise gate logic on a fixture
    /// rather than a machine.
    NotRun,
}

pub const RUNNER: &str = "tools/quality/capabilities.py";

impl Preflight {
    /// Probe every capability the inventory declares, once.
    ///
    /// The whole inventory rather than the selected gates' union: it costs well
    /// under a second, it makes the report say what this machine is regardless
    /// of which gates ran, and it removes an ordering dependency between gate
    /// selection and preflight.
    pub fn probe(repo_root: &Path) -> Preflight {
        let out = Command::new("python3").arg(RUNNER).arg("--all").arg("--json").current_dir(repo_root).output();
        let out = match out {
            Ok(o) => o,
            Err(e) => return Preflight::Unavailable(format!("could not run `python3 {RUNNER}`: {e}")),
        };
        // Exit 3 means "capabilities are unmet", which is an ANSWER, not a
        // failure to answer. Only a code the runner reserves for its own
        // breakage (1) or a signal leaves us without a model.
        let code = out.status.code();
        if !matches!(code, Some(0) | Some(3)) {
            return Preflight::Unavailable(format!(
                "`python3 {RUNNER} --all --json` exited {}: {}",
                code.map(|c| c.to_string()).unwrap_or_else(|| "by signal".into()),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let parsed: serde_json::Value = match serde_json::from_slice(&out.stdout) {
            Ok(v) => v,
            Err(e) => return Preflight::Unavailable(format!("{RUNNER} emitted unparsable JSON: {e}")),
        };
        Self::from_json(&parsed)
    }

    pub fn from_json(parsed: &serde_json::Value) -> Preflight {
        let mut requires = BTreeMap::new();
        let Some(map) = parsed.get("requires").and_then(|v| v.as_object()) else {
            return Preflight::Unavailable(format!("{RUNNER} reported no gate/capability map"));
        };
        for (gate, needs) in map {
            requires.insert(
                gate.clone(),
                needs
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                    .unwrap_or_default(),
            );
        }
        let mut caps = BTreeMap::new();
        for entry in parsed.get("probed").and_then(|v| v.as_array()).into_iter().flatten() {
            let s = |k: &str| entry.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let id = s("id");
            if id.is_empty() {
                continue;
            }
            caps.insert(
                id.clone(),
                Capability {
                    id,
                    ok: entry.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
                    detail: s("detail"),
                    why: s("why"),
                    remediation: s("remediation"),
                },
            );
        }
        Preflight::Probed { requires, caps }
    }

    /// Everything probed, for the report.
    pub fn capabilities(&self) -> Vec<&Capability> {
        match self {
            Preflight::Probed { caps, .. } => caps.values().collect(),
            _ => Vec::new(),
        }
    }

    /// `None` means this gate may run.
    pub fn unmet_for(&self, gate: &str) -> Option<Unmet> {
        match self {
            Preflight::NotRun => None,
            Preflight::Unavailable(why) => Some(Unmet {
                detail: format!(
                    "the environment model could not be consulted, so it is unknown whether gate \
                     `{gate}` can run at all: {why}"
                ),
                remediation: format!(
                    "repair the probe runner (`python3 {RUNNER} --self-test`); the gate was NOT run, \
                     because a controller that cannot tell a missing component from a defect must \
                     not report either"
                ),
            }),
            Preflight::Probed { requires, caps } => {
                // A gate the inventory does not name has an UNDECLARED
                // environment dependency, which is not the same as none. This
                // is what stops the model silently going stale as gates are
                // added: a new gate refuses until someone states what it needs.
                let Some(needs) = requires.get(gate) else {
                    return Some(Unmet {
                        detail: format!(
                            "gate `{gate}` is not declared in .quality/capabilities.toml, so what it \
                             needs from this machine is unknown"
                        ),
                        remediation: format!(
                            "add a `{gate}` entry to the [gates] table in .quality/capabilities.toml \
                             (an empty list is a valid, explicit answer)"
                        ),
                    });
                };
                let missing: Vec<&Capability> = needs.iter().filter_map(|id| caps.get(id)).filter(|c| !c.ok).collect();
                // A required capability the runner did not probe is itself an
                // unmet capability: the inventory and the results disagree.
                let unprobed: Vec<&String> = needs.iter().filter(|id| !caps.contains_key(*id)).collect();
                if missing.is_empty() && unprobed.is_empty() {
                    return None;
                }
                let mut detail = format!(
                    "gate `{gate}` needs {} host capabilit{} this machine does not have, so it was \
                     NOT run and no quality conclusion may be drawn from it:",
                    missing.len() + unprobed.len(),
                    if missing.len() + unprobed.len() == 1 { "y" } else { "ies" }
                );
                for c in &missing {
                    detail.push_str(&format!("\n  {} — {} ({})", c.id, c.detail, c.why));
                }
                for id in &unprobed {
                    detail.push_str(&format!("\n  {id} — declared by the gate but never probed"));
                }
                let remediation = missing
                    .iter()
                    .map(|c| c.remediation.clone())
                    .chain(
                        unprobed.iter().map(|id| format!("declare a probe for `{id}` in .quality/capabilities.toml")),
                    )
                    .collect::<Vec<_>>()
                    .join("  &&  ");
                Some(Unmet { detail, remediation })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probed(json: &str) -> Preflight {
        Preflight::from_json(&serde_json::from_str(json).unwrap())
    }

    const SAMPLE: &str = r#"{
      "requires": {"rust.tests": ["native.cc", "library.libclang"], "py.lint": []},
      "probed": [
        {"id": "native.cc", "ok": true, "detail": "/usr/bin/cc", "why": "w", "remediation": "r1"},
        {"id": "library.libclang", "ok": false, "detail": "not loadable", "why": "bindgen needs it", "remediation": "apt-get install -y libclang-dev"}
      ]
    }"#;

    #[test]
    fn a_gate_whose_capability_is_unmet_is_refused_with_the_inventorys_remediation() {
        let unmet = probed(SAMPLE).unmet_for("rust.tests").expect("must refuse");
        assert!(unmet.detail.contains("library.libclang"), "{}", unmet.detail);
        assert!(unmet.detail.contains("bindgen needs it"), "{}", unmet.detail);
        assert!(unmet.detail.contains("NOT run"), "{}", unmet.detail);
        assert!(!unmet.detail.contains("native.cc"), "a SATISFIED capability must not be blamed");
        assert_eq!(unmet.remediation, "apt-get install -y libclang-dev");
    }

    #[test]
    fn a_gate_declaring_nothing_runs() {
        assert!(probed(SAMPLE).unmet_for("py.lint").is_none());
    }

    #[test]
    fn a_gate_absent_from_the_inventory_is_refused_rather_than_assumed_empty() {
        let unmet = probed(SAMPLE).unmet_for("brand.new").expect("must refuse");
        assert!(unmet.detail.contains("not declared"), "{}", unmet.detail);
    }

    #[test]
    fn a_required_capability_the_runner_never_probed_is_unmet() {
        let unmet = probed(r#"{"requires": {"g": ["ghost"]}, "probed": []}"#).unmet_for("g").expect("must refuse");
        assert!(unmet.detail.contains("never probed"), "{}", unmet.detail);
    }

    #[test]
    fn a_runner_that_cannot_answer_refuses_every_gate_instead_of_permitting_them() {
        let p = Preflight::Unavailable("python3 is missing".into());
        let unmet = p.unmet_for("anything").expect("must refuse");
        assert!(unmet.detail.contains("could not be consulted"), "{}", unmet.detail);
    }

    #[test]
    fn unparsable_runner_output_is_unavailable_not_an_empty_model() {
        // An empty `requires` map would make every gate "undeclared" — the same
        // refusal by a different route. What must never happen is a model that
        // reports every gate as satisfied because nothing was probed.
        match probed(r#"{"probed": []}"#) {
            Preflight::Unavailable(why) => assert!(why.contains("no gate/capability map")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn not_run_permits_everything_so_unit_tests_do_not_need_a_machine() {
        assert!(Preflight::NotRun.unmet_for("rust.tests").is_none());
    }

    /// The completeness property that keeps ONE model: every gate the
    /// controller can run is declared in the inventory, and the inventory
    /// declares no gate the controller does not have.
    #[test]
    fn the_inventory_and_the_gate_catalogue_name_exactly_the_same_gates() {
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let text = std::fs::read_to_string(root.join(".quality/capabilities.toml"))
            .expect(".quality/capabilities.toml must exist");
        let doc: toml::Value = toml::from_str(&text).expect("inventory must parse");
        let declared: std::collections::BTreeSet<String> =
            doc.get("gates").and_then(|g| g.as_table()).expect("[gates] table").keys().cloned().collect();
        let known: std::collections::BTreeSet<String> =
            super::super::gates::all_ids().into_iter().map(str::to_owned).collect();
        let undeclared: Vec<_> = known.difference(&declared).collect();
        let unknown: Vec<_> = declared.difference(&known).collect();
        assert!(undeclared.is_empty(), "gates with no capability declaration (add them to [gates]): {undeclared:?}");
        assert!(unknown.is_empty(), "inventory names gates the controller does not have: {unknown:?}");
    }
}
