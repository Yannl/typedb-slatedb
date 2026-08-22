//! Quality controller modules.
//!
//! Layering, innermost first:
//!   `glob`, `date`, `digest`  - dependency-free primitives
//!   `policy`, `waivers`       - the protected policy and the exception register
//!   `scope`                   - the single machine-readable scope manifest
//!   `diff`                    - git change set + the §15 diff-to-gate matrix
//!   `forkowned`               - which overlay files are ours, derived not declared
//!   `tools`                   - pinned tool presence/version detection
//!   `capability`              - the ONE environment model, probed before any gate runs
//!   `report`                  - the §4 unified evidence document
//!   `gates`                   - gate catalogue and execution
//!   `exec`, `git`             - process and repository plumbing
//!   `cli`                     - argv wiring; contains no policy semantics

pub mod capability;
pub mod cli;
pub mod date;
pub mod diff;
pub mod digest;
pub mod exec;
pub mod forkowned;
pub mod gates;
pub mod git;
pub mod glob;
pub mod policy;
pub mod report;
pub mod scope;
pub mod tools;
pub mod waivers;
