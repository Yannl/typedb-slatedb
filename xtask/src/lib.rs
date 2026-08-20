//! Deterministic quality controller (spec §3).
//!
//! The library half exists so the controller's own logic can be tested as
//! adversarially as the code it gates. Every decision-making primitive here is
//! a pure function over explicit inputs; the `bin` half only wires argv, the
//! filesystem and `git` into them.

pub mod quality;
