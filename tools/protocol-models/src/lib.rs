/*
 * CT-P0 — pure deterministic models for the TypeDB-on-R2 protocol core.
 *
 * Brief §22.1 requires executable models, before any production reducer or
 * client, for: WAL allocation/finalisation/status-singleton/sync/fixed
 * iteration; controller incarnation/session/epoch fencing; command
 * reservation/no-intent/outcome; and the control journal/anchor chain.
 *
 * These models are deliberately small, deterministic, and free of clocks,
 * randomness, and I/O. Tests enumerate crash/retry/reorder/stale-actor
 * schedules exhaustively for bounded sizes, and every load-bearing checker
 * has a negative control proving it can fail (brief §22.9).
 */

pub mod command_model;
pub mod fencing_model;
pub mod journal_model;
pub mod wal_model;
