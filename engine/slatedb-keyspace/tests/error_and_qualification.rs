/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Structured-error and production-qualification contracts.

use slatedb_keyspace::{
    production_qualification, FeatureStatus, KeyspaceError, Operation, RetryClass,
};

#[test]
fn a_config_error_is_permanent_and_carries_its_operation() {
    let e = KeyspaceError::config("bad");
    assert_eq!(e.operation, Operation::Configure);
    assert_eq!(e.retry, RetryClass::Permanent);
    assert!(!e.is_transient());
}

#[test]
fn operation_identity_survives_display() {
    let e = KeyspaceError::new(Operation::GetPrev, RetryClass::Transient, "network blip");
    let shown = e.to_string();
    assert!(shown.contains("get_prev"), "operation must be legible: {shown}");
    assert!(e.is_transient());
}

#[test]
fn the_engine_is_not_production_qualified_and_says_why() {
    let q = production_qualification();
    assert!(!q.is_production_qualified());

    // Everyday keyspace operations are qualified; the two gaps are not.
    assert!(q.keyspace_operations.is_qualified());
    assert!(matches!(q.checkpoint_restore, FeatureStatus::Unimplemented { .. }));
    assert!(matches!(q.sustained_writes, FeatureStatus::Unimplemented { .. }));

    let gaps = q.gaps();
    assert_eq!(gaps.len(), 2, "exactly the two known gaps");
    // The checkpoint gap must name the expiry and the missing controller-rooted protocol,
    // rather than being hidden behind a passing engine test.
    let checkpoint = gaps.iter().find(|(name, _)| *name == "checkpoint_restore").unwrap();
    assert!(checkpoint.1.contains("expire"), "must name the one-hour expiry: {}", checkpoint.1);
    assert!(
        checkpoint.1.contains("controller-rooted") || checkpoint.1.contains("controller"),
        "must name the missing controller-rooted protocol: {}",
        checkpoint.1
    );
}
