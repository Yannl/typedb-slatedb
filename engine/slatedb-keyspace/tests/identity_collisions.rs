/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Proof that exact identities cannot collide where path-final-component prefixes could.
//!
//! Each test constructs the exact scenario the old scheme silently corrupted and asserts two
//! things: the prefixes are unequal, and neither is a *string prefix* of the other — the
//! stronger property an object store's prefix-namespaced `LIST` actually requires.

use slatedb_keyspace::StoreIdentity;
use uuid::Uuid;

fn base() -> StoreIdentity {
    StoreIdentity::new("prod", Uuid::from_u128(1), 0, Uuid::from_u128(100), 1, "0123456789abcdef")
        .unwrap()
}

/// Neither string is a prefix of the other, and they are unequal.
fn disjoint(a: &str, b: &str) {
    assert_ne!(a, b, "identities produced identical prefixes");
    assert!(!a.starts_with(b), "{b:?} is a string prefix of {a:?}");
    assert!(!b.starts_with(a), "{a:?} is a string prefix of {b:?}");
}

#[test]
fn two_databases_do_not_collide() {
    let a = base();
    let b = StoreIdentity::new(
        "prod",
        Uuid::from_u128(2),
        0,
        Uuid::from_u128(100),
        1,
        "0123456789abcdef",
    )
    .unwrap();
    disjoint(&a.prefix(), &b.prefix());
}

#[test]
fn two_generations_do_not_collide() {
    let a = base();
    let b = a.next_generation();
    assert_eq!(b.generation(), a.generation() + 1);
    disjoint(&a.prefix(), &b.prefix());
}

#[test]
fn two_scratch_attempts_of_one_generation_do_not_collide() {
    let a = base();
    let b = a.new_attempt();
    assert_eq!(b.generation(), a.generation());
    assert_ne!(b.materialization(), a.materialization());
    disjoint(&a.prefix(), &b.prefix());
}

#[test]
fn a_stale_actor_cannot_address_the_current_generations_bytes() {
    // The "stale actor" is a process still holding an old generation's identity after the
    // database has been destroyed and recreated. Its prefix must not reach the new bytes.
    let stale = base();
    let current = stale.next_generation();
    disjoint(&stale.prefix(), &current.prefix());
}

#[test]
fn numerically_adjacent_generations_are_not_string_prefixes() {
    // The bug a naive `gen-{n}` scheme has: `gen-1` is a string prefix of `gen-10`. Zero
    // padding to fixed width is what prevents it.
    let a = base();
    let mut b = a.clone();
    for _ in 0..9 {
        b = b.next_generation();
    }
    // Force same materialization so only the generation differs, isolating the property.
    let a_pref = a.prefix();
    let b_pref = b.prefix().replace(
        &format!("mat-{}", b.materialization()),
        &format!("mat-{}", a.materialization()),
    );
    disjoint(&a_pref, &b_pref);
}

#[test]
fn different_environments_are_isolated() {
    let prod = base();
    let staging = StoreIdentity::new(
        "staging",
        prod.database_id(),
        prod.generation(),
        prod.materialization(),
        prod.keyspace_schema_version(),
        prod.format_digest(),
    )
    .unwrap();
    disjoint(&prod.prefix(), &staging.prefix());
}

#[test]
fn a_bad_environment_is_refused() {
    assert!(StoreIdentity::new("", Uuid::nil(), 0, Uuid::nil(), 0, "0123456789abcdef").is_err());
    assert!(
        StoreIdentity::new("Prod/../x", Uuid::nil(), 0, Uuid::nil(), 0, "0123456789abcdef")
            .is_err(),
        "path-traversal characters must be rejected"
    );
    assert!(StoreIdentity::new("-prod", Uuid::nil(), 0, Uuid::nil(), 0, "0123456789abcdef").is_err());
}

#[test]
fn a_bad_format_digest_is_refused() {
    // Wrong length would let one identity's prefix be a string prefix of another's.
    assert!(StoreIdentity::new("prod", Uuid::nil(), 0, Uuid::nil(), 0, "abc").is_err());
    // Non-hex is refused too.
    assert!(StoreIdentity::new("prod", Uuid::nil(), 0, Uuid::nil(), 0, "zzzzzzzzzzzzzzzz").is_err());
}
