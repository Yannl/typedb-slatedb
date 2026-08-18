/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#![deny(unused_must_use)]
#![deny(rust_2018_idioms)]

use std::{
    borrow::Cow,
    error::Error,
    fmt, io,
    ops::{Add, AddAssign, Sub},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use crate::wal::WALError;

pub mod wal;

pub trait DurabilityService {
    fn register_record_type(&mut self, record_type: DurabilityRecordType, record_name: &str);

    fn sequenced_write(
        &self,
        record_type: DurabilityRecordType,
        bytes: &[u8],
    ) -> Result<DurabilitySequenceNumber, DurabilityServiceError>;

    fn unsequenced_write(&self, record_type: DurabilityRecordType, bytes: &[u8]) -> Result<(), DurabilityServiceError>;

    fn iter_any_from(
        &self,
        sequence_number: DurabilitySequenceNumber,
    ) -> Result<impl Iterator<Item = Result<RawRecord<'static>, DurabilityServiceError>>, DurabilityServiceError>;

    fn iter_type_from(
        &self,
        sequence_number: DurabilitySequenceNumber,
        record_type: DurabilityRecordType,
    ) -> Result<impl Iterator<Item = Result<RawRecord<'static>, DurabilityServiceError>>, DurabilityServiceError>;

    fn find_last_type(
        &self,
        record_type: DurabilityRecordType,
    ) -> Result<Option<RawRecord<'static>>, DurabilityServiceError>;

    fn truncate_from(&self, sequence_number: DurabilitySequenceNumber) -> Result<(), DurabilityServiceError>;

    fn delete_durability(self) -> Result<(), DurabilityServiceError>;

    fn reset(&mut self) -> Result<(), DurabilityServiceError>;
}

pub type DurabilityRecordType = u8;

#[derive(Debug)]
pub struct RawRecord<'a> {
    pub sequence_number: DurabilitySequenceNumber,
    pub record_type: DurabilityRecordType,
    pub bytes: Cow<'a, [u8]>,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DurabilitySequenceNumber {
    number: u64,
}

impl fmt::Display for DurabilitySequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SeqNr[{}]", self.number)
    }
}

impl DurabilitySequenceNumber {
    pub const MIN: Self = Self { number: u64::MIN };
    pub const MAX: Self = Self { number: u64::MAX };

    pub fn new(number: u64) -> Self {
        Self { number }
    }

    /// Successor, refusing to wrap (S-P0-09). Positional arithmetic at the
    /// top of the sequence space is a hard fault in every build profile:
    /// the unchecked `+ 1` panicked in debug but WRAPPED to zero in release,
    /// silently re-issuing the identity of the first commit ever made.
    /// Callers that can surface a typed error use [`Self::checked_next`];
    /// the panicking form exists for positional uses where an overflow is
    /// unreachable by construction.
    pub fn next(&self) -> Self {
        self.checked_next().expect("DurabilitySequenceNumber overflow: the u64 sequence space is exhausted")
    }

    /// Successor, or `None` at the top of the sequence space. The checked
    /// boundary for allocation paths (S-P0-09): exhaustion must become a
    /// typed error with no state mutated, never a wrap or a panic.
    pub fn checked_next(&self) -> Option<Self> {
        self.number.checked_add(1).map(|number| Self { number })
    }

    pub fn previous(&self) -> Self {
        Self {
            number: self
                .number
                .checked_sub(1)
                .expect("DurabilitySequenceNumber underflow: no sequence number precedes MIN"),
        }
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn serialise_be_into(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), std::mem::size_of::<u64>());
        let number_bytes = self.number.to_be_bytes();
        bytes.copy_from_slice(&number_bytes)
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut u64_bytes = [0; 8];
        u64_bytes.copy_from_slice(bytes);
        Self::from(u64::from_be_bytes(u64_bytes))
    }

    pub fn to_be_bytes(&self) -> [u8; std::mem::size_of::<u64>()] {
        self.number.to_be_bytes()
    }

    pub fn invert(&self) -> Self {
        Self { number: u64::MAX - self.number }
    }

    pub const fn serialised_len() -> usize {
        std::mem::size_of::<u64>()
    }

    pub fn saturating_sub(&self, context_size: u64) -> Self {
        Self { number: self.number.saturating_sub(context_size).max(1) }
    }
}

impl From<u64> for DurabilitySequenceNumber {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

// Positional arithmetic is CHECKED in every build profile (S-P0-09): the
// previous unchecked operators panicked in debug but wrapped in release,
// which is exactly the split the audit forbids — a release binary walking
// off either end of the sequence space would silently alias an existing
// (or nonexistent) sequence number instead of failing.
impl Add<usize> for DurabilitySequenceNumber {
    type Output = DurabilitySequenceNumber;

    fn add(self, rhs: usize) -> Self::Output {
        DurabilitySequenceNumber::from(
            self.number
                .checked_add(rhs as u64)
                .expect("DurabilitySequenceNumber overflow: the u64 sequence space is exhausted"),
        )
    }
}

impl Sub<usize> for DurabilitySequenceNumber {
    type Output = DurabilitySequenceNumber;

    fn sub(self, rhs: usize) -> Self::Output {
        DurabilitySequenceNumber::from(
            self.number
                .checked_sub(rhs as u64)
                .expect("DurabilitySequenceNumber underflow: subtrahend exceeds the sequence number"),
        )
    }
}

impl AddAssign<usize> for DurabilitySequenceNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs
    }
}

impl Sub<DurabilitySequenceNumber> for DurabilitySequenceNumber {
    type Output = usize;

    fn sub(self, rhs: DurabilitySequenceNumber) -> Self::Output {
        self.number
            .checked_sub(rhs.number)
            .expect("DurabilitySequenceNumber underflow: subtracting a later sequence number from an earlier one")
            as usize
    }
}

#[derive(Debug, Clone)]
pub enum DurabilityServiceError {
    // #[non_exhaustive]
    // BincodeSerialize { source: bincode::Error },
    #[non_exhaustive]
    IO {
        source: Arc<io::Error>,
    },
    WAL {
        source: WALError,
    },
    DeleteFailed {
        source: Arc<io::Error>,
    },
}

impl fmt::Display for DurabilityServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        error::todo_display_for_error!(f, self)
    }
}

// impl From<bincode::Error> for DurabilityError {
//     fn from(source: bincode::Error) -> Self {
//         Self::BincodeSerialize { source }
//     }
// }

impl From<WALError> for DurabilityServiceError {
    fn from(source: WALError) -> Self {
        Self::WAL { source }
    }
}

impl From<io::Error> for DurabilityServiceError {
    fn from(source: io::Error) -> Self {
        Self::IO { source: Arc::new(source) }
    }
}

impl Error for DurabilityServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            // Self::BincodeSerialize { source, .. } => Some(source),
            Self::IO { source, .. } => Some(source),
            Self::WAL { source, .. } => Some(source),
            Self::DeleteFailed { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod sequence_boundary_tests {
    //! S-P0-09: the u64 boundaries of the sequence space. Positive cases
    //! prove the checked arithmetic is exact up to the boundary; negative
    //! cases prove crossing it is a hard fault (never a release-mode wrap)
    //! and that the checked allocation form reports exhaustion as `None`
    //! without producing a value.

    use super::DurabilitySequenceNumber;

    #[test]
    fn next_is_exact_up_to_the_last_representable_sequence_number() {
        let penultimate = DurabilitySequenceNumber::new(u64::MAX - 1);
        assert_eq!(penultimate.next(), DurabilitySequenceNumber::MAX);
        assert_eq!(penultimate.checked_next(), Some(DurabilitySequenceNumber::MAX));
    }

    #[test]
    fn checked_next_reports_exhaustion_at_max_instead_of_wrapping() {
        assert_eq!(DurabilitySequenceNumber::MAX.checked_next(), None);
    }

    #[test]
    #[should_panic(expected = "sequence space is exhausted")]
    fn next_at_max_is_a_hard_fault_not_a_wrap() {
        let _ = DurabilitySequenceNumber::MAX.next();
    }

    #[test]
    #[should_panic(expected = "sequence space is exhausted")]
    fn add_across_max_is_a_hard_fault_not_a_wrap() {
        let _ = DurabilitySequenceNumber::new(u64::MAX - 1) + 2usize;
    }

    #[test]
    #[should_panic(expected = "no sequence number precedes MIN")]
    fn previous_at_min_is_a_hard_fault_not_a_wrap() {
        let _ = DurabilitySequenceNumber::MIN.previous();
    }

    #[test]
    #[should_panic(expected = "underflow")]
    fn subtracting_a_later_sequence_number_is_a_hard_fault_not_a_wrap() {
        let _ = DurabilitySequenceNumber::new(1) - DurabilitySequenceNumber::new(2);
    }

    #[test]
    fn add_assign_and_sub_are_exact_at_the_boundary() {
        let mut sequence_number = DurabilitySequenceNumber::new(u64::MAX - 3);
        sequence_number += 3usize;
        assert_eq!(sequence_number, DurabilitySequenceNumber::MAX);
        assert_eq!(DurabilitySequenceNumber::MAX - 1usize, DurabilitySequenceNumber::new(u64::MAX - 1));
        assert_eq!(DurabilitySequenceNumber::MAX - DurabilitySequenceNumber::new(u64::MAX), 0usize);
    }
}
