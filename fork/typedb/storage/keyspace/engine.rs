/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! TypeDB-owned key-value engine configuration boundary.
//!
//! All raw RocksDB tuning lives here, keyed by an engine-agnostic
//! [`KeyspaceTuningProfile`] that [`super::KeyspaceSet`] implementors select.
//! No crate outside `storage` names a RocksDB type to configure a keyspace;
//! the option-building code below is moved verbatim from the previous
//! `EncodingKeyspace::rocks_configuration` / `KeyspaceSet::rocks_configuration`
//! implementations, so engine behavior is unchanged.

use std::ffi::c_int;

use resource::constants::common::MB;
use rocksdb::{BlockBasedIndexType, BlockBasedOptions, DBCompressionType, Options, SliceTransform};

use crate::keyspace::rocks_resources::RocksResources;

/// Engine-agnostic tuning selection for a keyspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyspaceTuningProfile {
    /// Plain engine defaults; previously the `KeyspaceSet::rocks_configuration`
    /// trait default (used by test keyspace sets).
    Default,
    /// The production block/bloom/LSM tuning previously implemented by
    /// `EncodingKeyspace::rocks_configuration`. Uses the keyspace's prefix
    /// length (when present) for prefix extraction.
    ReadOptimisedBlocks,
}

pub(crate) fn build_rocks_options(
    profile: KeyspaceTuningProfile,
    prefix_length: Option<usize>,
    resources: &RocksResources,
) -> Options {
    match profile {
        KeyspaceTuningProfile::Default => {
            let mut options = Options::default();
            options.create_if_missing(true);
            options
        }
        KeyspaceTuningProfile::ReadOptimisedBlocks => read_optimised_blocks_options(prefix_length, resources),
    }
}

fn read_optimised_blocks_options(prefix_length: Option<usize>, resources: &RocksResources) -> Options {
    let mut options = Options::default();

    // Enable if we wanted to check bloom filter usage, cache hits, etc.
    // options.enable_statistics();
    // options.set_stats_dump_period_sec(100);

    options.create_if_missing(true);
    options.create_missing_column_families(true);
    if let Ok(parallelism) = std::thread::available_parallelism() {
        options.set_max_background_jobs(parallelism.get() as c_int);
    };
    options.set_target_file_size_base(64 * MB);
    options.set_write_buffer_size(64 * MB as usize);
    options.set_max_write_buffer_size_to_maintain(0);
    options.set_max_write_buffer_number(2);
    options.set_write_buffer_manager(&resources.write_buffer_manager());
    options.set_memtable_whole_key_filtering(false);
    options.set_optimize_filters_for_hits(false); // true => don't build bloom filters for the last level
    options.set_compression_per_level(&[
        DBCompressionType::None,
        DBCompressionType::None,
        DBCompressionType::Lz4,
        DBCompressionType::Lz4,
        DBCompressionType::Lz4,
        DBCompressionType::Lz4,
        DBCompressionType::Lz4,
    ]);

    // TODO: 2.x has   enable_index_compression: 1 set to 0

    let mut block_options = BlockBasedOptions::default();
    block_options.set_block_cache(&resources.cache());
    block_options.set_block_restart_interval(16);
    block_options.set_index_block_restart_interval(16);
    block_options.set_format_version(6);
    block_options.set_block_size(16 * 1024);
    block_options.set_whole_key_filtering(false);

    block_options.set_bloom_filter(10.0, false);
    block_options.set_partition_filters(true);
    block_options.set_index_type(BlockBasedIndexType::TwoLevelIndexSearch);
    block_options.set_optimize_filters_for_memory(true);
    block_options.set_pin_top_level_index_and_filter(true);
    block_options.set_pin_l0_filter_and_index_blocks_in_cache(true);
    block_options.set_cache_index_and_filter_blocks(true);

    if let Some(prefix_len) = prefix_length {
        options.set_prefix_extractor(SliceTransform::create_fixed_prefix(prefix_len))
    }
    options.set_block_based_table_factory(&block_options);
    options
}
