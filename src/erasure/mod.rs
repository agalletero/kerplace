//! Erasure-coded storage backend (feature #4) — see
//! `docs/ERASURE_CODING_DESIGN.md`.
//!
//! Phase 1 lands the core Reed-Solomon [`codec`]: split a block into `K` data +
//! `M` parity shards, reconstruct it from any `K` survivors, and detect bitrot
//! via per-shard checksums. Later phases build the `ObjectStore` backend on top.

// The codec is built before its consumer (the ErasureStore backend, next
// phase), so some items are not referenced yet outside their own tests.
#![allow(dead_code)]

pub mod codec;
pub mod drive;
pub mod store;
