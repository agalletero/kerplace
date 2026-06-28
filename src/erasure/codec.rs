//! Reed-Solomon block codec with bitrot checksums.
//!
//! A *block* of object bytes is split into `K` equal data shards (the last
//! zero-padded) and `M` parity shards, all of the same length. Any `K` of the
//! `N = K + M` shards reconstruct the block. Each shard carries a BLAKE3
//! checksum so corruption (bitrot) is detected and the bad shard treated as
//! lost during reconstruction.
//!
//! This module is backend-agnostic: it only turns bytes ⇄ shards. The storage
//! layer (later phase) maps shards to drives, persists `xl.meta`, and streams.

use reed_solomon_erasure::galois_8::ReedSolomon;

/// Errors from erasure encoding/decoding.
#[derive(Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Invalid `(data, parity)` configuration (zero, or `> 256` total).
    BadConfig,
    /// Fewer than `K` intact shards survive — the block cannot be reconstructed.
    TooManyMissing,
    /// A shard had the wrong length for the block.
    BadShardLen,
    /// The underlying Reed-Solomon library reported an error.
    Rs,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::BadConfig => write!(f, "invalid erasure (data, parity) configuration"),
            CodecError::TooManyMissing => write!(f, "too many missing/corrupt shards to reconstruct"),
            CodecError::BadShardLen => write!(f, "shard has the wrong length"),
            CodecError::Rs => write!(f, "reed-solomon error"),
        }
    }
}

/// A Reed-Solomon block codec for a fixed `(data, parity)` shape.
pub struct Codec {
    data: usize,
    parity: usize,
    rs: ReedSolomon,
}

impl Codec {
    /// Create a codec with `data` data shards and `parity` parity shards.
    ///
    /// # Parameters
    /// - `data`: number of data shards `K` (≥ 1).
    /// - `parity`: number of parity shards `M` (≥ 1); `K + M ≤ 256`.
    ///
    /// # Returns
    /// A [`Codec`], or [`CodecError::BadConfig`] for an invalid shape.
    pub fn new(data: usize, parity: usize) -> Result<Self, CodecError> {
        if data == 0 || parity == 0 || data + parity > 256 {
            return Err(CodecError::BadConfig);
        }
        let rs = ReedSolomon::new(data, parity).map_err(|_| CodecError::BadConfig)?;
        Ok(Codec { data, parity, rs })
    }

    /// Number of data shards `K`.
    pub fn data(&self) -> usize {
        self.data
    }

    /// Number of parity shards `M`.
    pub fn parity(&self) -> usize {
        self.parity
    }

    /// Total shards `N = K + M`.
    pub fn total(&self) -> usize {
        self.data + self.parity
    }

    /// Per-shard length for a block of `block_len` bytes
    /// (`ceil(block_len / K)`, minimum 1 so empty blocks still produce shards).
    pub fn shard_len(&self, block_len: usize) -> usize {
        block_len.div_ceil(self.data).max(1)
    }

    /// Encode one block into `N` shards (`K` data, then `M` parity), each of
    /// length [`Codec::shard_len`]. The final data shard is zero-padded.
    ///
    /// # Parameters
    /// - `block`: the block bytes (may be shorter than `K * shard_len`).
    ///
    /// # Returns
    /// `N` shards on success, or [`CodecError::Rs`].
    pub fn encode_block(&self, block: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
        let slen = self.shard_len(block.len());
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.total());
        // Data shards: split the (zero-padded) block into K equal pieces.
        for i in 0..self.data {
            let mut shard = vec![0u8; slen];
            let start = i * slen;
            if start < block.len() {
                let end = (start + slen).min(block.len());
                shard[..end - start].copy_from_slice(&block[start..end]);
            }
            shards.push(shard);
        }
        // Parity shards start empty; the library fills them.
        for _ in 0..self.parity {
            shards.push(vec![0u8; slen]);
        }
        self.rs.encode(&mut shards).map_err(|_| CodecError::Rs)?;
        Ok(shards)
    }

    /// Reconstruct a block from its shards, recovering any missing ones.
    ///
    /// # Parameters
    /// - `shards`: `N` slots; `Some(bytes)` for an available shard, `None` for a
    ///   missing one. All present shards must share one length.
    /// - `block_len`: the original block length (to trim zero padding).
    ///
    /// # Returns
    /// The reconstructed block bytes, or [`CodecError::TooManyMissing`] when
    /// fewer than `K` intact shards remain.
    pub fn reconstruct_block(
        &self,
        shards: &mut [Option<Vec<u8>>],
        block_len: usize,
    ) -> Result<Vec<u8>, CodecError> {
        if shards.len() != self.total() {
            return Err(CodecError::BadShardLen);
        }
        let present = shards.iter().filter(|s| s.is_some()).count();
        if present < self.data {
            return Err(CodecError::TooManyMissing);
        }
        self.rs
            .reconstruct(shards)
            .map_err(|_| CodecError::TooManyMissing)?;

        let slen = self.shard_len(block_len);
        let mut out = Vec::with_capacity(self.data * slen);
        for shard in shards.iter().take(self.data) {
            let s = shard.as_ref().ok_or(CodecError::Rs)?;
            if s.len() != slen {
                return Err(CodecError::BadShardLen);
            }
            out.extend_from_slice(s);
        }
        out.truncate(block_len);
        Ok(out)
    }
}

/// BLAKE3 checksum of a shard, as lowercase hex (bitrot detection).
///
/// # Parameters
/// - `shard`: the shard bytes.
///
/// # Returns
/// The 64-character hex digest.
pub fn checksum(shard: &[u8]) -> String {
    blake3::hash(shard).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode then reconstruct from all shards round-trips for many sizes.
    #[test]
    fn roundtrip_all_present() {
        let codec = Codec::new(4, 2).unwrap();
        for len in [0usize, 1, 7, 100, 1024, 4096, 4097] {
            let block: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let shards = codec.encode_block(&block).unwrap();
            assert_eq!(shards.len(), 6);
            let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
            let back = codec.reconstruct_block(&mut opt, len).unwrap();
            assert_eq!(back, block, "len {len}");
        }
    }

    /// Losing exactly `M` shards (any positions) still reconstructs.
    #[test]
    fn survives_parity_many_losses() {
        let codec = Codec::new(4, 2).unwrap(); // tolerates 2 losses
        let block: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
        let shards = codec.encode_block(&block).unwrap();

        // Drop two arbitrary shards (one data, one parity).
        let mut opt: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        opt[1] = None;
        opt[5] = None;
        let back = codec.reconstruct_block(&mut opt, block.len()).unwrap();
        assert_eq!(back, block);

        // Drop two data shards.
        let mut opt2: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        opt2[0] = None;
        opt2[3] = None;
        let back2 = codec.reconstruct_block(&mut opt2, block.len()).unwrap();
        assert_eq!(back2, block);
    }

    /// Losing `M + 1` shards is unrecoverable.
    #[test]
    fn fails_beyond_parity() {
        let codec = Codec::new(4, 2).unwrap();
        let block: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        let shards = codec.encode_block(&block).unwrap();
        let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        opt[0] = None;
        opt[1] = None;
        opt[2] = None; // 3 missing > parity 2
        assert_eq!(
            codec.reconstruct_block(&mut opt, block.len()),
            Err(CodecError::TooManyMissing)
        );
    }

    /// Bitrot: a corrupt shard is detected by its checksum, dropped, and the
    /// block reconstructed from the rest.
    #[test]
    fn checksum_detects_bitrot() {
        let codec = Codec::new(4, 2).unwrap();
        let block: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let shards = codec.encode_block(&block).unwrap();
        let sums: Vec<String> = shards.iter().map(|s| checksum(s)).collect();

        // Corrupt shard 2 in place.
        let mut corrupted = shards.clone();
        corrupted[2][0] ^= 0xFF;
        assert_ne!(checksum(&corrupted[2]), sums[2], "checksum must change");

        // Drop shards that fail verification, then reconstruct.
        let mut opt: Vec<Option<Vec<u8>>> = corrupted
            .into_iter()
            .enumerate()
            .map(|(i, s)| if checksum(&s) == sums[i] { Some(s) } else { None })
            .collect();
        let back = codec.reconstruct_block(&mut opt, block.len()).unwrap();
        assert_eq!(back, block);
    }

    /// Invalid configurations are rejected.
    #[test]
    fn bad_config_rejected() {
        assert_eq!(Codec::new(0, 2).err(), Some(CodecError::BadConfig));
        assert_eq!(Codec::new(4, 0).err(), Some(CodecError::BadConfig));
        assert_eq!(Codec::new(200, 100).err(), Some(CodecError::BadConfig));
    }
}
