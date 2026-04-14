// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// HashMix — Prepares block data for the ShadowHash algorithm by combining
// header fields into a deterministic byte representation.
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;

pub struct HashMix;

impl HashMix {
    /// Create a deterministic mix string from block header fields
    pub fn mix(block: &Block) -> String {
        format!(
            "v{}:h{}:t{}:n{}:d{}:mr{}:ps{}",
            block.header.version,
            block.header.height,
            block.header.timestamp,
            block.header.nonce,
            block.header.difficulty,
            block.header.merkle_root,
            block.header.parents.len(),
        )
    }

    /// Create mix bytes (more efficient for hashing)
    pub fn mix_bytes(block: &Block) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&block.header.version.to_le_bytes());
        buf.extend_from_slice(&block.header.height.to_le_bytes());
        buf.extend_from_slice(&block.header.timestamp.to_le_bytes());
        buf.extend_from_slice(&block.header.nonce.to_le_bytes());
        buf.extend_from_slice(&block.header.difficulty.to_le_bytes());
        buf.extend_from_slice(block.header.merkle_root.as_bytes());
        for parent in &block.header.parents {
            buf.extend_from_slice(parent.as_bytes());
        }
        buf
    }

    /// Mix raw header values (used during mining when we don't have a Block)
    pub fn mix_raw(
        version: u32,
        height: u64,
        timestamp: u64,
        nonce: u64,
        difficulty: u64,
        merkle_root: &str,
    ) -> String {
        format!(
            "v{}:h{}:t{}:n{}:d{}:mr{}",
            version, height, timestamp, nonce, difficulty, merkle_root,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;

    fn make_block() -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                hash: String::new(),
                parents: vec!["parent1".to_string()],
                merkle_root: "merkle123".to_string(),
                timestamp: 1735689600,
                nonce: 42,
                difficulty: 4,
                height: 1,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
            },
            body: BlockBody {
                transactions: vec![],
            },
        }
    }

    #[test]
    fn mix_is_deterministic() {
        let block = make_block();
        assert_eq!(HashMix::mix(&block), HashMix::mix(&block));
    }

    #[test]
    fn mix_bytes_not_empty() {
        let block = make_block();
        assert!(!HashMix::mix_bytes(&block).is_empty());
    }

    #[test]
    fn mix_raw_matches_format() {
        let s = HashMix::mix_raw(1, 0, 100, 42, 4, "mr");
        assert!(s.contains("v1:"));
        assert!(s.contains("n42:"));
    }
}
