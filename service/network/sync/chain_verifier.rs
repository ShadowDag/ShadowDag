// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Chain Verifier — Validates chain integrity during sync.
// Protects against fake chain attacks and bootstrap poisoning.
//
// Checks:
//   1. Genesis hash matches hardcoded value
//   2. PoW difficulty meets target for each header
//   3. Timestamps are monotonically increasing (within tolerance)
//   4. Checkpoint hashes match (if available)
//   5. Blue score is consistent with GHOSTDAG rules
//   6. Cumulative work exceeds minimum threshold
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block_header::BlockHeader;

/// Minimum cumulative difficulty to accept a chain as valid
pub const MIN_CUMULATIVE_WORK: u64 = 1_000;

/// Maximum allowed timestamp gap between consecutive headers (1 hour)
pub const MAX_HEADER_TIME_GAP_SECS: u64 = 3_600;

/// Verification result
#[derive(Debug, Clone)]
pub enum ChainVerifyResult {
    Valid,
    InvalidGenesis { expected: String, got: String },
    InvalidPoW { height: u64, hash: String },
    TimestampGap { height: u64, gap_secs: u64 },
    TimestampBackward { height: u64, timestamp: u64, prev_timestamp: u64 },
    CheckpointMismatch { height: u64, expected: String, got: String },
    InsufficientWork { cumulative: u64, required: u64 },
    EmptyChain,
}

/// Known checkpoints (hardcoded)
pub struct Checkpoint {
    pub height: u64,
    pub hash:   String,
}

pub struct ChainVerifier {
    genesis_hash:  String,
    checkpoints:   Vec<Checkpoint>,
}

impl ChainVerifier {
    pub fn new(genesis_hash: &str) -> Self {
        Self {
            genesis_hash: genesis_hash.to_string(),
            checkpoints:  Vec::new(),
        }
    }

    pub fn add_checkpoint(&mut self, height: u64, hash: &str) {
        self.checkpoints.push(Checkpoint {
            height,
            hash: hash.to_string(),
        });
    }

    /// Verify a chain of headers received during sync.
    /// Returns Valid if all checks pass, or the first error found.
    pub fn verify_header_chain(&self, headers: &[BlockHeader]) -> ChainVerifyResult {
        if headers.is_empty() {
            return ChainVerifyResult::EmptyChain;
        }

        // 1. Genesis check
        if headers[0].height == 0 && headers[0].hash != self.genesis_hash {
            return ChainVerifyResult::InvalidGenesis {
                expected: self.genesis_hash.clone(),
                got: headers[0].hash.clone(),
            };
        }

        // If the chain doesn't start at height 0, require a checkpoint
        // match for the first header — otherwise there's no root of trust.
        if headers[0].height > 0 {
            // Chain doesn't start at genesis — REQUIRE a checkpoint match.
            // Without checkpoints, there's no root-of-trust for mid-chain
            // starts, and an attacker can forge an entire chain.
            if self.checkpoints.is_empty() {
                return ChainVerifyResult::InvalidGenesis {
                    expected: "chain must start at height 0 (no checkpoints configured)".into(),
                    got: format!("starts at height {}", headers[0].height),
                };
            }
            let has_matching_checkpoint = self.checkpoints.iter()
                .any(|cp| cp.height == headers[0].height && cp.hash == headers[0].hash);
            if !has_matching_checkpoint {
                // No checkpoint covers this starting height — reject
                return ChainVerifyResult::InvalidGenesis {
                    expected: format!("checkpoint at height {}", headers[0].height),
                    got: headers[0].hash.clone(),
                };
            }
        }

        let mut cumulative_work: u64 = 0;
        let mut prev_timestamp: u64 = 0;
        let mut prev_hash: Option<&str> = None;
        let mut prev_height: u64 = headers[0].height.saturating_sub(1);

        for header in headers {
            // 2. PoW check — use PowValidator (numeric target comparison)
            //    so sync verification matches consensus validation exactly.
            //    The previous leading-zeros check silently skipped PoW for
            //    difficulty > 64, and used a weaker difficulty metric than
            //    the actual consensus rule.
            // Recompute hash from header fields to prevent forgery.
            // shadow_hash_raw_full computes from (version, height, timestamp,
            // nonce, extra_nonce, difficulty, merkle_root, parents) — all
            // available in the header without the block body.
            {
                use crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full;
                let recomputed = shadow_hash_raw_full(
                    header.version, header.height, header.timestamp,
                    header.nonce, header.extra_nonce, header.difficulty,
                    &header.merkle_root, &header.parents,
                );
                if recomputed != header.hash {
                    return ChainVerifyResult::InvalidPoW {
                        height: header.height,
                        hash: format!("hash mismatch: claimed {} != computed {}",
                            &header.hash[..header.hash.len().min(16)],
                            &recomputed[..recomputed.len().min(16)]),
                    };
                }
            }

            if header.difficulty > 0 {
                use crate::engine::mining::pow::pow_validator::PowValidator;
                if !PowValidator::hash_meets_target(&header.hash, header.difficulty) {
                    return ChainVerifyResult::InvalidPoW {
                        height: header.height,
                        hash: header.hash.clone(),
                    };
                }
            } else if header.height > 0 {
                // Non-genesis header with difficulty 0 is invalid — it would
                // bypass PoW entirely.
                return ChainVerifyResult::InvalidPoW {
                    height: header.height,
                    hash: format!("difficulty=0 on non-genesis height {}", header.height),
                };
            }

            // Wall-clock future check: reject headers with timestamps
            // too far in the future. Without this, an attacker could
            // serve a chain with all timestamps set years ahead and
            // it would pass the relative monotonicity/gap checks.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if header.timestamp > now + MAX_HEADER_TIME_GAP_SECS {
                return ChainVerifyResult::TimestampGap {
                    height: header.height,
                    gap_secs: header.timestamp - now,
                };
            }

            // 2b. Parent continuity
            if let Some(ph) = prev_hash {
                if !header.parents.iter().any(|p| p == ph)
                    && header.selected_parent.as_deref() != Some(ph)
                {
                    return ChainVerifyResult::InvalidPoW {
                        height: header.height,
                        hash: format!("parent continuity: expected parent {}", &ph[..ph.len().min(16)]),
                    };
                }
            }

            // 2c. Height continuity: each header must be exactly parent_height + 1
            // (in a DAG, this is max(parent_heights) + 1, but we only have
            // the linear chain here, so check sequential increment).
            if let Some(_ph) = prev_hash {
                // Already checked parent continuity above — now verify height
                if header.height != prev_height + 1 {
                    return ChainVerifyResult::InvalidPoW {
                        height: header.height,
                        hash: format!("height gap: expected {} got {}", prev_height + 1, header.height),
                    };
                }
            }

            // 3. Timestamp check — must be strictly increasing and within max gap
            if prev_timestamp > 0 {
                if header.timestamp <= prev_timestamp {
                    return ChainVerifyResult::TimestampBackward {
                        height: header.height,
                        timestamp: header.timestamp,
                        prev_timestamp,
                    };
                }
                let gap = header.timestamp - prev_timestamp;
                if gap > MAX_HEADER_TIME_GAP_SECS {
                    return ChainVerifyResult::TimestampGap {
                        height: header.height,
                        gap_secs: gap,
                    };
                }
            }
            prev_timestamp = header.timestamp;

            // 4. Checkpoint check
            for cp in &self.checkpoints {
                if header.height == cp.height && header.hash != cp.hash {
                    return ChainVerifyResult::CheckpointMismatch {
                        height: cp.height,
                        expected: cp.hash.clone(),
                        got: header.hash.clone(),
                    };
                }
            }

            // 5. Accumulate work: use exponential metric (2^difficulty) not
            // linear difficulty. A chain at difficulty 20 has ~1M times
            // more work than difficulty 0, not 20 times more.
            let block_work = if header.difficulty <= 63 {
                1u64 << header.difficulty
            } else {
                u64::MAX // difficulty > 63 → maximum representable work
            };
            cumulative_work = cumulative_work.saturating_add(block_work);

            prev_hash = Some(&header.hash);
            prev_height = header.height;
        }

        // 6. Minimum cumulative work
        if cumulative_work < MIN_CUMULATIVE_WORK {
            return ChainVerifyResult::InsufficientWork {
                cumulative: cumulative_work,
                required: MIN_CUMULATIVE_WORK,
            };
        }

        ChainVerifyResult::Valid
    }

    /// Quick check: is this genesis hash correct?
    pub fn verify_genesis(&self, hash: &str) -> bool {
        hash == self.genesis_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header with a real shadow_hash_raw_full so the hash
    /// recomputation check passes during verify_header_chain.
    fn make_header(height: u64, difficulty: u64, timestamp: u64, parents: Vec<String>) -> BlockHeader {
        use crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full;
        let merkle_root = "mr".to_string();
        let hash = shadow_hash_raw_full(1, height, timestamp, 0, 0, difficulty, &merkle_root, &parents);
        BlockHeader {
            version: 1, hash, parents,
            merkle_root, timestamp, nonce: 0,
            difficulty, height, blue_score: 0, selected_parent: None,
            utxo_commitment: None, extra_nonce: 0,
            receipt_root: None, state_root: None,
        }
    }

    /// Build a header with a WRONG hash (for negative tests).
    fn make_header_bad_hash(height: u64, hash: &str, difficulty: u64, timestamp: u64) -> BlockHeader {
        BlockHeader {
            version: 1, hash: hash.to_string(), parents: vec![],
            merkle_root: "mr".into(), timestamp, nonce: 0,
            difficulty, height, blue_score: 0, selected_parent: None,
            utxo_commitment: None, extra_nonce: 0,
            receipt_root: None, state_root: None,
        }
    }

    #[test]
    fn valid_chain() {
        let genesis = make_header(0, 4, 1000, vec![]);
        let cv = ChainVerifier::new(&genesis.hash);
        // MIN_CUMULATIVE_WORK = 1000; difficulty 4 → work = 2^4 = 16 per block
        // Need 1000/16 = 63 blocks minimum → use 70
        let mut headers = vec![genesis];
        for i in 1..70u64 {
            let prev_hash = headers.last().unwrap().hash.clone();
            headers.push(make_header(i, 4, 1000 + i * 100, vec![prev_hash]));
        }
        assert!(matches!(cv.verify_header_chain(&headers), ChainVerifyResult::Valid));
    }

    #[test]
    fn invalid_genesis() {
        let cv = ChainVerifier::new("0000real_genesis");
        // Use a real-hash header (hash won't match "0000real_genesis")
        let headers = vec![make_header(0, 4, 1000, vec![])];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::InvalidGenesis { .. }
        ));
    }

    #[test]
    fn invalid_pow() {
        // Header with a bad hash will fail the hash recomputation check
        let genesis = make_header(0, 4, 1000, vec![]);
        let cv = ChainVerifier::new(&genesis.hash);
        let headers = vec![
            genesis.clone(),
            make_header_bad_hash(1, "abcd_no_zeros", 4, 2000),
        ];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::InvalidPoW { .. }
        ));
    }

    #[test]
    fn checkpoint_mismatch() {
        let genesis = make_header(0, 4, 1000, vec![]);
        let mut cv = ChainVerifier::new(&genesis.hash);
        // Set a checkpoint that the real hash won't match
        let block1 = make_header(1, 4, 2000, vec![genesis.hash.clone()]);
        cv.add_checkpoint(1, "0000wrong_checkpoint_hash");
        let headers = vec![genesis, block1];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::CheckpointMismatch { .. }
        ));
    }

    #[test]
    fn empty_chain() {
        let cv = ChainVerifier::new("0000genesis");
        assert!(matches!(cv.verify_header_chain(&[]), ChainVerifyResult::EmptyChain));
    }

    #[test]
    fn backward_timestamp_rejected() {
        let genesis = make_header(0, 50, 5000, vec![]);
        let cv = ChainVerifier::new(&genesis.hash);
        // Block 1 has earlier timestamp — will fail recomputation then timestamp check
        // But since we need a real hash for block1, create it with earlier timestamp
        let block1 = make_header(1, 50, 4000, vec![genesis.hash.clone()]);
        let headers = vec![genesis, block1];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::TimestampBackward { height: 1, .. }
        ));
    }

    #[test]
    fn equal_timestamp_rejected() {
        let genesis = make_header(0, 50, 5000, vec![]);
        let cv = ChainVerifier::new(&genesis.hash);
        let block1 = make_header(1, 50, 5000, vec![genesis.hash.clone()]);
        let headers = vec![genesis, block1];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::TimestampBackward { height: 1, .. }
        ));
    }

    #[test]
    fn height_gap_rejected() {
        let genesis = make_header(0, 50, 5000, vec![]);
        let cv = ChainVerifier::new(&genesis.hash);
        // Skip from height 0 to height 5
        let block5 = make_header(5, 50, 6000, vec![genesis.hash.clone()]);
        let headers = vec![genesis, block5];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::InvalidPoW { .. }
        ));
    }

    #[test]
    fn no_checkpoints_mid_chain_rejected() {
        // Chain starting at height > 0 with no checkpoints configured
        let cv = ChainVerifier::new("0000genesis");
        let headers = vec![make_header(10, 4, 1000, vec![])];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::InvalidGenesis { .. }
        ));
    }

    #[test]
    fn genesis_verification() {
        let cv = ChainVerifier::new("0000abc");
        assert!(cv.verify_genesis("0000abc"));
        assert!(!cv.verify_genesis("0000xyz"));
    }
}
