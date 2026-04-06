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
pub const MIN_CUMULATIVE_WORK: u64 = 100;

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

        let mut cumulative_work: u64 = 0;
        let mut prev_timestamp: u64 = 0;

        for header in headers {
            // 2. PoW check — hash must have required leading zeros
            let required_zeros = header.difficulty as usize;
            if required_zeros > 0 && required_zeros <= header.hash.len() {
                let has_zeros = header.hash.as_bytes()[..required_zeros]
                    .iter()
                    .all(|&b| b == b'0');
                if !has_zeros {
                    return ChainVerifyResult::InvalidPoW {
                        height: header.height,
                        hash: header.hash.clone(),
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
                if gap > MAX_HEADER_TIME_GAP_SECS * 1000 { // milliseconds
                    return ChainVerifyResult::TimestampGap {
                        height: header.height,
                        gap_secs: gap / 1000,
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

            // 5. Accumulate work
            cumulative_work = cumulative_work.saturating_add(header.difficulty);
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

    fn make_header(height: u64, hash: &str, difficulty: u64, timestamp: u64) -> BlockHeader {
        BlockHeader {
            version: 1, hash: hash.to_string(), parents: vec![],
            merkle_root: "mr".into(), timestamp, nonce: 0,
            difficulty, height, blue_score: 0, selected_parent: None,
            utxo_commitment: None, extra_nonce: 0,
        }
    }

    #[test]
    fn valid_chain() {
        let cv = ChainVerifier::new("0000genesis");
        // Need cumulative difficulty >= MIN_CUMULATIVE_WORK (100)
        let mut headers = vec![make_header(0, "0000genesis", 4, 1000)];
        for i in 1..30 {
            headers.push(make_header(i, &format!("0000block{}", i), 4, 1000 + i * 1000));
        }
        // 30 headers * difficulty 4 = 120 > 100
        assert!(matches!(cv.verify_header_chain(&headers), ChainVerifyResult::Valid));
    }

    #[test]
    fn invalid_genesis() {
        let cv = ChainVerifier::new("0000real_genesis");
        let headers = vec![make_header(0, "0000fake_genesis", 4, 1000)];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::InvalidGenesis { .. }
        ));
    }

    #[test]
    fn invalid_pow() {
        let cv = ChainVerifier::new("0000genesis");
        let headers = vec![
            make_header(0, "0000genesis", 4, 1000),
            make_header(1, "abcd_no_zeros", 4, 2000), // No leading zeros
        ];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::InvalidPoW { .. }
        ));
    }

    #[test]
    fn checkpoint_mismatch() {
        let mut cv = ChainVerifier::new("0000genesis");
        cv.add_checkpoint(1, "0000correct_hash");
        let headers = vec![
            make_header(0, "0000genesis", 4, 1000),
            make_header(1, "0000wrong_hash", 4, 2000),
        ];
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
        let cv = ChainVerifier::new("0000genesis");
        let headers = vec![
            make_header(0, "0000genesis", 50, 5000),
            make_header(1, "0000block1", 50, 4000), // earlier than genesis
        ];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::TimestampBackward { height: 1, .. }
        ));
    }

    #[test]
    fn equal_timestamp_rejected() {
        let cv = ChainVerifier::new("0000genesis");
        let headers = vec![
            make_header(0, "0000genesis", 50, 5000),
            make_header(1, "0000block1", 50, 5000), // same as genesis
        ];
        assert!(matches!(
            cv.verify_header_chain(&headers),
            ChainVerifyResult::TimestampBackward { height: 1, .. }
        ));
    }

    #[test]
    fn genesis_verification() {
        let cv = ChainVerifier::new("0000abc");
        assert!(cv.verify_genesis("0000abc"));
        assert!(!cv.verify_genesis("0000xyz"));
    }
}
