// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::block::block::Block;

/// Nonce range: the miner divides u64 space among threads, so nonces
/// can be anywhere in 0..u64::MAX. No artificial range restriction.
pub const MAX_VALID_NONCE: u64 = u64::MAX;
pub const MIN_VALID_NONCE: u64 = 0;

// حدود الوقت
/// Canonical value: 120s (see block_validator::MAX_FUTURE_SECS).
pub const MAX_FUTURE_SECS: u64 = 120;
pub const MAX_PAST_SECS: u64 = 600;

pub struct FloodProtection;

impl FloodProtection {

    pub fn validate(block: &Block) -> bool {
        // 1️⃣ Timestamp — wall-clock sanity only.
        //    Full timestamp validation (MTP, causality, jump limits) is in
        //    block_validator::validate_timestamp(). This is just a fast
        //    pre-filter to reject obviously bogus timestamps at the P2P layer.
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(t) => t.as_secs(),
            Err(_) => return false,
        };

        let ts = block.header.timestamp;

        // Block cannot be too far in the future
        if ts > now.saturating_add(MAX_FUTURE_SECS) {
            return false;
        }

        // Block cannot be too far in the past (relative to system clock)
        // Generous: 1 hour. Tighter checks are in block_validator R2.
        if ts < now.saturating_sub(MAX_PAST_SECS) {
            return false;
        }

        true
    }
}

#[cfg(test)]
fn fast_hex_to_u64(hex: &str) -> Option<u64> {
    if hex.is_empty() { return None; }
    let mut result: u64 = 0;
    for byte in hex.bytes() {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        result = result.checked_mul(16)?.checked_add(digit as u64)?;
    }
    Some(result)
}

#[cfg(test)]
fn fallback_mix(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    fn make_block_ts(nonce: u64, timestamp: u64, parents: Vec<&str>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                hash: "test_hash".to_string(),
                parents: parents.into_iter().map(|s| s.to_string()).collect(),
                merkle_root: "mr".into(),
                timestamp,
                nonce,
                difficulty: 1,
                height: 1,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
            },
            body: BlockBody { transactions: vec![] },
        }
    }

    #[test]
    fn valid_block_passes() {
        let b = make_block_ts(42, now_secs(), vec!["aabbccdd"]);
        assert!(FloodProtection::validate(&b));
    }

    #[test]
    fn nonce_zero_valid() {
        // Nonce 0 is valid — miner divides full u64 range among threads
        let b = make_block_ts(0, now_secs(), vec!["aabbccdd"]);
        assert!(FloodProtection::validate(&b));
    }

    #[test]
    fn large_nonce_valid() {
        // Large nonces are valid — threads start at u64::MAX / n
        let b = make_block_ts(u64::MAX - 1, now_secs(), vec!["aabbccdd"]);
        assert!(FloodProtection::validate(&b));
    }

    #[test]
    fn timestamp_far_future_rejected() {
        let ts = now_secs() + MAX_FUTURE_SECS + 100;
        let b = make_block_ts(42, ts, vec!["aabbccdd"]);
        assert!(!FloodProtection::validate(&b));
    }

    #[test]
    fn timestamp_far_past_rejected() {
        let ts = now_secs().saturating_sub(MAX_PAST_SECS + 100);
        let b = make_block_ts(42, ts, vec!["aabbccdd"]);
        assert!(!FloodProtection::validate(&b));
    }

    #[test]
    fn fast_hex_to_u64_valid() {
        assert_eq!(fast_hex_to_u64("ff"), Some(0xff));
        assert_eq!(fast_hex_to_u64("0a"), Some(0x0a));
        assert_eq!(fast_hex_to_u64("ABCDEF"), Some(0xABCDEF));
    }

    #[test]
    fn fast_hex_to_u64_empty_returns_none() {
        assert_eq!(fast_hex_to_u64(""), None);
    }

    #[test]
    fn fast_hex_to_u64_invalid_returns_none() {
        assert_eq!(fast_hex_to_u64("xyz"), None);
    }

    #[test]
    fn fallback_mix_deterministic() {
        let a = fallback_mix(b"hello");
        let b = fallback_mix(b"hello");
        assert_eq!(a, b);
        let c = fallback_mix(b"world");
        assert_ne!(a, c);
    }
}