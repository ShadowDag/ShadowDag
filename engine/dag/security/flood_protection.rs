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
/// Canonical future-drift bound in MILLISECONDS (120 s of real time).
/// Timestamps are unix epoch ms. Shares ConsensusParams::MAX_FUTURE_MS.
pub const MAX_FUTURE_MS: u64 =
    crate::config::consensus::consensus_params::ConsensusParams::MAX_FUTURE_MS;

pub struct FloodProtection;

impl FloodProtection {
    pub fn validate(block: &Block) -> bool {
        // Timestamp sanity — reject ONLY blocks dated too far in the FUTURE (a
        // block cannot come from ahead of the wall clock). We deliberately do
        // NOT reject blocks with OLD timestamps: during sync/IBD a node
        // legitimately receives HISTORICAL blocks that are minutes/hours/days
        // old. A wall-clock "too far in the past" reject here made catch-up
        // IMPOSSIBLE — any node more than a few minutes behind rejected every
        // backlog block at the P2P layer (and, being a consensus-layer reject,
        // banned the peer serving the backlog), so the chain never converged.
        // Past-timestamp causality (ts > parents, MTP, jump limits) is enforced
        // against the block's ANCESTRY in block_validator::validate_timestamp(),
        // which is the correct place — not against the wall clock.
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(t) => t.as_millis() as u64,
            Err(_) => return false,
        };

        let ts = block.header.timestamp;

        // Block cannot be too far in the future (ms vs ms).
        if ts > now.saturating_add(MAX_FUTURE_MS) {
            return false;
        }

        true
    }
}

#[cfg(test)]
fn fast_hex_to_u64(hex: &str) -> Option<u64> {
    if hex.is_empty() {
        return None;
    }
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
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
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
                mix_hash: String::new(),
            },
            body: BlockBody {
                transactions: vec![],
            },
        }
    }

    #[test]
    fn valid_block_passes() {
        let b = make_block_ts(42, now_ms(), vec!["aabbccdd"]);
        assert!(FloodProtection::validate(&b));
    }

    #[test]
    fn nonce_zero_valid() {
        // Nonce 0 is valid — miner divides full u64 range among threads
        let b = make_block_ts(0, now_ms(), vec!["aabbccdd"]);
        assert!(FloodProtection::validate(&b));
    }

    #[test]
    fn large_nonce_valid() {
        // Large nonces are valid — threads start at u64::MAX / n
        let b = make_block_ts(u64::MAX - 1, now_ms(), vec!["aabbccdd"]);
        assert!(FloodProtection::validate(&b));
    }

    #[test]
    fn timestamp_far_future_rejected() {
        let ts = now_ms() + MAX_FUTURE_MS + 100;
        let b = make_block_ts(42, ts, vec!["aabbccdd"]);
        assert!(!FloodProtection::validate(&b));
    }

    #[test]
    fn timestamp_far_past_allowed_for_sync() {
        // Historical blocks (hours/days old) MUST pass this pre-filter so a
        // lagging node can sync the backlog. Rejecting them here made catch-up
        // impossible. Causality vs. parents is checked in block_validator.
        let ts = now_ms().saturating_sub(7 * 24 * 3600 * 1000); // a week old (ms)
        let b = make_block_ts(42, ts, vec!["aabbccdd"]);
        assert!(
            FloodProtection::validate(&b),
            "old historical blocks must pass the P2P flood pre-filter (sync)"
        );
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
