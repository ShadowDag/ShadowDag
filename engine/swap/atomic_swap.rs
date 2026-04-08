// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Atomic Swap — Hash Time-Locked Contract (HTLC) for trustless cross-chain
// trading. Enables direct SDAG ↔ BTC/ETH/KAS swaps without intermediaries.
//
// Protocol:
//   1. Alice generates secret S, computes H = SHA256(S)
//   2. Alice locks SDAG with HTLC(H, Bob, timeout=24h)
//   3. Bob sees H, locks BTC with HTLC(H, Alice, timeout=12h)
//   4. Alice claims BTC by revealing S
//   5. Bob uses S to claim SDAG
//
// If either party fails to act, funds return after timeout.
//
// Kaspa does NOT have native atomic swap support.
// ShadowDAG implements HTLC natively in the UTXO layer.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// HTLC lock duration constants (all values are in BLOCKS, not seconds).
pub const DEFAULT_INITIATOR_TIMEOUT: u64 = 86400;    // 24 hours worth of blocks
pub const DEFAULT_PARTICIPANT_TIMEOUT: u64 = 43200;   // 12 hours worth of blocks

/// Minimum timeout in BLOCKS (not seconds).
/// At 10 BPS, 36 000 blocks = 1 hour. Adjust if semantics should be time-based.
pub const MIN_TIMEOUT_BLOCKS: u64 = 36_000;

pub const SECRET_SIZE: usize = 32;                     // 256-bit secret

/// Atomic swap state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapState {
    /// HTLC created, waiting for counterparty
    Initiated,
    /// Counterparty has locked funds
    Participated,
    /// Secret revealed, swap completing
    Redeemed,
    /// Timeout expired, funds refunded
    Refunded,
    /// Swap completed successfully
    Completed,
}

/// Hash Time-Locked Contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTLC {
    /// SHA256 hash of the secret
    pub secret_hash:     String,
    /// Address that can claim with the secret
    pub recipient:       String,
    /// Address that can refund after timeout
    pub sender:          String,
    /// Amount locked in the HTLC
    pub amount:          u64,
    /// Block height at which the HTLC expires
    pub timeout_height:  u64,
    /// Current state
    pub state:           SwapState,
    /// The secret (only set after redeem)
    pub secret:          Option<String>,
    /// Chain identifier (for cross-chain tracking)
    pub chain:           String,
    /// Creation timestamp
    pub created_at:      u64,
}

/// Atomic swap engine
pub struct AtomicSwap;

impl AtomicSwap {
    /// Generate a cryptographically secure random secret
    pub fn generate_secret() -> [u8; SECRET_SIZE] {
        let mut secret = [0u8; SECRET_SIZE];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut secret);
        secret
    }

    /// Compute the hash of a secret (SHA256)
    pub fn hash_secret(secret: &[u8]) -> String {
        let hash = Sha256::digest(secret);
        hex::encode(hash)
    }

    /// Create an HTLC for initiating a swap
    pub fn initiate(
        secret_hash: &str,
        sender: &str,
        recipient: &str,
        amount: u64,
        current_height: u64,
        timeout_blocks: u64,
    ) -> HTLC {
        HTLC {
            secret_hash:    secret_hash.to_string(),
            recipient:      recipient.to_string(),
            sender:         sender.to_string(),
            amount,
            timeout_height: current_height + timeout_blocks.max(MIN_TIMEOUT_BLOCKS),
            state:          SwapState::Initiated,
            secret:         None,
            chain:          "SDAG".to_string(),
            created_at:     current_height,
        }
    }

    /// Redeem an HTLC by providing the secret.
    ///
    /// After timeout, the HTLC should only be refundable, not redeemable.
    pub fn redeem(htlc: &mut HTLC, secret: &[u8], current_height: u64) -> bool {
        // At or after timeout, only refund is allowed
        if current_height >= htlc.timeout_height {
            return false;
        }
        // Verify the secret matches the hash
        let computed_hash = Self::hash_secret(secret);
        if computed_hash != htlc.secret_hash {
            return false;
        }
        if htlc.state != SwapState::Initiated && htlc.state != SwapState::Participated {
            return false;
        }
        htlc.secret = Some(hex::encode(secret));
        htlc.state = SwapState::Redeemed;
        true
    }

    /// Refund an HTLC after timeout
    pub fn refund(htlc: &mut HTLC, current_height: u64) -> bool {
        if htlc.state == SwapState::Refunded {
            return false; // Already refunded
        }
        if current_height < htlc.timeout_height {
            return false; // Not expired yet
        }
        if htlc.state == SwapState::Redeemed || htlc.state == SwapState::Completed {
            return false; // Already claimed
        }
        htlc.state = SwapState::Refunded;
        true
    }

    /// Verify a secret against a hash
    pub fn verify_secret(secret: &[u8], expected_hash: &str) -> bool {
        Self::hash_secret(secret) == expected_hash
    }

    /// Check if an HTLC has expired
    pub fn is_expired(htlc: &HTLC, current_height: u64) -> bool {
        current_height >= htlc.timeout_height
    }

    /// Supported cross-chain swap pairs
    pub fn supported_chains() -> Vec<&'static str> {
        vec!["SDAG", "BTC", "ETH", "KAS", "LTC", "XMR"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_generation() {
        let s1 = AtomicSwap::generate_secret();
        let s2 = AtomicSwap::generate_secret();
        assert_ne!(s1, s2); // Should be random
        assert_eq!(s1.len(), SECRET_SIZE);
    }

    #[test]
    fn hash_and_verify() {
        let secret = AtomicSwap::generate_secret();
        let hash = AtomicSwap::hash_secret(&secret);
        assert_eq!(hash.len(), 64);
        assert!(AtomicSwap::verify_secret(&secret, &hash));
        assert!(!AtomicSwap::verify_secret(&[0u8; 32], &hash));
    }

    #[test]
    fn htlc_lifecycle() {
        let secret = AtomicSwap::generate_secret();
        let hash = AtomicSwap::hash_secret(&secret);

        let mut htlc = AtomicSwap::initiate(&hash, "SD1alice", "SD1bob", 1000, 100, 86400);
        assert_eq!(htlc.state, SwapState::Initiated);

        // Can't refund before timeout
        assert!(!AtomicSwap::refund(&mut htlc, 100));

        // Redeem with correct secret (before timeout)
        assert!(AtomicSwap::redeem(&mut htlc, &secret, 100));
        assert_eq!(htlc.state, SwapState::Redeemed);
        assert!(htlc.secret.is_some());
    }

    #[test]
    fn htlc_wrong_secret_fails() {
        let secret = AtomicSwap::generate_secret();
        let hash = AtomicSwap::hash_secret(&secret);
        let mut htlc = AtomicSwap::initiate(&hash, "SD1a", "SD1b", 500, 0, 86400);

        assert!(!AtomicSwap::redeem(&mut htlc, &[0u8; 32], 0));
        assert_eq!(htlc.state, SwapState::Initiated); // State unchanged
    }

    #[test]
    fn htlc_refund_after_timeout() {
        let hash = AtomicSwap::hash_secret(&[1u8; 32]);
        let mut htlc = AtomicSwap::initiate(&hash, "SD1a", "SD1b", 500, 100, 86400);

        assert!(!AtomicSwap::refund(&mut htlc, 50000)); // Not expired
        assert!(AtomicSwap::refund(&mut htlc, 200000));  // Expired
        assert_eq!(htlc.state, SwapState::Refunded);
    }

    #[test]
    fn cant_refund_after_redeem() {
        let secret = AtomicSwap::generate_secret();
        let hash = AtomicSwap::hash_secret(&secret);
        let mut htlc = AtomicSwap::initiate(&hash, "SD1a", "SD1b", 500, 0, 100);

        AtomicSwap::redeem(&mut htlc, &secret, 0);
        assert!(!AtomicSwap::refund(&mut htlc, 999999));
    }

    #[test]
    fn supported_chains_include_major() {
        let chains = AtomicSwap::supported_chains();
        assert!(chains.contains(&"BTC"));
        assert!(chains.contains(&"ETH"));
        assert!(chains.contains(&"SDAG"));
        assert!(chains.contains(&"KAS"));
    }
}
