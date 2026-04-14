// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Connection Puzzle — PoW-based anti-Sybil/anti-fake-node protection.
//
// Before a peer can connect, they must solve a small PoW puzzle.
// This makes it expensive to create thousands of fake connections.
//
// Puzzle: SHA-256(challenge || nonce) must have N leading zeros.
// Difficulty is moderate (N=3, ~4096 hashes) — trivial for real nodes,
// but expensive at scale for an attacker with 10,000 fake nodes.
// ═══════════════════════════════════════════════════════════════════════════

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Puzzle difficulty (leading hex zeros required).
/// 3 = ~4096 hashes average (~0.1ms on modern CPU) — trivial for
/// legitimate nodes but forces an attacker with 10,000 fake nodes to
/// compute ~41 million hashes = significant cost and latency.
///
/// Previous value was 2 (~256 hashes), which was too cheap for mainnet.
pub const PUZZLE_DIFFICULTY: usize = 3;

/// Puzzle expiry (5 minutes)
pub const PUZZLE_EXPIRY_SECS: u64 = 300;

/// A connection challenge
#[derive(Debug, Clone)]
pub struct ConnectionChallenge {
    pub challenge: String,
    pub created_at: u64,
}

/// A solution to a connection challenge
#[derive(Debug, Clone)]
pub struct ChallengeSolution {
    pub challenge: String,
    pub nonce: u64,
    pub hash: String,
}

pub struct ConnectionPuzzle;

impl ConnectionPuzzle {
    /// Generate a new challenge for an incoming connection
    pub fn generate_challenge() -> ConnectionChallenge {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mut h = Sha256::new();
        h.update(b"ShadowDAG_ConnPuzzle_v1");
        h.update(entropy);
        let challenge = hex::encode(h.finalize());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ConnectionChallenge {
            challenge,
            created_at: now,
        }
    }

    /// Solve a challenge (done by the connecting peer)
    pub fn solve(challenge: &str) -> ChallengeSolution {
        let target = "0".repeat(PUZZLE_DIFFICULTY);
        let mut nonce: u64 = 0;

        loop {
            let mut h = Sha256::new();
            h.update(challenge.as_bytes());
            h.update(nonce.to_le_bytes());
            let hash = hex::encode(h.finalize());

            if hash.starts_with(&target) {
                return ChallengeSolution {
                    challenge: challenge.to_string(),
                    nonce,
                    hash,
                };
            }
            nonce += 1;
        }
    }

    /// Verify a challenge solution
    pub fn verify(challenge: &ConnectionChallenge, solution: &ChallengeSolution) -> bool {
        // Check challenge matches
        if solution.challenge != challenge.challenge {
            return false;
        }

        // Check expiry
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(challenge.created_at) > PUZZLE_EXPIRY_SECS {
            return false;
        }

        // Verify hash
        let mut h = Sha256::new();
        h.update(solution.challenge.as_bytes());
        h.update(solution.nonce.to_le_bytes());
        let computed = hex::encode(h.finalize());

        if computed != solution.hash {
            return false;
        }

        // Check difficulty
        let target = "0".repeat(PUZZLE_DIFFICULTY);
        computed.starts_with(&target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_and_verify() {
        let challenge = ConnectionPuzzle::generate_challenge();
        let solution = ConnectionPuzzle::solve(&challenge.challenge);
        assert!(ConnectionPuzzle::verify(&challenge, &solution));
    }

    #[test]
    fn wrong_challenge_fails() {
        let challenge = ConnectionPuzzle::generate_challenge();
        let mut solution = ConnectionPuzzle::solve(&challenge.challenge);
        solution.challenge = "wrong_challenge".into();
        assert!(!ConnectionPuzzle::verify(&challenge, &solution));
    }

    #[test]
    fn wrong_nonce_fails() {
        let challenge = ConnectionPuzzle::generate_challenge();
        let mut solution = ConnectionPuzzle::solve(&challenge.challenge);
        solution.nonce += 1; // Tamper
        assert!(!ConnectionPuzzle::verify(&challenge, &solution));
    }

    #[test]
    fn solution_has_leading_zeros() {
        let challenge = ConnectionPuzzle::generate_challenge();
        let solution = ConnectionPuzzle::solve(&challenge.challenge);
        assert!(solution.hash.starts_with(&"0".repeat(PUZZLE_DIFFICULTY)));
    }

    #[test]
    fn unique_challenges() {
        let c1 = ConnectionPuzzle::generate_challenge();
        let c2 = ConnectionPuzzle::generate_challenge();
        assert_ne!(c1.challenge, c2.challenge);
    }
}
