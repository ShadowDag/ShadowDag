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

/// A well-formed challenge is the hex encoding of a SHA-256 digest, so it is
/// always exactly this many characters. Enforcing the exact shape before
/// solving is what keeps the solver's per-iteration cost constant: `solve`
/// hashes the whole challenge on every attempt, so an unbounded challenge
/// turns ~4096 iterations into ~4096 x len bytes of SHA-256.
pub const CHALLENGE_HEX_LEN: usize = 64;

/// Hard ceiling on the solver's search. Each attempt succeeds with
/// probability 16^-PUZZLE_DIFFICULTY = 1/4096, so reaching this cap has
/// probability (1 - 1/4096)^(2^22), i.e. below 2^-1400 — it exists so a
/// network handler can never contain an unbounded loop, not because it is
/// expected to trigger.
pub const MAX_SOLVE_ITERS: u64 = 1 << 22;

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

    /// Whether a challenge has the only shape `generate_challenge` can
    /// produce. Callers MUST check this before solving: the challenge arrives
    /// off the wire from a peer, and `solve` hashes all of it once per
    /// iteration.
    pub fn is_well_formed(challenge: &str) -> bool {
        challenge.len() == CHALLENGE_HEX_LEN && challenge.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// Solve a challenge (done by the connecting peer).
    ///
    /// Returns `None` for a challenge that is not well-formed, and `None` if
    /// the search reaches `MAX_SOLVE_ITERS` — never an unbounded loop.
    pub fn solve(challenge: &str) -> Option<ChallengeSolution> {
        if !Self::is_well_formed(challenge) {
            return None;
        }
        let target = "0".repeat(PUZZLE_DIFFICULTY);

        for nonce in 0..MAX_SOLVE_ITERS {
            let mut h = Sha256::new();
            h.update(challenge.as_bytes());
            h.update(nonce.to_le_bytes());
            let hash = hex::encode(h.finalize());

            if hash.starts_with(&target) {
                return Some(ChallengeSolution {
                    challenge: challenge.to_string(),
                    nonce,
                    hash,
                });
            }
        }
        None
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
        let solution = ConnectionPuzzle::solve(&challenge.challenge).expect("solvable");
        assert!(ConnectionPuzzle::verify(&challenge, &solution));
    }

    #[test]
    fn wrong_challenge_fails() {
        let challenge = ConnectionPuzzle::generate_challenge();
        let mut solution = ConnectionPuzzle::solve(&challenge.challenge).expect("solvable");
        solution.challenge = "wrong_challenge".into();
        assert!(!ConnectionPuzzle::verify(&challenge, &solution));
    }

    #[test]
    fn wrong_nonce_fails() {
        let challenge = ConnectionPuzzle::generate_challenge();
        let mut solution = ConnectionPuzzle::solve(&challenge.challenge).expect("solvable");
        solution.nonce += 1; // Tamper
        assert!(!ConnectionPuzzle::verify(&challenge, &solution));
    }

    #[test]
    fn solution_has_leading_zeros() {
        let challenge = ConnectionPuzzle::generate_challenge();
        let solution = ConnectionPuzzle::solve(&challenge.challenge).expect("solvable");
        assert!(solution.hash.starts_with(&"0".repeat(PUZZLE_DIFFICULTY)));
    }

    #[test]
    fn generated_challenge_is_well_formed() {
        let c = ConnectionPuzzle::generate_challenge();
        assert!(
            ConnectionPuzzle::is_well_formed(&c.challenge),
            "generate_challenge must produce the shape solve() accepts: {:?}",
            c.challenge
        );
        assert_eq!(c.challenge.len(), CHALLENGE_HEX_LEN);
    }

    #[test]
    fn solve_refuses_anything_but_a_64_hex_challenge() {
        // The amplification vector: `solve` hashes the whole challenge once
        // per iteration (~4096 iterations), so a multi-megabyte challenge off
        // the wire costs gigabytes of SHA-256. Nothing but the exact shape is
        // allowed to reach the loop.
        let oversized = "a".repeat(4 * 1024 * 1024);
        for bad in [
            oversized.as_str(),
            "",
            "00",
            &"0".repeat(CHALLENGE_HEX_LEN - 1),
            &"0".repeat(CHALLENGE_HEX_LEN + 1),
            // right length, not hex
            &"z".repeat(CHALLENGE_HEX_LEN),
        ] {
            assert!(
                ConnectionPuzzle::solve(bad).is_none(),
                "solve must reject a malformed challenge (len {})",
                bad.len()
            );
        }
    }

    #[test]
    fn unique_challenges() {
        let c1 = ConnectionPuzzle::generate_challenge();
        let c2 = ConnectionPuzzle::generate_challenge();
        assert_ne!(c1.challenge, c2.challenge);
    }
}
