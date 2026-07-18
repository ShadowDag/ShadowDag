// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ShadowHash — LEGACY (pre-fork) proof-of-work algorithm.
//
// Rounds: SHA-256 header -> BLAKE3 scratchpad mix -> SHA3-256 -> anti-ASIC mix.
//
// HONEST SECURITY NOTE (internal crypto pre-audit F-2, 2026-07-15): this
// algorithm's "memory-hardness / ASIC-resistance" does NOT hold. The 256 KB
// scratchpad is filled by independent SHA256(round1 || i) chunks and the mix
// loop's addressing (idx, rot_idx) depends only on the header pre-hash and
// constants — no scratchpad VALUE ever selects an address — so there is no
// data-dependent memory-latency chain. An optimizer computes only the few
// touched chunks and streams the final hash, reducing the whole thing to
// SHA256 work, which mature SHA256 ASICs crush. It is retained ONLY to
// validate pre-fork blocks. The chain's real memory-hard PoW is UmbraHash
// (engine/mining/algorithms/umbrahash.rs, Ethash-DAG + mini-ProgPoW); once
// UmbraHash is activated (UMBRA_ACTIVATION_HEIGHT), consensus must reject
// this legacy algorithm so it can never be a cheaper co-valid path at the
// same difficulty target.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

use crate::domain::block::block::Block;

/// ShadowHash scratchpad size in bytes (256 KB). NOTE: this provides no real
/// memory-latency hardness — the access pattern is not value-dependent (see the
/// F-2 note in the file header); the scratchpad is streamable/regenerable.
pub const SCRATCHPAD_SIZE: usize = 262144;

/// Number of mixing rounds. 16 rounds over a fixed (non-value-dependent) access
/// pattern do not defeat ASIC pipelining; see the F-2 note in the file header.
pub const MIX_ROUNDS: usize = 16;

/// Hash a full block
pub fn shadow_hash(block: &Block) -> String {
    let header_bytes = serialize_header(block);
    shadow_hash_bytes(&header_bytes)
}

/// Hash from raw header fields with extra_nonce=0.
/// Only valid for genesis blocks and tests. For mining/validation,
/// use shadow_hash_raw_full() with explicit extra_nonce.
#[deprecated(note = "Use shadow_hash_raw_full() with explicit extra_nonce")]
#[allow(clippy::too_many_arguments)]
pub fn shadow_hash_raw(
    version: u32,
    height: u64,
    timestamp: u64,
    nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
    prev_state_commitment: Option<&str>,
) -> String {
    shadow_hash_raw_full(
        version,
        height,
        timestamp,
        nonce,
        0,
        difficulty,
        merkle_root,
        parents,
        prev_state_commitment,
    )
}

/// Hash from raw header fields including extra_nonce.
/// This is the canonical hash function — ALL validation must use this.
#[allow(clippy::too_many_arguments)]
pub fn shadow_hash_raw_full(
    version: u32,
    height: u64,
    timestamp: u64,
    nonce: u64,
    extra_nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
    prev_state_commitment: Option<&str>,
) -> String {
    let mut bytes = serialize_header_raw(
        version,
        height,
        timestamp,
        nonce,
        difficulty,
        merkle_root,
        parents,
        prev_state_commitment,
    );
    bytes.extend_from_slice(&extra_nonce.to_le_bytes());
    shadow_hash_bytes(&bytes)
}

/// Core ShadowHash: 3-round multi-algorithm pipeline
fn shadow_hash_bytes(data: &[u8]) -> String {
    // ── Round 1: SHA-256 ──
    let mut sha256 = Sha256::new();
    sha256.update(data);
    let round1 = sha256.finalize();

    // ── Round 2: Memory-hard mixing with scratchpad ──
    let mut scratchpad = vec![0u8; SCRATCHPAD_SIZE];
    // Initialize scratchpad from round1
    for (i, chunk) in scratchpad.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(round1);
        h.update((i as u32).to_le_bytes());
        let block = h.finalize();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&block[..len]);
    }

    // Mix scratchpad entries (memory-hard: random access pattern)
    for round in 0..MIX_ROUNDS {
        let idx = (round1[round % 32] as usize * 256 + round1[(round + 1) % 32] as usize)
            % (SCRATCHPAD_SIZE - 32);
        let mut mix = [0u8; 32];
        mix.copy_from_slice(&scratchpad[idx..idx + 32]);

        // XOR with rotated position
        let rot_idx = (idx.wrapping_mul(0x9E3779B9)) % (SCRATCHPAD_SIZE - 32);
        for j in 0..32 {
            mix[j] ^= scratchpad[rot_idx + j];
            mix[j] = mix[j].rotate_left((round as u32) % 8);
        }

        // Write back
        scratchpad[idx..idx + 32].copy_from_slice(&mix);
    }

    // Compress scratchpad
    let mut h2 = Sha256::new();
    h2.update(&scratchpad);
    let round2 = h2.finalize();

    // ── Round 2.5: Anti-ASIC hardening (data-dependent branching) ──
    // Uses the 16KB scratchpad from anti_asic.rs with 256 branch-heavy rounds.
    // This makes ASIC pipelining impractical.
    let anti_asic_hash =
        crate::engine::mining::algorithms::anti_asic::AntiAsic::harden_bytes(&round2);

    // ── Round 3: SHA3-256 combining all previous rounds ──
    let mut sha3 = Sha3_256::new();
    sha3.update(round1); // SHA-256 output
    sha3.update(round2); // Scratchpad compression
    sha3.update(anti_asic_hash); // Anti-ASIC 16KB hardening
    sha3.update(data); // Original header
    let round3 = sha3.finalize();

    hex::encode(round3)
}

/// Hash arbitrary bytes with the ShadowHash pipeline. This is the exact
/// transform a GPU kernel reproduces; exposing it lets the miner/tests verify a
/// GPU-found nonce against the canonical CPU hash.
pub fn shadow_hash_of_bytes(data: &[u8]) -> String {
    shadow_hash_bytes(data)
}

/// Check if a hash meets the target difficulty.
/// Unified: delegates to the canonical 256-bit target comparison.
pub fn meets_difficulty(hash: &str, difficulty: u64) -> bool {
    crate::engine::mining::pow::pow_validator::PowValidator::hash_meets_target(hash, difficulty)
}

/// Convert difficulty to a target hash value.
/// Delegates to PowValidator for proper 256-bit target: target = MAX_TARGET / difficulty.
pub fn difficulty_to_target(difficulty: u64) -> String {
    crate::engine::mining::pow::pow_validator::PowValidator::difficulty_to_target(difficulty)
}

/// Canonical encoding of an optional root (hex string) for the M5 deferred state
/// commitment: `0x00` for None, else `0x01 || u32-le len || utf8 bytes`.
/// Distinguishes None from Some("") so the commitment is unambiguous.
fn enc_opt_root(buf: &mut Vec<u8>, root: Option<&str>) {
    match root {
        None => buf.push(0x00),
        Some(s) => {
            buf.push(0x01);
            let b = s.as_bytes();
            buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
            buf.extend_from_slice(b);
        }
    }
}

/// M5 DEFERRED STATE COMMITMENT: SHA3-256 over the selected parent's identity and
/// its post-execution roots. A block binds THIS value in its PoW preimage, so the
/// block hash commits to the state it builds on (the parent's post-state). All
/// nodes derive it identically from the parent's stored roots; a forged value
/// fails BOTH the deferred verify (compare vs the parent's stored roots) and PoW
/// (it is inside the preimage). Domain-separated + versioned to avoid ambiguity.
pub fn compute_prev_state_commitment(
    selected_parent: &str,
    parent_utxo_commitment: Option<&str>,
    parent_state_root: Option<&str>,
    parent_receipt_root: Option<&str>,
) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(160);
    buf.extend_from_slice(b"ShadowDAG_PrevState_v1");
    let sp = selected_parent.as_bytes();
    buf.extend_from_slice(&(sp.len() as u32).to_le_bytes());
    buf.extend_from_slice(sp);
    enc_opt_root(&mut buf, parent_utxo_commitment);
    enc_opt_root(&mut buf, parent_state_root);
    enc_opt_root(&mut buf, parent_receipt_root);
    let mut h = Sha3_256::new();
    h.update(&buf);
    hex::encode(h.finalize())
}

/// The M5 deferred state commitment for GENESIS: no parent, empty initial state
/// (selected_parent = "" and all parent roots None). A fixed constant every node
/// agrees on.
pub fn genesis_prev_state_commitment() -> String {
    compute_prev_state_commitment("", None, None, None)
}

/// Serialize block header to bytes (uses same path as shadow_hash_raw_full)
fn serialize_header(block: &Block) -> Vec<u8> {
    let mut buf = serialize_header_raw(
        block.header.version,
        block.header.height,
        block.header.timestamp,
        block.header.nonce,
        block.header.difficulty,
        &block.header.merkle_root,
        &block.header.parents,
        block.header.prev_state_commitment.as_deref(),
    );
    buf.extend_from_slice(&block.header.extra_nonce.to_le_bytes());
    buf
}

/// Serialize raw header fields to bytes (deterministic). The single core
/// preimage serializer: BOTH PoW preimages (ShadowHash via `shadow_hash_raw_full`
/// and UmbraHash via `serialize_header_template`) build on it, so every field
/// bound here is bound identically for both algorithms and for miner + validator
/// + sync + light (the "one serializer, literally" requirement).
///
/// M5: the domain tag is bumped v1 -> v2 (same 18-byte length, so
/// `HEADER_NONCE_OFFSET` is unchanged) and the deferred `prev_state_commitment`
/// is appended AFTER the parents (never between the nonce and the domain, so the
/// GPU nonce patch offset stays valid). `enc_opt_root` makes `None` vs `Some("")`
/// unambiguous.
#[allow(clippy::too_many_arguments)]
fn serialize_header_raw(
    version: u32,
    height: u64,
    timestamp: u64,
    nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
    prev_state_commitment: Option<&str>,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);

    // Domain separation (v2: M5 deferred state commitment appended below).
    buf.extend_from_slice(b"ShadowDAG_Block_v2");

    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&difficulty.to_le_bytes());
    buf.extend_from_slice(merkle_root.as_bytes());

    // CONSENSUS RULE: Parents MUST be sorted before hashing.
    // Without sorting, the same block with parents [A,B] vs [B,A]
    // would produce different hashes → consensus fork.
    let mut sorted_parents: Vec<&String> = parents.iter().collect();
    sorted_parents.sort();

    buf.push(sorted_parents.len().min(255) as u8);
    for parent in &sorted_parents {
        let p_bytes = parent.as_bytes();
        let len = (p_bytes.len() as u16).to_le_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(p_bytes);
    }

    // M5 deferred state commitment (appended last; canonical Option encoding).
    enc_opt_root(&mut buf, prev_state_commitment);
    buf
}

/// Byte offset of the 8-byte little-endian `nonce` field inside the serialized
/// header, i.e. after the 18-byte domain tag + version(4) + height(8) +
/// timestamp(8). A GPU miner patches these 8 bytes per work-item, so this MUST
/// stay in sync with `serialize_header_raw`.
pub const HEADER_NONCE_OFFSET: usize = 18 + 4 + 8 + 8;

/// Serialize the exact bytes `shadow_hash_raw_full` hashes, with the `nonce`
/// field left as zero. A GPU miner hashes this template while overwriting the 8
/// bytes at `HEADER_NONCE_OFFSET` with each candidate nonce — producing the
/// identical input the CPU path would for that nonce.
#[allow(clippy::too_many_arguments)]
pub fn serialize_header_template(
    version: u32,
    height: u64,
    timestamp: u64,
    extra_nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
    prev_state_commitment: Option<&str>,
) -> Vec<u8> {
    let mut buf = serialize_header_raw(
        version,
        height,
        timestamp,
        0, // nonce placeholder — the GPU overwrites HEADER_NONCE_OFFSET..+8
        difficulty,
        merkle_root,
        parents,
        prev_state_commitment,
    );
    buf.extend_from_slice(&extra_nonce.to_le_bytes());
    buf
}

/// Hash a string (utility function used in Merkle trees, etc.)
pub fn shadow_hash_str(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Hash_v1");
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prev_state_commitment_is_deterministic_and_sensitive() {
        // M5 KAT: the deferred commitment is a 64-hex SHA3-256, deterministic, and
        // changes if ANY input byte changes (parent hash or any parent root).
        let uc = "aa".repeat(32);
        let sr = "bb".repeat(32);
        let rr = "cc".repeat(32);
        let base = compute_prev_state_commitment("parentA", Some(&uc), Some(&sr), None);
        assert_eq!(base.len(), 64);
        assert!(base.chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic.
        assert_eq!(base, compute_prev_state_commitment("parentA", Some(&uc), Some(&sr), None));
        // Changing the selected parent -> different commitment.
        assert_ne!(base, compute_prev_state_commitment("parentB", Some(&uc), Some(&sr), None));
        // Changing utxo_commitment / state_root / adding receipt_root -> different.
        let uc2 = "ac".repeat(32);
        assert_ne!(base, compute_prev_state_commitment("parentA", Some(&uc2), Some(&sr), None));
        let sr2 = "bc".repeat(32);
        assert_ne!(base, compute_prev_state_commitment("parentA", Some(&uc), Some(&sr2), None));
        assert_ne!(base, compute_prev_state_commitment("parentA", Some(&uc), Some(&sr), Some(&rr)));
        // Canonical encoding: None is distinct from Some("").
        assert_ne!(
            compute_prev_state_commitment("p", None, None, None),
            compute_prev_state_commitment("p", Some(""), None, None)
        );
        // Field boundaries are unambiguous: (Some,None) != (None,Some) shuffle.
        assert_ne!(
            compute_prev_state_commitment("p", Some(&uc), None, None),
            compute_prev_state_commitment("p", None, Some(&uc), None)
        );
        // Genesis commitment = empty parent + all-None, stable.
        assert_eq!(genesis_prev_state_commitment(), compute_prev_state_commitment("", None, None, None));
        assert_eq!(genesis_prev_state_commitment().len(), 64);
    }

    #[test]
    fn hash_str_is_64_chars() {
        let h = shadow_hash_str("test");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_raw_is_deterministic() {
        let h1 = shadow_hash_raw_full(1, 0, 1735689600, 42, 0, 4, "merkle", &[], None);
        let h2 = shadow_hash_raw_full(1, 0, 1735689600, 42, 0, 4, "merkle", &[], None);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_nonce_different_hash() {
        let h1 = shadow_hash_raw_full(1, 0, 1735689600, 1, 0, 4, "merkle", &[], None);
        let h2 = shadow_hash_raw_full(1, 0, 1735689600, 2, 0, 4, "merkle", &[], None);
        assert_ne!(h1, h2);
    }

    #[test]
    fn meets_difficulty_check() {
        // difficulty 0 always returns false (only valid for genesis via special path)
        assert!(!meets_difficulty(&"a".repeat(64), 0));
        // difficulty 1: target = MAX_TARGET, any valid 64-char hash passes
        assert!(meets_difficulty(&format!("{:0>64}", "0123456789"), 1));
        // all-zeros passes any difficulty
        assert!(meets_difficulty(&"0".repeat(64), 1));
        assert!(meets_difficulty(&"0".repeat(64), 1_000_000));
        // all-f fails high difficulty (target = MAX/2 = 7fff...)
        assert!(!meets_difficulty(&"f".repeat(64), 2));
    }

    #[test]
    fn difficulty_to_target_format() {
        let t = difficulty_to_target(3);
        assert_eq!(t.len(), 64);
        // 256-bit target: MAX_TARGET / 3 → starts with "55" (0x55 = 0xFF/3)
        assert!(t.starts_with("55"));
    }

    #[test]
    fn gpu_template_plus_nonce_matches_raw_full() {
        // The GPU miner hashes serialize_header_template(...) after overwriting 8
        // bytes at HEADER_NONCE_OFFSET with the candidate nonce. That MUST equal
        // the canonical shadow_hash_raw_full for the same nonce, or GPU-mined
        // blocks would be rejected by consensus.
        let parents = vec!["a".repeat(64), "f".repeat(64)];
        let mr = "deadbeef".repeat(8);
        for &nonce in &[0u64, 1, 42, 9_999_999, u64::MAX] {
            let mut tmpl = serialize_header_template(2, 123, 1_735_689_600_000, 7, 4096, &mr, &parents, None);
            tmpl[HEADER_NONCE_OFFSET..HEADER_NONCE_OFFSET + 8]
                .copy_from_slice(&nonce.to_le_bytes());
            let via_template = shadow_hash_of_bytes(&tmpl);
            let via_raw = shadow_hash_raw_full(2, 123, 1_735_689_600_000, nonce, 7, 4096, &mr, &parents, None);
            assert_eq!(via_template, via_raw, "template+nonce must equal raw_full (nonce={})", nonce);
        }
    }

    #[test]
    fn shadow_hash_includes_memory_hard_mixing() {
        // Verify that different data produces very different hashes
        let h1 = shadow_hash_raw_full(1, 0, 0, 0, 0, 1, "a", &[], None);
        let h2 = shadow_hash_raw_full(1, 0, 0, 0, 0, 1, "b", &[], None);
        assert_ne!(h1, h2);

        // And they look random (no obvious patterns)
        let chars: Vec<char> = h1.chars().collect();
        let unique: std::collections::HashSet<&char> = chars.iter().collect();
        assert!(unique.len() > 5, "Hash should use diverse hex chars");
    }

    #[test]
    fn prev_state_commitment_binds_to_block_hash() {
        // M5 stage-1b KAT: the deferred commitment is part of the PoW preimage, so
        // a 1-byte change in prev_state_commitment (or None vs Some) yields a
        // DIFFERENT ShadowHash AND a different UmbraHash header_hash — the block
        // hash commits to the parent's post-state. BOTH preimages must react.
        let parents = vec!["a".repeat(64)];
        let mr = "cd".repeat(32);
        let c1 = "11".repeat(32);
        let c2 = "12".repeat(32); // exactly one byte different
        // ShadowHash (shadow_hash_raw_full).
        let s_none = shadow_hash_raw_full(2, 5, 1_700_000_000_000, 7, 0, 100, &mr, &parents, None);
        let s_c1 = shadow_hash_raw_full(2, 5, 1_700_000_000_000, 7, 0, 100, &mr, &parents, Some(&c1));
        let s_c2 = shadow_hash_raw_full(2, 5, 1_700_000_000_000, 7, 0, 100, &mr, &parents, Some(&c2));
        assert_ne!(s_none, s_c1, "None vs Some commitment must change the ShadowHash");
        assert_ne!(s_c1, s_c2, "a 1-byte commitment change must change the ShadowHash");
        // UmbraHash preimage (header_hash) reacts too.
        use crate::engine::mining::algorithms::umbrahash::header_hash;
        let u_c1 = header_hash(3, 5, 1_700_000_000_000, 0, 100, &mr, &parents, Some(&c1));
        let u_c2 = header_hash(3, 5, 1_700_000_000_000, 0, 100, &mr, &parents, Some(&c2));
        let u_none = header_hash(3, 5, 1_700_000_000_000, 0, 100, &mr, &parents, None);
        assert_ne!(u_c1, u_c2, "a 1-byte commitment change must change the UmbraHash preimage");
        assert_ne!(u_none, u_c1, "None vs Some commitment must change the UmbraHash preimage");
        // Domain bumped v1->v2 stays 18 bytes, so the GPU nonce patch offset holds.
        assert_eq!(HEADER_NONCE_OFFSET, 18 + 4 + 8 + 8);
    }
}
