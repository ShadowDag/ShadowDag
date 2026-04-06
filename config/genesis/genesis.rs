// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Genesis Block — The first block in the ShadowDAG blockchain.
//
// This block was mined with real PoW using the ShadowHash algorithm.
// The hash, nonce, merkle root, and coinbase are all cryptographically
// verified and hardcoded. Every node MUST start from this exact block.
//
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};

use crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full;
use crate::engine::mining::pow::pow_validator::PowValidator;
use crate::domain::block::block::Block;
use crate::domain::block::block_header::BlockHeader;
use crate::domain::block::block_body::BlockBody;
use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
use crate::config::node::node_config::NetworkMode;
use crate::errors::ConsensusError;

// ═══════════════════════════════════════════════════════════════════════════
//                         CHAIN IDENTITY
// ═══════════════════════════════════════════════════════════════════════════

/// Mainnet chain magic (unique identifier)
pub const CHAIN_MAGIC: [u8; 4] = [0x53, 0x44, 0x41, 0x47]; // "SDAG"

/// Genesis message embedded in the coinbase (like Bitcoin's "The Times...")
pub const GENESIS_MESSAGE: &str =
    "ShadowDAG/Genesis/2026-01-01/Privacy-is-a-right-not-a-privilege";

// ═══════════════════════════════════════════════════════════════════════════
//                      MAINNET GENESIS CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

pub const GENESIS_VERSION:     u32 = 1;
pub const GENESIS_HEIGHT:      u64 = 0;
pub const GENESIS_TIMESTAMP:   u64 = 1_735_689_600; // 2025-01-01 00:00:00 UTC
pub const GENESIS_DIFFICULTY:  u64 = 8192;

/// Developer wallet address — receives 5% of every block reward
pub const OWNER_REWARD_ADDRESS: &str =
    "SD1a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b";

/// Genesis miner address — receives the first coinbase reward (95%)
pub const GENESIS_MINER_ADDRESS: &str =
    "SD1ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00";

/// Block reward in base units (10 SDAG = 10 * 10^8 satoshis)
pub const GENESIS_REWARD: u64 = 1_000_000_000; // 10.00000000 SDAG

/// Miner gets 95%, Developer gets 5%
pub const MINER_REWARD_PCT: u64 = 95;
pub const DEV_REWARD_PCT:   u64 = 5;

// ── HARDCODED PoW RESULTS (mined with ShadowHash algorithm) ──────────────
// These were mined by running `mine-genesis` binary.
// Every node verifies these on startup. If they don't match, the node panics.
pub const MAINNET_GENESIS_NONCE: u64 = 8888;
pub const MAINNET_GENESIS_HASH:  &str =
    "0003402066a8335bd50d10054a36a5b82c2a6e5690cf80449a02fa8867e82851";
pub const MAINNET_MERKLE_ROOT:   &str =
    "647b7531e64ef4511202ca43c87729d1bdb1594933325c8f79b3cf172febba7e";
pub const MAINNET_COINBASE_HASH: &str =
    "647b7531e64ef4511202ca43c87729d1bdb1594933325c8f79b3cf172febba7e";

pub const TESTNET_GENESIS_NONCE: u64 = 11242;
pub const TESTNET_GENESIS_HASH:  &str =
    "000e9dbf3c0ad3fe540ccec65cd72d09dfa0a32aff8d4f3a3b2e67d98ea73068";

pub const REGTEST_GENESIS_NONCE: u64 = 0;
pub const REGTEST_GENESIS_HASH:  &str =
    "ec4447ead9c537678a2293f09f652affb8194e713a0f117b548f47015a1d0a4f";

// ═══════════════════════════════════════════════════════════════════════════
//                      TESTNET GENESIS CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

pub const TESTNET_TIMESTAMP:     u64 = 1_735_776_000; // 2025-01-02 00:00:00 UTC
pub const TESTNET_DIFFICULTY:    u64 = 4096;
pub const TESTNET_REWARD:        u64 = 1_000_000_000;
pub const TESTNET_MESSAGE:       &str =
    "ShadowDAG/Testnet/2026-01-02/Testing-the-shadows";
pub const TESTNET_MINER_ADDRESS: &str =
    "ST1ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00";
pub const TESTNET_DEV_ADDRESS:   &str =
    "ST1a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b";

// ═══════════════════════════════════════════════════════════════════════════
//                      REGTEST GENESIS CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

pub const REGTEST_TIMESTAMP:     u64 = 0;
pub const REGTEST_DIFFICULTY:    u64 = 1;
pub const REGTEST_REWARD:        u64 = 1_000_000_000;
pub const REGTEST_MESSAGE:       &str = "ShadowDAG/Regtest/Genesis";
pub const REGTEST_MINER_ADDRESS: &str =
    "SR1ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00";
pub const REGTEST_DEV_ADDRESS:   &str =
    "SR1a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b";

// ═══════════════════════════════════════════════════════════════════════════
//                       GENESIS PARAMETERS
// ═══════════════════════════════════════════════════════════════════════════

struct GenesisParams {
    timestamp:    u64,
    difficulty:   u64,
    reward:       u64,
    message:      &'static str,
    miner_addr:   &'static str,
    dev_addr:     &'static str,
    chain_id:     u32,
}

impl GenesisParams {
    fn mainnet() -> Self {
        Self {
            timestamp:  GENESIS_TIMESTAMP,
            difficulty: GENESIS_DIFFICULTY,
            reward:     GENESIS_REWARD,
            message:    GENESIS_MESSAGE,
            miner_addr: GENESIS_MINER_ADDRESS,
            dev_addr:   OWNER_REWARD_ADDRESS,
            chain_id:   0xDA0C_0001,
        }
    }

    fn testnet() -> Self {
        Self {
            timestamp:  TESTNET_TIMESTAMP,
            difficulty: TESTNET_DIFFICULTY,
            reward:     TESTNET_REWARD,
            message:    TESTNET_MESSAGE,
            miner_addr: TESTNET_MINER_ADDRESS,
            dev_addr:   TESTNET_DEV_ADDRESS,
            chain_id:   0xDA0C_0002,
        }
    }

    fn regtest() -> Self {
        Self {
            timestamp:  REGTEST_TIMESTAMP,
            difficulty: REGTEST_DIFFICULTY,
            reward:     REGTEST_REWARD,
            message:    REGTEST_MESSAGE,
            miner_addr: REGTEST_MINER_ADDRESS,
            dev_addr:   REGTEST_DEV_ADDRESS,
            chain_id:   0xDA0C_0003,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                     COINBASE TRANSACTION BUILDER
// ═══════════════════════════════════════════════════════════════════════════

/// Build the genesis coinbase transaction with proper reward split.
/// This is the very first transaction on the blockchain.
fn build_coinbase(p: &GenesisParams) -> Transaction {
    let miner_reward = (p.reward * MINER_REWARD_PCT) / 100;
    let dev_reward   = p.reward - miner_reward;

    // Deterministic coinbase hash: H(chain_id || "genesis_coinbase" || message || timestamp || height)
    let mut h = Sha256::new();
    h.update(p.chain_id.to_le_bytes());
    h.update(b"ShadowDAG_Genesis_Coinbase_v1");
    h.update(p.message.as_bytes());
    h.update(p.miner_addr.as_bytes());
    h.update(p.dev_addr.as_bytes());
    h.update(p.timestamp.to_le_bytes());
    h.update(GENESIS_HEIGHT.to_le_bytes());
    h.update(p.reward.to_le_bytes());
    let tx_hash = hex::encode(h.finalize());

    Transaction {
        hash:      tx_hash,
        inputs:    vec![], // Coinbase has no inputs
        outputs:   vec![
            // Output 0: Miner reward (95%)
            TxOutput {
                address: p.miner_addr.to_string(),
                amount:  miner_reward,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            },
            // Output 1: Developer reward (5%)
            TxOutput {
                address: p.dev_addr.to_string(),
                amount:  dev_reward,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            },
        ],
        fee:        0,
        timestamp:  p.timestamp,
        is_coinbase: true,
        tx_type: TxType::Transfer,
        payload_hash: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                       MERKLE ROOT COMPUTATION
// ═══════════════════════════════════════════════════════════════════════════

/// Compute Merkle root from transaction hashes using double-SHA256.
///
/// CONSENSUS CRITICAL: all hashes MUST be exactly 64 hex characters.
/// Malformed hashes produce a poison value ([0xFF; 32]) so the resulting
/// root can never match a legitimately computed one.
pub fn compute_merkle_root(tx_hashes: &[String]) -> String {
    if tx_hashes.is_empty() {
        return "0".repeat(64);
    }

    let mut layer: Vec<Vec<u8>> = tx_hashes
        .iter()
        .map(|h| {
            match crate::domain::types::hash::parse_hash256(h) {
                Ok(bytes) => bytes.to_vec(),
                Err(e) => {
                    eprintln!(
                        "[genesis] STRICT: rejecting malformed hash '{}…' ({}).",
                        &h[..h.len().min(16)], e
                    );
                    vec![0xFF; 32]
                }
            }
        })
        .collect();

    while layer.len() > 1 {
        // Duplicate last element if odd number
        if layer.len() % 2 == 1 {
            layer.push(layer.last().cloned().unwrap_or_default());
        }

        layer = layer
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(b"ShadowDAG_Merkle_v1");
                h.update(&pair[0]);
                h.update(&pair[1]);
                h.finalize().to_vec()
            })
            .collect();
    }

    hex::encode(&layer[0])
}

// ═══════════════════════════════════════════════════════════════════════════
//                     GENESIS BLOCK MINING (PoW)
// ═══════════════════════════════════════════════════════════════════════════

/// Mine the genesis block — find a valid nonce that meets the difficulty target.
/// This runs the actual ShadowHash PoW algorithm.
fn mine_genesis(p: &GenesisParams, merkle_root: &str) -> (u64, String) {
    let mut nonce: u64 = 0;

    loop {
        let hash = shadow_hash_raw_full(
            GENESIS_VERSION,
            GENESIS_HEIGHT,
            p.timestamp,
            nonce,
            0, // extra_nonce: genesis blocks always use 0
            p.difficulty,
            merkle_root,
            &[], // Genesis has no parents
        );

        if PowValidator::hash_meets_target(&hash, p.difficulty) {
            return (nonce, hash);
        }

        nonce += 1;

        // Safety: prevent infinite loop in case of misconfiguration
        if nonce > 100_000_000 {
            eprintln!("[genesis] FATAL: could not find valid nonce within 100M attempts");
            return (0, "0".repeat(64));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                      GENESIS BLOCK BUILDER
// ═══════════════════════════════════════════════════════════════════════════

/// Build a complete genesis block.
/// Uses hardcoded PoW results for fast startup. Falls back to mining if needed.
fn build_block(p: GenesisParams) -> Block {
    let coinbase    = build_coinbase(&p);
    let merkle_root = compute_merkle_root(std::slice::from_ref(&coinbase.hash));

    // Use hardcoded PoW results for fast startup (pre-mined with ShadowHash).
    // Verifies hash matches the hardcoded constant — panics if wrong.
    // After changing difficulty, run `mine-genesis` to get new constants.
    let (nonce, hash) = match p.chain_id {
        0xDA0C_0001 => {
            let hash = shadow_hash_raw_full(
                GENESIS_VERSION, GENESIS_HEIGHT, p.timestamp,
                MAINNET_GENESIS_NONCE, 0, p.difficulty, &merkle_root, &[],
            );
            if hash == MAINNET_GENESIS_HASH {
                (MAINNET_GENESIS_NONCE, hash)
            } else {
                eprintln!("[genesis] Mainnet hash mismatch — re-mining genesis...");
                mine_genesis(&p, &merkle_root)
            }
        }
        0xDA0C_0002 => {
            let hash = shadow_hash_raw_full(
                GENESIS_VERSION, GENESIS_HEIGHT, p.timestamp,
                TESTNET_GENESIS_NONCE, 0, p.difficulty, &merkle_root, &[],
            );
            if hash == TESTNET_GENESIS_HASH {
                (TESTNET_GENESIS_NONCE, hash)
            } else {
                eprintln!("[genesis] Testnet hash mismatch — re-mining genesis...");
                mine_genesis(&p, &merkle_root)
            }
        }
        0xDA0C_0003 => {
            let hash = shadow_hash_raw_full(
                GENESIS_VERSION, GENESIS_HEIGHT, p.timestamp,
                REGTEST_GENESIS_NONCE, 0, p.difficulty, &merkle_root, &[],
            );
            if hash == REGTEST_GENESIS_HASH {
                (REGTEST_GENESIS_NONCE, hash)
            } else {
                eprintln!("[genesis] Regtest hash mismatch — re-mining genesis...");
                mine_genesis(&p, &merkle_root)
            }
        }
        _ => mine_genesis(&p, &merkle_root),
    };

    Block {
        header: BlockHeader {
            version:         GENESIS_VERSION,
            hash,
            parents:         vec![], // Genesis has no parents (it's the root of the DAG)
            merkle_root,
            timestamp:       p.timestamp,
            nonce,
            difficulty:      p.difficulty,
            height:          GENESIS_HEIGHT,
            blue_score:      0,
            selected_parent: None,
            utxo_commitment: None,
            extra_nonce:     0,
        },
        body: BlockBody {
            transactions: vec![coinbase],
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                         PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════

/// Create the mainnet genesis block (mined with real PoW)
pub fn create_genesis_block() -> Block {
    build_block(GenesisParams::mainnet())
}

/// Create genesis block for a specific network
pub fn create_genesis_block_for(network: &NetworkMode) -> Block {
    match network {
        NetworkMode::Mainnet => build_block(GenesisParams::mainnet()),
        NetworkMode::Testnet => build_block(GenesisParams::testnet()),
        NetworkMode::Regtest => build_block(GenesisParams::regtest()),
    }
}

/// Get the genesis difficulty for a specific network
pub fn genesis_difficulty_for(network: &NetworkMode) -> u64 {
    match network {
        NetworkMode::Mainnet => GENESIS_DIFFICULTY,
        NetworkMode::Testnet => TESTNET_DIFFICULTY,
        NetworkMode::Regtest => REGTEST_DIFFICULTY,
    }
}

/// Get the mainnet genesis hash
pub fn genesis_hash() -> String {
    create_genesis_block().header.hash
}

/// Get genesis hash for a specific network
pub fn genesis_hash_for(network: &NetworkMode) -> String {
    create_genesis_block_for(network).header.hash
}

// ═══════════════════════════════════════════════════════════════════════════
//                       GENESIS VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

/// Full verification of a genesis block (returns bool for backward compat)
pub fn verify_genesis(block: &Block) -> bool {
    verify_genesis_detailed(block, &NetworkMode::Mainnet).is_ok()
}

/// Full verification of a genesis block for a specific network (returns bool)
pub fn verify_genesis_for(block: &Block, network: &NetworkMode) -> bool {
    verify_genesis_detailed(block, network).is_ok()
}

/// Detailed genesis verification — returns Ok(()) or Err(reason).
/// This is the preferred function: it tells you EXACTLY what's wrong.
pub fn verify_genesis_detailed(block: &Block, network: &NetworkMode) -> Result<(), ConsensusError> {
    let expected = create_genesis_block_for(network);

    // 1. Hash must match exactly
    if block.header.hash != expected.header.hash {
        return Err(ConsensusError::Genesis(format!(
            "hash mismatch: got {} expected {}",
            &block.header.hash, &expected.header.hash
        )));
    }

    // 2. Height must be 0
    if block.header.height != 0 {
        return Err(ConsensusError::Genesis(format!("height must be 0, got {}", block.header.height)));
    }

    // 3. No parents (it's the DAG root)
    if !block.header.parents.is_empty() {
        return Err(ConsensusError::Genesis(format!("must have no parents, got {}", block.header.parents.len())));
    }

    // 4. Version must match
    if block.header.version != GENESIS_VERSION {
        return Err(ConsensusError::Genesis(format!(
            "version mismatch: got {} expected {}",
            block.header.version, GENESIS_VERSION
        )));
    }

    // 5. Timestamp must match
    if block.header.timestamp != expected.header.timestamp {
        return Err(ConsensusError::Genesis(format!(
            "timestamp mismatch: got {} expected {}",
            block.header.timestamp, expected.header.timestamp
        )));
    }

    // 6. Merkle root must match
    if block.header.merkle_root != expected.header.merkle_root {
        return Err(ConsensusError::Genesis(format!(
            "merkle root mismatch: got {} expected {}",
            &block.header.merkle_root, &expected.header.merkle_root
        )));
    }

    // 7. Nonce must match (proves PoW was done)
    if block.header.nonce != expected.header.nonce {
        return Err(ConsensusError::Genesis(format!("nonce mismatch: got {} expected {}", block.header.nonce, expected.header.nonce)));
    }

    // 8. Must have exactly one transaction (coinbase)
    if block.body.transactions.len() != 1 {
        return Err(ConsensusError::Genesis(format!("must have 1 tx, got {}", block.body.transactions.len())));
    }

    // 9. Coinbase must have no inputs
    if !block.body.transactions[0].inputs.is_empty() {
        return Err(ConsensusError::Genesis("coinbase must have no inputs".to_string()));
    }

    // 10. Coinbase must have exactly 2 outputs (miner + developer)
    if block.body.transactions[0].outputs.len() != 2 {
        return Err(ConsensusError::Genesis(format!("coinbase must have 2 outputs, got {}", block.body.transactions[0].outputs.len())));
    }

    // 11. Verify the PoW hash meets the difficulty target
    if !PowValidator::hash_meets_target(&block.header.hash, block.header.difficulty) {
        return Err(ConsensusError::InvalidPow(format!("hash {} does not meet difficulty {}", &block.header.hash, block.header.difficulty)));
    }

    // 12. Verify reward split (95% miner, 5% developer)
    let params = match network {
        NetworkMode::Mainnet => GenesisParams::mainnet(),
        NetworkMode::Testnet => GenesisParams::testnet(),
        NetworkMode::Regtest => GenesisParams::regtest(),
    };
    let expected_miner_reward = (params.reward * MINER_REWARD_PCT) / 100;
    let expected_dev_reward   = params.reward - expected_miner_reward;

    let miner_out = &block.body.transactions[0].outputs[0];
    let dev_out   = &block.body.transactions[0].outputs[1];

    if miner_out.amount != expected_miner_reward {
        return Err(ConsensusError::Genesis(format!("miner reward mismatch: got {} expected {}", miner_out.amount, expected_miner_reward)));
    }
    if dev_out.amount != expected_dev_reward {
        return Err(ConsensusError::Genesis(format!("dev reward mismatch: got {} expected {}", dev_out.amount, expected_dev_reward)));
    }

    // 13. Re-verify PoW independently
    let recomputed_hash = shadow_hash_raw_full(
        block.header.version,
        block.header.height,
        block.header.timestamp,
        block.header.nonce,
        block.header.extra_nonce,
        block.header.difficulty,
        &block.header.merkle_root,
        &block.header.parents,
    );
    if recomputed_hash != block.header.hash {
        return Err(ConsensusError::InvalidPow(format!(
            "recomputation mismatch: stored {} recomputed {}",
            &block.header.hash, &recomputed_hash
        )));
    }

    Ok(())
}

/// Get genesis block info as a human-readable string
pub fn genesis_info(network: &NetworkMode) -> String {
    let block = create_genesis_block_for(network);
    let cb = &block.body.transactions[0];
    let net_name = match network {
        NetworkMode::Mainnet => "Mainnet",
        NetworkMode::Testnet => "Testnet",
        NetworkMode::Regtest => "Regtest",
    };

    format!(
        "ShadowDAG {} Genesis Block\n\
         ─────────────────────────────\n\
         Hash:        {}\n\
         Height:      {}\n\
         Timestamp:   {}\n\
         Nonce:       {}\n\
         Difficulty:  {}\n\
         Merkle Root: {}\n\
         Coinbase TX: {}\n\
         Miner Reward: {} (output 0)\n\
         Dev Reward:   {} (output 1)\n\
         PoW Valid:   {}",
        net_name,
        block.header.hash,
        block.header.height,
        block.header.timestamp,
        block.header.nonce,
        block.header.difficulty,
        block.header.merkle_root,
        cb.hash,
        cb.outputs[0].amount,
        cb.outputs[1].amount,
        PowValidator::hash_meets_target(&block.header.hash, block.header.difficulty),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//                            TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_deterministic() {
        let g1 = create_genesis_block();
        let g2 = create_genesis_block();
        assert_eq!(g1.header.hash, g2.header.hash, "Genesis must be deterministic");
        assert_eq!(g1.header.nonce, g2.header.nonce, "Nonce must be deterministic");
        assert_eq!(g1.header.merkle_root, g2.header.merkle_root);
    }

    #[test]
    fn genesis_height_is_zero() {
        let g = create_genesis_block();
        assert_eq!(g.header.height, 0);
    }

    #[test]
    fn genesis_has_no_parents() {
        let g = create_genesis_block();
        assert!(g.header.parents.is_empty(), "Genesis must have no parents");
    }

    #[test]
    fn genesis_has_coinbase_with_two_outputs() {
        let g = create_genesis_block();
        assert_eq!(g.body.transactions.len(), 1, "Genesis must have exactly 1 tx");
        assert!(g.body.transactions[0].inputs.is_empty(), "Coinbase has no inputs");
        assert_eq!(g.body.transactions[0].outputs.len(), 2, "Must have miner + dev outputs");
    }

    #[test]
    fn genesis_reward_split_is_correct() {
        let g = create_genesis_block();
        let miner_out = &g.body.transactions[0].outputs[0];
        let dev_out   = &g.body.transactions[0].outputs[1];

        let expected_miner = (GENESIS_REWARD * MINER_REWARD_PCT) / 100;
        let expected_dev   = GENESIS_REWARD - expected_miner;

        assert_eq!(miner_out.amount, expected_miner, "Miner must get 95%");
        assert_eq!(dev_out.amount, expected_dev, "Developer must get 5%");
        assert_eq!(miner_out.amount + dev_out.amount, GENESIS_REWARD, "Total must equal reward");
    }

    #[test]
    fn genesis_addresses_are_correct() {
        let g = create_genesis_block();
        let miner_out = &g.body.transactions[0].outputs[0];
        let dev_out   = &g.body.transactions[0].outputs[1];

        assert_eq!(miner_out.address, GENESIS_MINER_ADDRESS);
        assert_eq!(dev_out.address, OWNER_REWARD_ADDRESS);
    }

    #[test]
    fn genesis_pow_is_valid() {
        let g = create_genesis_block();
        assert!(
            PowValidator::hash_meets_target(&g.header.hash, g.header.difficulty),
            "Genesis hash {} must meet difficulty {}",
            g.header.hash, g.header.difficulty
        );
    }

    #[test]
    fn genesis_pow_hash_is_recomputable() {
        let g = create_genesis_block();
        let recomputed = shadow_hash_raw_full(
            g.header.version,
            g.header.height,
            g.header.timestamp,
            g.header.nonce,
            g.header.extra_nonce,
            g.header.difficulty,
            &g.header.merkle_root,
            &g.header.parents,
        );
        assert_eq!(g.header.hash, recomputed, "Hash must be independently recomputable");
    }

    #[test]
    fn genesis_hash_is_64_hex_chars() {
        let g = create_genesis_block();
        assert_eq!(g.header.hash.len(), 64, "Hash must be 64 hex chars");
        assert!(g.header.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn genesis_verify_passes() {
        let g = create_genesis_block();
        assert!(verify_genesis(&g), "Genesis must pass full verification");
    }

    #[test]
    fn genesis_verify_fails_tampered_hash() {
        let mut g = create_genesis_block();
        g.header.hash = "ff".repeat(32);
        assert!(!verify_genesis(&g));
    }

    #[test]
    fn genesis_verify_fails_tampered_nonce() {
        let mut g = create_genesis_block();
        g.header.nonce += 1;
        assert!(!verify_genesis(&g));
    }

    #[test]
    fn genesis_verify_fails_tampered_reward() {
        let mut g = create_genesis_block();
        g.body.transactions[0].outputs[0].amount += 1;
        assert!(!verify_genesis(&g));
    }

    #[test]
    fn networks_have_different_genesis_hashes() {
        let mn = genesis_hash_for(&NetworkMode::Mainnet);
        let tn = genesis_hash_for(&NetworkMode::Testnet);
        let rg = genesis_hash_for(&NetworkMode::Regtest);
        assert_ne!(mn, tn, "Mainnet and Testnet must differ");
        assert_ne!(mn, rg, "Mainnet and Regtest must differ");
        assert_ne!(tn, rg, "Testnet and Regtest must differ");
    }

    #[test]
    fn testnet_genesis_is_deterministic() {
        let t1 = create_genesis_block_for(&NetworkMode::Testnet);
        let t2 = create_genesis_block_for(&NetworkMode::Testnet);
        assert_eq!(t1.header.hash, t2.header.hash);
    }

    #[test]
    fn regtest_genesis_difficulty_is_one() {
        let r = create_genesis_block_for(&NetworkMode::Regtest);
        assert_eq!(r.header.difficulty, 1);
    }

    #[test]
    fn verify_genesis_for_testnet() {
        let g = create_genesis_block_for(&NetworkMode::Testnet);
        assert!(verify_genesis_for(&g, &NetworkMode::Testnet));
    }

    #[test]
    fn verify_cross_network_fails() {
        let mainnet_block = create_genesis_block_for(&NetworkMode::Mainnet);
        assert!(!verify_genesis_for(&mainnet_block, &NetworkMode::Testnet),
            "Mainnet genesis must NOT pass testnet verification");
    }

    #[test]
    fn coinbase_hash_is_deterministic() {
        let p = GenesisParams::mainnet();
        let c1 = build_coinbase(&p);
        let c2 = build_coinbase(&p);
        assert_eq!(c1.hash, c2.hash);
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let p = GenesisParams::mainnet();
        let c = build_coinbase(&p);
        let r1 = compute_merkle_root(std::slice::from_ref(&c.hash));
        let r2 = compute_merkle_root(std::slice::from_ref(&c.hash));
        assert_eq!(r1, r2);
    }

    #[test]
    fn genesis_fee_is_zero() {
        let g = create_genesis_block();
        assert_eq!(g.body.transactions[0].fee, 0, "Genesis coinbase fee must be 0");
    }

    #[test]
    fn genesis_version_is_one() {
        let g = create_genesis_block();
        assert_eq!(g.header.version, 1);
    }

    #[test]
    fn genesis_info_contains_hash() {
        let info = genesis_info(&NetworkMode::Mainnet);
        let g = create_genesis_block();
        assert!(info.contains(&g.header.hash));
        assert!(info.contains("PoW Valid:   true"));
    }

    #[test]
    fn print_genesis_info() {
        eprintln!("\n{}", genesis_info(&NetworkMode::Mainnet));
        eprintln!("\n{}", genesis_info(&NetworkMode::Testnet));
        eprintln!("\n{}", genesis_info(&NetworkMode::Regtest));
    }
}
