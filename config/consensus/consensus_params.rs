// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::genesis::genesis::{
    genesis_hash, GENESIS_TIMESTAMP, GENESIS_DIFFICULTY,
    OWNER_REWARD_ADDRESS as DEV_ADDR,
    GENESIS_REWARD, MINER_REWARD_PCT, DEV_REWARD_PCT,
};

use crate::engine::dag::core::bps_engine::BpsParams;

pub struct ConsensusParams;

impl ConsensusParams {
    // ── Chain Identity ─────────────────────────────────────────────────────
    pub const CHAIN_ID:   u32          = 0xDA0C_0001;
    pub const CHAIN_NAME: &'static str = "shadowdag-mainnet";
    pub const TESTNET_CHAIN_ID: u32    = 0xDA0C_0002;
    pub const REGTEST_CHAIN_ID: u32    = 0xDA0C_0003;

    // ── Economics ──────────────────────────────────────────────────────────
    /// 21 billion SDAG in satoshis (1 SDAG = 100_000_000 satoshis)
    pub const MAX_SUPPLY:          u64 = 21_000_000_000 * 100_000_000; // 2.1 * 10^18 satoshis
    pub const BLOCK_REWARD:        u64 = GENESIS_REWARD;   // 10 SDAG per block
    pub const BLOCK_TIME:          u64 = 1;                // 1 second target
    pub const MINER_PERCENT:       u64 = MINER_REWARD_PCT; // 95% to miners
    pub const DEVELOPER_PERCENT:   u64 = DEV_REWARD_PCT;   // 5% to developer
    /// Coinbase maturity in blocks. At DEFAULT_BPS this = 100 seconds.
    /// Scales with BPS to maintain ~100 seconds minimum maturity time.
    pub const COINBASE_MATURITY:   u64 = 1_000;            // 1000 blocks = 100 sec at DEFAULT_BPS

    // ── Developer Reward Wallet ────────────────────────────────────────────
    pub const OWNER_REWARD_ADDRESS: &'static str = DEV_ADDR;

    // ── Genesis ────────────────────────────────────────────────────────────
    pub fn genesis_hash() -> String { genesis_hash() }
    pub const GENESIS_TIMESTAMP:  u64 = GENESIS_TIMESTAMP;
    pub const GENESIS_DIFFICULTY: u64 = GENESIS_DIFFICULTY;

    // ── Difficulty ─────────────────────────────────────────────────────────
    pub const DIFFICULTY_WINDOW: usize = 20;
    pub const MIN_DIFFICULTY:    u64   = 1;
    pub const MAX_DIFFICULTY:    u64   = u64::MAX / 2; // Unified with engine/difficulty

    // ── DAG / GHOSTDAG (defaults for DEFAULT_BPS — use DynamicConsensusParams for runtime) ──
    pub const GHOSTDAG_K:        usize = 180;  // K=18*BPS for DEFAULT_BPS
    pub const MAX_PARENTS:       usize = 80;   // 8*BPS for DEFAULT_BPS
    pub const MAX_ANTICONE_WALK: usize = 16_384;
    pub const BLOCKS_PER_SECOND: u64   = 10;

    // ── Block Limits ───────────────────────────────────────────────────────
    pub const MAX_BLOCK_SIZE:    usize = 2 * 1024 * 1024; // 2 MB
    pub const MAX_BLOCK_TXS:     usize = 10_000;
    pub const MAX_TX_SIZE:       usize = 100 * 1024;      // 100 KB
    pub const MAX_MEMPOOL_SIZE:  usize =
        crate::config::consensus::mempool_config::MempoolConfig::MAX_MEMPOOL_SIZE;
    /// Minimum transaction fee in satoshis.
    /// Set to 100 to ensure sustainable mining economics when block rewards decline.
    /// At 10K tx/block this generates 1M satoshis (0.01 SDAG) per block in fees.
    pub const MIN_FEE:           u64   =
        crate::config::consensus::mempool_config::MempoolConfig::MIN_RELAY_FEE;
    pub const DUST_LIMIT:        u64   = 1_000;

    // ── Network (mainnet defaults — testnet/regtest use NetworkMode::p2p_port/rpc_port) ──
    pub const DEFAULT_P2P_PORT:  u16   = 9333;
    pub const DEFAULT_RPC_PORT:  u16   = 9332;
    pub const MAX_PEERS:         usize = 125;

    // ── Feature Flags ────────────────────────────────────────────────────
    /// Privacy layer: CLSAG ring signatures + Pedersen commitments + Dandelion++.
    /// Integrated into the consensus protocol for native transaction privacy.
    pub const PRIVACY_ENABLED:       bool = true;

    /// Smart contracts: ShadowVM with U256 stack, 90+ opcodes, and gas metering.
    /// Full EVM-compatible execution environment with ASIC-resistant PoW security.
    pub const SMART_CONTRACTS_ENABLED: bool = true;

    // ── VM Versioning ─────────────────────────────────────────────────────
    /// Active VM version for this chain.
    /// Contracts deployed with a different vm_version are rejected.
    /// Future upgrades (v2, v3) will use fork-height activation.
    pub const VM_VERSION: u8 = 1;

    /// Block height at which VM v1 activates (genesis for v1).
    pub const VM_V1_ACTIVATION_HEIGHT: u64 = 0;
}

/// Runtime-configurable consensus parameters derived from BPS engine.
/// Use this instead of ConsensusParams constants when BPS may vary.
pub struct DynamicConsensusParams {
    params: BpsParams,
}

impl DynamicConsensusParams {
    pub fn new(bps: u32) -> Self {
        Self { params: BpsParams::for_bps(bps) }
    }

    pub fn default_10bps() -> Self { Self::new(10) }

    pub fn max_parents(&self) -> usize { self.params.max_parents }
    pub fn ghostdag_k(&self) -> usize { self.params.ghostdag_k }
    pub fn max_block_size(&self) -> usize { self.params.max_block_size }
    pub fn max_block_txs(&self) -> usize { self.params.max_block_txs }
    pub fn block_interval_ms(&self) -> u64 { self.params.block_interval_ms }
    pub fn bps(&self) -> u32 { self.params.bps }
    pub fn max_tps(&self) -> u64 { self.params.max_tps }
    pub fn pruning_depth_sec(&self) -> u64 { self.params.pruning_depth_sec }
}
