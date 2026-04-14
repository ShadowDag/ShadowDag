// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Centralized mempool & economic configuration.
//
// SINGLE SOURCE OF TRUTH for all pool sizes, fee thresholds, eviction
// parameters, RBF rules, reorg limits, and base-fee settings.
//
// Every module MUST import from here instead of defining its own constants.
// Duplicated constants across modules caused conflicting values:
//   - MAX_MEMPOOL_SIZE was 200K in mempool.rs, 50K in eviction.rs and dos_protection.rs
//   - MIN_RELAY_FEE was 1 in mempool.rs, 100 in consensus_params.rs
//   - EVICTION_BATCH_SIZE was 128 in mempool.rs, 500 in eviction.rs
// ═══════════════════════════════════════════════════════════════════════════

/// Centralized configuration for all mempool, fee, eviction, RBF, orphan
/// pool, base-fee, and reorg-protection parameters.
///
/// Use `MempoolConfig::default()` for mainnet defaults, or construct a
/// custom instance for testnet / regtest / benchmarks.
pub struct MempoolConfig {
    // ── Pool Limits ───────────────────────────────────────────────────────
    /// Maximum number of transactions the mempool will hold.
    /// Compromise between 200K (mempool.rs) and 50K (eviction / DoS).
    /// 100K supports DEFAULT_BPS x 10K tx/block with a 1-second buffer.
    pub max_mempool_size: usize,

    /// Maximum total byte size of the mempool (300 MB).
    /// 500 MB was too aggressive for small nodes; 300 MB is sufficient
    /// for 100K transactions averaging ~2 KB each with headroom.
    pub max_mempool_bytes: usize,

    /// Maximum byte size of a single transaction (100 KB).
    pub max_tx_byte_size: usize,

    /// Maximum number of transactions per block.
    /// Aligned with `ConsensusParams::MAX_BLOCK_TXS` and BPS engine.
    pub max_block_tx_count: usize,

    // ── Fee Thresholds ────────────────────────────────────────────────────
    /// Minimum relay fee in satoshis.
    /// Aligned with `ConsensusParams::MIN_FEE` (100 satoshis) for
    /// consistency. The old value of 1 was too permissive.
    pub min_relay_fee: u64,

    /// Minimum fee rate in satoshis per byte.
    /// 0.5 sat/byte was too permissive; 1.0 prevents dust-level spam.
    pub min_fee_rate: f64,

    // ── Eviction Parameters ───────────────────────────────────────────────
    /// Number of transactions evicted in a single batch.
    /// Compromise between 128 (mempool.rs) and 500 (eviction.rs).
    pub eviction_batch_size: usize,

    /// Maximum age of a mempool transaction before it is evicted (seconds).
    /// 72 hours = 259_200 seconds.
    pub max_mempool_tx_age_secs: u64,

    // ── RBF (Replace-By-Fee) Parameters ───────────────────────────────────
    /// Minimum additional fee (in satoshis) a replacement tx must pay
    /// over the original to be accepted.
    pub min_fee_bump: u64,

    /// Maximum depth of the replacement chain (how many ancestors can be
    /// replaced in a single RBF operation).
    pub max_replacement_depth: usize,

    /// Maximum number of transactions that can be evicted by a single
    /// RBF replacement.
    pub max_rbf_evictions: usize,

    // ── Orphan Pool ───────────────────────────────────────────────────────
    /// Maximum number of orphan transactions held pending parent resolution.
    pub max_orphan_pool_size: usize,

    /// Maximum age of an orphan transaction before it is discarded (seconds).
    pub max_orphan_age_secs: u64,

    // ── Base Fee / EIP-1559 Style ─────────────────────────────────────────
    /// Target utilization percentage of the mempool / block space.
    /// When utilization exceeds this, the base fee rises.
    pub target_utilization_pct: u64,

    /// Maximum percentage the base fee can change between consecutive blocks.
    pub max_fee_change_pct: u64,

    /// Floor for the base fee (satoshis). The base fee never drops below this.
    pub min_base_fee: u64,

    /// Ceiling for the base fee (satoshis). Prevents runaway fee spikes.
    pub max_base_fee: u64,

    // ── Reorg Protection ──────────────────────────────────────────────────
    /// Maximum number of blocks the node will reorganize.
    /// Beyond this depth, blocks are considered permanently settled.
    pub max_reorg_depth: u64,

    /// Number of confirmations after which a block is considered final.
    /// Used for exchange crediting, checkpoint selection, etc.
    pub finality_depth: u64,
}

impl MempoolConfig {
    // ════════════════════════════════════════════════════════════════════════
    //  Associated constants — for backward compatibility and static usage
    // ════════════════════════════════════════════════════════════════════════

    // ── Pool Limits ───────────────────────────────────────────────────────
    pub const MAX_MEMPOOL_SIZE: usize = 100_000;
    pub const MAX_MEMPOOL_BYTES: usize = 300 * 1024 * 1024; // 300 MB
    pub const MAX_TX_BYTE_SIZE: usize = 100_000;
    pub const MAX_BLOCK_TX_COUNT: usize = 10_000;

    // ── Fee Thresholds ────────────────────────────────────────────────────
    pub const MIN_RELAY_FEE: u64 = 100;
    pub const MIN_FEE_RATE: f64 = 1.0;

    // ── Eviction Parameters ───────────────────────────────────────────────
    pub const EVICTION_BATCH_SIZE: usize = 256;
    pub const MAX_MEMPOOL_TX_AGE_SECS: u64 = 72 * 60 * 60; // 259_200 seconds

    // ── RBF Parameters ────────────────────────────────────────────────────
    pub const MIN_FEE_BUMP: u64 = 1_000;
    pub const MAX_REPLACEMENT_DEPTH: usize = 25;
    pub const MAX_RBF_EVICTIONS: usize = 100;

    // ── Orphan Pool ───────────────────────────────────────────────────────
    pub const MAX_ORPHAN_POOL_SIZE: usize = 1_000;
    pub const MAX_ORPHAN_AGE_SECS: u64 = 3_600; // 1 hour

    // ── Base Fee / EIP-1559 ───────────────────────────────────────────────
    pub const TARGET_UTILIZATION_PCT: u64 = 50;
    pub const MAX_FEE_CHANGE_PCT: u64 = 12;
    pub const MIN_BASE_FEE: u64 = 1;
    pub const MAX_BASE_FEE: u64 = 1_000_000_000;

    // ── Reorg Protection ──────────────────────────────────────────────────
    pub const MAX_REORG_DEPTH: u64 = 1_000;
    pub const FINALITY_DEPTH: u64 = 200;

    // ════════════════════════════════════════════════════════════════════════
    //  Constructor — returns mainnet defaults
    // ════════════════════════════════════════════════════════════════════════

    /// Returns a `MempoolConfig` populated with the canonical mainnet
    /// defaults. Every value matches the associated `pub const` above.
    pub const fn default() -> Self {
        Self {
            // Pool Limits
            max_mempool_size: Self::MAX_MEMPOOL_SIZE,
            max_mempool_bytes: Self::MAX_MEMPOOL_BYTES,
            max_tx_byte_size: Self::MAX_TX_BYTE_SIZE,
            max_block_tx_count: Self::MAX_BLOCK_TX_COUNT,

            // Fee Thresholds
            min_relay_fee: Self::MIN_RELAY_FEE,
            min_fee_rate: Self::MIN_FEE_RATE,

            // Eviction
            eviction_batch_size: Self::EVICTION_BATCH_SIZE,
            max_mempool_tx_age_secs: Self::MAX_MEMPOOL_TX_AGE_SECS,

            // RBF
            min_fee_bump: Self::MIN_FEE_BUMP,
            max_replacement_depth: Self::MAX_REPLACEMENT_DEPTH,
            max_rbf_evictions: Self::MAX_RBF_EVICTIONS,

            // Orphan Pool
            max_orphan_pool_size: Self::MAX_ORPHAN_POOL_SIZE,
            max_orphan_age_secs: Self::MAX_ORPHAN_AGE_SECS,

            // Base Fee / EIP-1559
            target_utilization_pct: Self::TARGET_UTILIZATION_PCT,
            max_fee_change_pct: Self::MAX_FEE_CHANGE_PCT,
            min_base_fee: Self::MIN_BASE_FEE,
            max_base_fee: Self::MAX_BASE_FEE,

            // Reorg Protection
            max_reorg_depth: Self::MAX_REORG_DEPTH,
            finality_depth: Self::FINALITY_DEPTH,
        }
    }
}
