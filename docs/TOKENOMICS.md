# ShadowDAG Tokenomics

This documents the economic parameters **as implemented in code** (with exact
source references), followed by items the team should review/decide before
mainnet. Numbers here are read from `config/consensus/` and `config/genesis/` —
not assumptions.

## Unit & supply

| Parameter | Value | Source |
|---|---|---|
| Base unit | 1 SDAG = 100,000,000 satoshis (1e8) | genesis (`GENESIS_REWARD` = 1e9 sat = 10 SDAG) |
| **Max supply** | **21,000,000,000 SDAG** (2.1 × 10¹⁸ sat) | `ConsensusParams::MAX_SUPPLY` |
| Premine | **None** — genesis is a standard coinbase, no special allocation | `config/genesis/genesis.rs` |

> Note: this is **21 billion** SDAG (≈1000× Bitcoin's 21M coin count). A design choice.

## Block production

| Parameter | Value | Source |
|---|---|---|
| Block time target | 1 second | `ConsensusParams::BLOCK_TIME` |
| Blocks per second | 10 (BlockDAG produces multiple blocks/sec) | `ConsensusParams::BLOCKS_PER_SECOND` / `DEFAULT_BPS` |
| Coinbase maturity | 1,000 blocks (~100 s at 10 BPS) | `ConsensusParams::COINBASE_MATURITY` |

## Emission schedule (smooth decay, not abrupt halving)

Implemented in `config/consensus/emission_schedule.rs`:

- **Initial reward:** 10 SDAG/block (`INITIAL_REWARD` = 1e9 sat).
- **Curve:** `reward = 10 SDAG × 0.9962^step`, where
  `step = height / REDUCTION_INTERVAL`.
- **Step length:** `REDUCTION_INTERVAL_SECS (2,592,000 s = 30 days) × BPS` — i.e.
  **time-based** (≈30 days per step regardless of BPS). At 10 BPS that is
  25,920,000 blocks per step.
- **Decay:** −0.38% per 30-day step (`DECAY = 9962/10000`). Reward **halves about
  every ~5.5 years** (~182 steps), versus Bitcoin's discrete 4-year 50% drop.
- **Floor:** emission stops when the per-block reward falls below `MIN_REWARD`
  (1 sat) or `MAX_STEPS` (12,000) is reached.
- **Hard cap:** `block_reward_at_bps` clips the reward so cumulative emission can
  never exceed `MAX_SUPPLY` (asymptotic convergence to 21B SDAG).

Rationale (from the code comments): smooth decay avoids the miner-exodus / price
shock of discrete halvings and suits 1-second DAG blocks.

## Reward split

| Recipient | Share | Source |
|---|---|---|
| Miner | **95%** | `MINER_REWARD_PCT` |
| Developer / owner fund | **5%** | `DEV_REWARD_PCT`, paid to `OWNER_REWARD_ADDRESS` (hardcoded) |

The split is applied to every block reward (`build_coinbase`). The dev share
therefore continues for as long as block rewards are emitted.

## Fees

- **Minimum relay fee:** 100 sat (`MempoolConfig::MIN_RELAY_FEE`).
- Fee-rate prioritization in the mempool (milli-sat/byte).
- After emission ends, miners earn from transaction + smart-contract gas fees
  (the design assumes contract activity sustains mining long-term).

## ⚠️ Review / decisions before mainnet **[DECIDE]**

These are economic-policy choices that code alone cannot validate — review them
deliberately:

1. **Front-loaded emission.** At 10 BPS × 10 SDAG, initial issuance is ~100 SDAG/s
   ≈ ~3.15B SDAG/year before decay — roughly 15% of max supply in year one, and
   the 21B cap is approached within a relatively small number of years. Confirm
   this issuance curve is intended (it is much faster than Bitcoin's).
2. **Perpetual 5% dev fund** to a single hardcoded address
   (`SD009189b8…`). Decide: key custody/governance, whether it should taper or
   sunset, and on-chain transparency of its spending.
3. **21 billion supply** (vs 21M). Confirm the unit/supply scale and its messaging.
4. **Fee market.** Only a flat `MIN_RELAY_FEE` exists today — no dynamic base-fee /
   burn mechanism. Decide whether a fee market or fee-burn (deflationary pressure)
   is desired, especially given the front-loaded emission.
5. **Long-term security budget.** Once emission tapers, mining security depends on
   fee revenue. Model whether projected fee volume sustains adequate hashrate.

## Verification

The emission constants and split are covered by tests in
`config/consensus/emission_schedule.rs` and `config/genesis/genesis.rs`
(`genesis_reward_split_is_correct`, emission monotonicity / cap tests).
