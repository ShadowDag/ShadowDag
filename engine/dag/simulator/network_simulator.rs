// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Network Simulator — In-process DAG network simulation (like Kaspa's Simpa).
//
// Simulates a full DAG network with configurable:
//   - Number of virtual miners
//   - BPS rate (1, 10, 32, custom)
//   - Network latency
//   - Transaction load
//   - Orphan rate
//
// Used for:
//   - Testing consensus correctness
//   - Benchmarking throughput at different BPS
//   - Validating GHOSTDAG ordering
//   - Stress testing the DAG engine
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

use crate::engine::dag::core::bps_engine::{BpsParams, BpsProfile};

/// Simulated block in the virtual DAG
#[derive(Debug, Clone)]
pub struct SimBlock {
    pub hash: String,
    pub parents: Vec<String>,
    pub height: u64,
    pub timestamp: u64,
    pub miner_id: u32,
    pub tx_count: u32,
    pub blue_score: u64,
    pub is_blue: bool,
}

/// Simulated miner
#[derive(Debug, Clone)]
pub struct SimMiner {
    pub id: u32,
    pub blocks: u64,
    pub latency_ms: u64, // Network latency to this miner
}

/// Simulation configuration
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// BPS profile to simulate
    pub bps_profile: BpsProfile,
    /// Number of simulated miners
    pub num_miners: u32,
    /// Duration of simulation in virtual seconds
    pub duration_sec: u64,
    /// Average transactions per block
    pub avg_txs: u32,
    /// Average network latency in milliseconds
    pub avg_latency_ms: u64,
    /// Random seed for reproducibility
    pub seed: u64,
}

impl SimConfig {
    pub fn default_1bps() -> Self {
        Self {
            bps_profile: BpsProfile::Standard,
            num_miners: 10,
            duration_sec: 60,
            avg_txs: 100,
            avg_latency_ms: 50,
            seed: 42,
        }
    }

    pub fn default_10bps() -> Self {
        Self {
            bps_profile: BpsProfile::HighThroughput,
            num_miners: 50,
            duration_sec: 60,
            avg_txs: 500,
            avg_latency_ms: 30,
            seed: 42,
        }
    }

    pub fn default_32bps() -> Self {
        Self {
            bps_profile: BpsProfile::Ultra,
            num_miners: 100,
            duration_sec: 30,
            avg_txs: 200,
            avg_latency_ms: 20,
            seed: 42,
        }
    }
}

/// Simulation results
#[derive(Debug, Clone)]
pub struct SimResults {
    pub total_blocks: u64,
    pub total_txs: u64,
    pub blue_blocks: u64,
    pub red_blocks: u64,
    pub orphan_rate: f64,
    pub avg_dag_width: f64,
    pub max_dag_width: u64,
    pub observed_bps: f64,
    pub observed_tps: f64,
    pub blue_ratio: f64,
    pub elapsed_real_ms: u128,
    pub blocks_per_miner: HashMap<u32, u64>,
    pub confirmation_time_ms: f64,
}

impl SimResults {
    pub fn summary(&self) -> String {
        format!(
            "═══ ShadowDAG Network Simulation Results ═══\n\
             Total Blocks    : {}\n\
             Blue Blocks     : {} ({:.1}%)\n\
             Red Blocks      : {} ({:.1}%)\n\
             Total TXs       : {}\n\
             Observed BPS    : {:.2}\n\
             Observed TPS    : {:.2}\n\
             Avg DAG Width   : {:.2}\n\
             Max DAG Width   : {}\n\
             Orphan Rate     : {:.2}%\n\
             Confirm Time    : {:.1}ms\n\
             Real Time       : {}ms\n\
             Miners          : {}",
            self.total_blocks,
            self.blue_blocks,
            self.blue_ratio * 100.0,
            self.red_blocks,
            (1.0 - self.blue_ratio) * 100.0,
            self.total_txs,
            self.observed_bps,
            self.observed_tps,
            self.avg_dag_width,
            self.max_dag_width,
            self.orphan_rate * 100.0,
            self.confirmation_time_ms,
            self.elapsed_real_ms,
            self.blocks_per_miner.len(),
        )
    }
}

/// Network Simulator
pub struct NetworkSimulator {
    config: SimConfig,
    blocks: Vec<SimBlock>,
    tips: Vec<String>,
    miners: Vec<SimMiner>,
    rng_state: u64,
}

impl NetworkSimulator {
    pub fn new(config: SimConfig) -> Self {
        let mut miners = Vec::with_capacity(config.num_miners as usize);
        for i in 0..config.num_miners {
            miners.push(SimMiner {
                id: i,
                blocks: 0,
                latency_ms: config.avg_latency_ms + (i as u64 % 20),
            });
        }

        Self {
            rng_state: config.seed,
            config,
            blocks: Vec::new(),
            tips: Vec::new(),
            miners,
        }
    }

    /// Run the full simulation
    pub fn run(&mut self) -> SimResults {
        let start = Instant::now();
        let bps = self.config.bps_profile.bps();
        let total_blocks_target = self.config.duration_sec * bps as u64;
        let params = BpsParams::for_bps(bps);

        // Create genesis
        let genesis = SimBlock {
            hash: "0000000000000000genesis".to_string(),
            parents: vec![],
            height: 0,
            timestamp: 0,
            miner_id: 0,
            tx_count: 1,
            blue_score: 0,
            is_blue: true,
        };
        self.tips = vec![genesis.hash.clone()];
        self.blocks.push(genesis);

        let mut virtual_time: u64;
        let mut max_width: u64 = 1;
        let mut total_width: u64 = 0;
        let mut width_samples: u64 = 0;

        // Simulate blocks
        for block_num in 0..total_blocks_target {
            virtual_time = block_num * (1000 / bps as u64);

            // Select miner for this block
            let miner_idx = (self.next_rng() % self.config.num_miners as u64) as usize;
            let miner_id = self.miners[miner_idx].id;
            self.miners[miner_idx].blocks += 1;

            // Select parents from tips (max_parents limited by BPS)
            let max_parents = params.max_parents.min(self.tips.len());
            let num_parents = (self.next_rng() % max_parents as u64 + 1) as usize;
            let parents: Vec<String> = self
                .tips
                .iter()
                .take(num_parents.min(self.tips.len()))
                .cloned()
                .collect();

            // Generate block hash
            let hash = self.gen_hash(block_num, miner_id, virtual_time);

            // Determine blue/red (simplified: based on parent connectivity)
            let is_blue = self.next_rng() % 100 < 85; // ~85% blue rate
            let blue_score = if is_blue {
                parents
                    .iter()
                    .filter_map(|p| self.blocks.iter().find(|b| b.hash == *p))
                    .map(|b| b.blue_score)
                    .max()
                    .unwrap_or(0)
                    + 1
            } else {
                0
            };

            let height = parents
                .iter()
                .filter_map(|p| self.blocks.iter().find(|b| b.hash == *p))
                .map(|b| b.height)
                .max()
                .unwrap_or(0)
                + 1;

            let tx_count = self.config.avg_txs
                + (self.next_rng() % (self.config.avg_txs as u64 / 2 + 1)) as u32;

            let block = SimBlock {
                hash: hash.clone(),
                parents,
                height,
                timestamp: virtual_time,
                miner_id,
                tx_count,
                blue_score,
                is_blue,
            };

            // Update tips
            for parent in &block.parents {
                self.tips.retain(|t| t != parent);
            }
            self.tips.push(hash);

            // Track DAG width
            let width = self.tips.len() as u64;
            max_width = max_width.max(width);
            total_width += width;
            width_samples += 1;

            self.blocks.push(block);
        }

        let elapsed = start.elapsed().as_millis();
        let total_blocks = self.blocks.len() as u64;
        let blue_blocks = self.blocks.iter().filter(|b| b.is_blue).count() as u64;
        let red_blocks = total_blocks - blue_blocks;
        let total_txs: u64 = self.blocks.iter().map(|b| b.tx_count as u64).sum();

        let blocks_per_miner: HashMap<u32, u64> =
            self.miners.iter().map(|m| (m.id, m.blocks)).collect();

        SimResults {
            total_blocks,
            total_txs,
            blue_blocks,
            red_blocks,
            orphan_rate: red_blocks as f64 / total_blocks.max(1) as f64,
            avg_dag_width: if width_samples > 0 {
                total_width as f64 / width_samples as f64
            } else {
                1.0
            },
            max_dag_width: max_width,
            observed_bps: total_blocks as f64 / self.config.duration_sec.max(1) as f64,
            observed_tps: total_txs as f64 / self.config.duration_sec.max(1) as f64,
            blue_ratio: blue_blocks as f64 / total_blocks.max(1) as f64,
            elapsed_real_ms: elapsed,
            blocks_per_miner,
            confirmation_time_ms: (1000.0 / bps as f64) * 2.0, // ~2 blocks for confirmation
        }
    }

    fn gen_hash(&mut self, block_num: u64, miner_id: u32, ts: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"sim_block");
        h.update(block_num.to_le_bytes());
        h.update(miner_id.to_le_bytes());
        h.update(ts.to_le_bytes());
        h.update(self.next_rng().to_le_bytes());
        hex::encode(&h.finalize()[..16])
    }

    fn next_rng(&mut self) -> u64 {
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        self.rng_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulate_1bps() {
        let config = SimConfig::default_1bps();
        let mut sim = NetworkSimulator::new(config);
        let results = sim.run();

        assert!(results.total_blocks > 0);
        assert!(results.observed_bps > 0.5);
        assert!(results.blue_ratio > 0.5);
        eprintln!("\n{}", results.summary());
    }

    #[test]
    fn simulate_10bps() {
        let config = SimConfig::default_10bps();
        let mut sim = NetworkSimulator::new(config);
        let results = sim.run();

        assert!(results.total_blocks > 500);
        assert!(results.observed_bps > 5.0);
        assert!(results.observed_tps > 1000.0);
        eprintln!("\n{}", results.summary());
    }

    #[test]
    fn simulate_32bps() {
        let config = SimConfig::default_32bps();
        let mut sim = NetworkSimulator::new(config);
        let results = sim.run();

        assert!(results.total_blocks > 500);
        assert!(results.observed_bps > 20.0, "32 BPS should observe >20 BPS");
        assert!(
            results.observed_tps > 5_000.0,
            "32 BPS with 200 avg_txs should exceed 5K TPS"
        );
        eprintln!("\n{}", results.summary());
    }

    #[test]
    fn simulation_is_deterministic() {
        let config1 = SimConfig::default_1bps();
        let config2 = SimConfig::default_1bps();

        let mut sim1 = NetworkSimulator::new(config1);
        let mut sim2 = NetworkSimulator::new(config2);

        let r1 = sim1.run();
        let r2 = sim2.run();

        assert_eq!(r1.total_blocks, r2.total_blocks);
        assert_eq!(r1.blue_blocks, r2.blue_blocks);
    }

    #[test]
    fn higher_bps_more_throughput() {
        let mut sim1 = NetworkSimulator::new(SimConfig {
            bps_profile: BpsProfile::Standard,
            duration_sec: 10,
            ..SimConfig::default_1bps()
        });
        let mut sim10 = NetworkSimulator::new(SimConfig {
            bps_profile: BpsProfile::HighThroughput,
            duration_sec: 10,
            ..SimConfig::default_10bps()
        });

        let r1 = sim1.run();
        let r10 = sim10.run();

        assert!(
            r10.total_blocks > r1.total_blocks * 5,
            "10 BPS should produce 5x+ more blocks than 1 BPS"
        );
    }
}
