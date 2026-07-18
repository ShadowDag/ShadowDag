// â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
//                           S H A D O W D A G
//                     آ© ShadowDAG Project â€” All Rights Reserved
// â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
//
// shadowdag-miner â€” Multi-threaded mining binary with RPC integration
//
// Usage:
//   shadowdag-miner --address=SD1your...       # Mine to address
//   shadowdag-miner --threads=8                 # Set thread count
//   shadowdag-miner --rpc=127.0.0.1:19332       # RPC address
//   shadowdag-miner --network=testnet           # Mine on testnet
//   shadowdag-miner --gpu [--gpu-batch=8192]     # GPU mining (needs the
//                                                # 'gpu-opencl' build feature)
// â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

use sha2::{Digest, Sha256};
use shadowdag::config::consensus::consensus_params::ConsensusParams;
use shadowdag::config::consensus::emission_schedule::EmissionSchedule;
use shadowdag::config::genesis::genesis::{
    create_genesis_block_for, REGTEST_DEV_ADDRESS, TESTNET_DEV_ADDRESS,
};
use shadowdag::config::node::node_config::NetworkMode;
use shadowdag::domain::block::block::Block;
use shadowdag::domain::block::block_body::BlockBody;
use shadowdag::domain::block::block_header::BlockHeader;
use shadowdag::domain::block::merkle_tree::MerkleTree;
use shadowdag::domain::transaction::transaction::{Transaction, TxOutput, TxType};
use shadowdag::engine::mining::algorithms::shadowhash::{meets_difficulty, shadow_hash_raw_full};
use shadowdag::engine::mining::algorithms::umbrahash;
use shadowdag::engine::mining::pow::pow_validator::PowValidator;
use shadowdag::errors::NodeError;
use shadowdag::{slog_error, slog_fatal, slog_info, slog_warn};
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default)]
struct RpcAuthConfig {
    bearer_token: Option<String>,
    username: String,
    password: Option<String>,
}

fn main() {
    shadowdag::telemetry::logging::structured::init();
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_help();
        return;
    }
    if has_flag(&args, "--version") || has_flag(&args, "-v") {
        println!("ShadowDAG Miner v1.0.0");
        return;
    }

    if let Err(e) = run_miner(&args) {
        slog_fatal!("miner", "startup_failed", error => &e);
        eprintln!("[miner] Run 'shadowdag-miner --help' for usage information.");
        std::process::exit(1);
    }
}

fn run_miner(args: &[String]) -> Result<(), NodeError> {
    // Parse flags
    let miner_address = match parse_flag_opt(args, "--address") {
        Ok(Some(addr)) => addr,
        Ok(None) => {
            eprintln!("ERROR: --address is required. Mining rewards need a destination.");
            eprintln!("Usage: shadowdag-miner --address=SD1your_address_here");
            return Err(NodeError::Init("--address is required".into()));
        }
        Err(msg) => {
            eprintln!("Error: {}", msg);
            return Err(NodeError::Init(msg));
        }
    };
    let network_str = parse_flag(args, "--network", "mainnet");
    let network: NetworkMode = network_str.parse().map_err(|_| {
        NodeError::Init(format!(
            "invalid --network '{}'. Use: mainnet, testnet, or regtest",
            network_str
        ))
    })?;
    let default_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let threads: usize = parse_flag(args, "--threads", &default_threads.to_string())
        .parse()
        .unwrap_or(4)
        .clamp(1, 256);

    // GPU mining (real OpenCL ShadowHash). Only active if this binary was built
    // with `--features gpu-opencl` AND `--gpu` is passed.
    let use_gpu = args.iter().any(|a| a == "--gpu");
    #[cfg(feature = "gpu-opencl")]
    let gpu_batch: usize = parse_flag(args, "--gpu-batch", "8192")
        .parse()
        .unwrap_or(8192)
        .clamp(256, 1_000_000);
    #[cfg(not(feature = "gpu-opencl"))]
    if use_gpu {
        eprintln!("[miner] --gpu requested but this binary was built WITHOUT the 'gpu-opencl' feature.");
        eprintln!("[miner] Rebuild: cargo build --release --features gpu-opencl --bin shadowdag-miner");
        eprintln!("[miner] Falling back to CPU mining.");
    }

    // UmbraHash PoW mode (memory-hard, version-gated). Opt-in via --pow=umbra;
    // default stays ShadowHash so existing chains and tests are unaffected. In
    // this mode the miner produces version-UMBRA_POW_VERSION blocks and the node
    // validates them via the UmbraHash path.
    let umbra_flag = parse_flag(args, "--pow", "shadow").eq_ignore_ascii_case("umbra");
    // Miner<->verifier PARITY: on any network where the UmbraHash fork is
    // scheduled (mainnet), UmbraHash is MANDATORY for every mined block. Force it
    // regardless of --pow, else the miner would produce legacy v2 blocks that
    // consensus rejects at height >= 1 (a liveness halt). Testnet/Regtest are
    // unscheduled and keep the flag-based opt-in. This startup-time force is valid
    // because mainnet activates at height 1 (ALL mined blocks are UmbraHash); a
    // mid-chain testnet activation would instead require per-height version switching.
    let umbra_forced = umbrahash::umbra_activation_height(&network).is_some();
    let umbra_mode = umbra_flag || umbra_forced;
    let block_version: u32 = if umbra_mode {
        umbrahash::UMBRA_POW_VERSION
    } else {
        2 // ms-timestamp era (ShadowHash)
    };
    if umbra_forced && !umbra_flag {
        println!(
            "[miner] network {:?} mandates UmbraHash (fork active) — forcing block version {}",
            network, block_version
        );
    }
    if umbra_mode {
        println!(
            "[miner] PoW = UmbraHash (memory-hard, block version {}); CPU cache-verify mining",
            block_version
        );
    }

    let rpc_port = match network {
        NetworkMode::Testnet => 19332,
        NetworkMode::Regtest => 29332,
        _ => 9332,
    };
    let rpc_addr = parse_flag(args, "--rpc", &format!("127.0.0.1:{}", rpc_port));
    let mut rpc_auth = resolve_rpc_auth(args, &network, &rpc_addr);
    if rpc_auth.bearer_token.is_none() {
        if let Some(token) = rpc_login(&rpc_addr, &rpc_auth.username, rpc_auth.password.as_deref()) {
            rpc_auth.bearer_token = Some(token);
            slog_info!("miner", "rpc_login_ok", user => &rpc_auth.username);
        }
    }

    let owner_address = match network {
        NetworkMode::Mainnet => ConsensusParams::OWNER_REWARD_ADDRESS,
        NetworkMode::Testnet => TESTNET_DEV_ADDRESS,
        NetworkMode::Regtest => REGTEST_DEV_ADDRESS,
    }
    .to_string();
    let genesis = create_genesis_block_for(&network);

    // Initialize rayon thread pool â€” fail loudly if it can't be built
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        eprintln!("[miner] WARNING: Failed to build rayon thread pool: {}", e);
        eprintln!("[miner] Falling back to default thread pool");
    }

    println!("â•”â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•—");
    println!("â•‘     S H A D O W D A G  â€”  Miner v1.0.0       â•‘");
    println!("â•‘     Multi-Threaded ShadowHash Mining           â•‘");
    println!("â•ڑâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•‌");
    slog_info!("miner", "config",
        network => &network_str,
        address => format!("{}...{}", &miner_address[..8.min(miner_address.len())], &miner_address[miner_address.len().saturating_sub(6)..]),
        dev_address => format!("{}...{}", &owner_address[..8.min(owner_address.len())], &owner_address[owner_address.len().saturating_sub(6)..]),
        threads => threads,
        rpc => &rpc_addr,
        genesis => &genesis.header.hash[..16.min(genesis.header.hash.len())],
        reward => EmissionSchedule::info(0));

    let mut total_mined: u64 = 0;
    let mut total_accepted: u64 = 0;
    let mut last_submitted_hash = String::new();
    let mut last_submitted_template: Option<TemplateKey> = None;
    let mut last_submit_attempt_at: Option<Instant> = None;
    let mut stale_reject_streak: u32 = 0;
    let session_start = Instant::now();

    // Build the ShadowHash GPU miner once (reused across blocks). None = CPU.
    // Not used in UmbraHash mode (which has its own GPU miner below).
    #[cfg(feature = "gpu-opencl")]
    let gpu_miner: Option<shadowdag::engine::mining::gpu::opencl::OpenClMiner> =
        if use_gpu && !umbra_mode {
            match shadowdag::engine::mining::gpu::opencl::OpenClMiner::new(gpu_batch) {
                Ok(m) => {
                    println!("[miner] GPU mining ENABLED — device: {} (batch={})", m.device_name(), m.batch());
                    Some(m)
                }
                Err(e) => {
                    eprintln!("[miner] GPU init failed ({}); falling back to CPU.", e);
                    None
                }
            }
        } else {
            None
        };

    // UmbraHash GPU miner (generates the ~1 GiB dataset into VRAM once per epoch).
    #[cfg(feature = "gpu-opencl")]
    let mut umbra_gpu: Option<shadowdag::engine::mining::gpu::umbra::UmbraGpuMiner> =
        if umbra_mode && use_gpu {
            match shadowdag::engine::mining::gpu::umbra::UmbraGpuMiner::new(
                gpu_batch,
                umbrahash::DATASET_BYTES,
                umbrahash::CACHE_BYTES,
            ) {
                Ok(m) => {
                    println!(
                        "[miner] UmbraHash GPU mining on {} (batch={}, dataset=1GiB VRAM)",
                        m.device_name(),
                        m.batch()
                    );
                    Some(m)
                }
                Err(e) => {
                    eprintln!("[miner] Umbra GPU init failed ({}); CPU fallback.", e);
                    None
                }
            }
        } else {
            None
        };

    slog_info!("miner", "mining_loop_started");

    loop {
        // â•گâ•گâ•گ STEP 1: Get fresh template from node EVERY block â•گâ•گâ•گ
        // This ensures we always mine on top of the latest tip.
        let template = match rpc_get_template(&rpc_addr, rpc_auth.bearer_token.as_deref()) {
            Some(t) => t,
            None => {
                if total_mined == 0 {
                    slog_warn!("miner", "rpc_connect_failed", addr => &rpc_addr, retry_sec => 5);
                }
                // The one-shot login at startup can race node startup: if the
                // RPC wasn't listening yet, we hold no token and every
                // getblocktemplate returns None (unauthorized). Keep retrying
                // login here so the miner recovers on its own instead of
                // looping unauthenticated forever (the block-rejection relogin
                // path below is never reached without a template).
                if rpc_auth.bearer_token.is_none() && rpc_auth.password.as_deref().is_some() {
                    if let Some(token) =
                        rpc_login(&rpc_addr, &rpc_auth.username, rpc_auth.password.as_deref())
                    {
                        rpc_auth.bearer_token = Some(token);
                        slog_info!("miner", "rpc_login_ok", user => &rpc_auth.username);
                        continue; // retry the template immediately with fresh auth
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        };
        let template_key = TemplateKey::from_template(&template);

        // Avoid spamming the node by reminting on an unchanged template.
        if last_submitted_template.as_ref() == Some(&template_key) {
            std::thread::sleep(std::time::Duration::from_millis(150));
            continue;
        }

        let height = template.height;
        let prev_hash = template.prev_hash;
        let difficulty = template.difficulty;
        // M5: the deferred state commitment to stamp + mine (parity with the node).
        let prev_state_commitment = template.prev_state_commitment.clone();

        if total_mined == 0 {
            slog_info!("miner", "connected_to_node", height => height - 1, difficulty => difficulty);
        }

        // Stamp at least max_parent_ts + 1 (from the template) so fast,
        // sub-second blocks still satisfy R4 (monotonic DAG time: ts must be
        // strictly greater than every parent's). Timestamps are unix epoch
        // MILLISECONDS. Falls back to wall-clock when the node supplied no floor.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // LIVENESS THROTTLE (MILLISECONDS): R4 forces ts >= max_parent_ts + 1,
        // now +1 MS. At the 100ms target the tip timestamp tracks wall-clock and
        // drift no longer accrues, so this should essentially never fire (unlike
        // the 1-second era, where +1s/block drifted the tip ahead of real time
        // and stalled mining on the future gate). It remains a safety valve: if
        // the required floor is already far ahead of our clock (e.g. a burst
        // pushed timestamps forward), wait for the clock to catch up rather than
        // stamp a block beyond the consensus future window (MAX_FUTURE_MS =
        // 120_000 ms) that every honest node would reject.
        const TS_DRIFT_BUDGET_MS: u64 = 30_000; // << 120_000 ms window, robust to clock skew
        if template.min_timestamp > now_ms.saturating_add(TS_DRIFT_BUDGET_MS) {
            let wait_ms = (template.min_timestamp - now_ms - TS_DRIFT_BUDGET_MS).min(15_000);
            slog_info!("miner", "timestamp_drift_throttle",
                min_timestamp => template.min_timestamp,
                now => now_ms,
                wait_ms => wait_ms);
            std::thread::sleep(Duration::from_millis(wait_ms.max(1)));
            continue; // refetch a fresh template with an advanced wall-clock
        }
        let timestamp = now_ms.max(template.min_timestamp);

        // â•گâ•گâ•گ STEP 2: Build coinbase transaction â•گâ•گâ•گ
        // Include the node-selected mempool transactions so user transactions
        // actually confirm; the coinbase claims their fees. The node's
        // post-execution check requires coinbase_total == emission + applied_fees
        // EXACTLY, so fees are summed over EXACTLY the txs included here.
        let included_txs = template.transactions.clone();
        let included_fees: u64 = included_txs
            .iter()
            .map(|t| t.fee)
            .fold(0u64, |a, f| a.saturating_add(f));
        let emission = EmissionSchedule::block_reward(height);
        let (miner_reward, dev_reward) =
            coinbase_split(emission, included_fees, ConsensusParams::MINER_PERCENT);

        let cb_hash = {
            let mut h = Sha256::new();
            h.update(b"coinbase");
            h.update(miner_address.as_bytes());
            h.update(timestamp.to_le_bytes());
            h.update(height.to_le_bytes());
            hex::encode(h.finalize())
        };

        let coinbase = Transaction {
            hash: cb_hash,
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    address: miner_address.clone(),
                    amount: miner_reward,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                    one_time_pubkey: None,
                    encrypted_amount: None,
                },
                TxOutput {
                    address: owner_address.clone(),
                    amount: dev_reward,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                    one_time_pubkey: None,
                    encrypted_amount: None,
                },
            ],
            fee: 0,
            timestamp,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };

        // Use DAG tips from template as parents (not just prev_hash)
        let mut parents = template.parent_hashes.clone();
        if parents.is_empty() {
            parents.push(prev_hash.clone());
        }
        // Pre-sort parents for deterministic hashing (consensus rule)
        parents.sort();
        parents.dedup();

        // Body = coinbase first, then the selected mempool txs (in order). The
        // merkle root commits to the FULL body; the node recomputes it over the
        // same list and rejects a mismatch.
        let mut block_txs = Vec::with_capacity(1 + included_txs.len());
        block_txs.push(coinbase);
        block_txs.extend(included_txs);
        let merkle_root = MerkleTree::build(&block_txs, height, &parents);

        // â•گâ•گâ•گ STEP 3: Multi-threaded mining â•گâ•گâ•گ
        let start = Instant::now();
        let found = Arc::new(AtomicBool::new(false));
        let found_nonce = Arc::new(AtomicU64::new(0));
        let hash_count = Arc::new(AtomicU64::new(0));

        // Clone values for threads
        let t_merkle = merkle_root.clone();
        let t_parents = parents.clone();
        let t_found = found.clone();
        let t_found_nonce = found_nonce.clone();
        let t_hash_count = hash_count.clone();
        let t_difficulty = difficulty;

        // Divide nonce space among threads.
        // Reserve u64::MAX because consensus treats it as a sentinel and rejects it.
        let max_mine_nonce = u64::MAX - 1;
        let nonces_per_thread = (max_mine_nonce as u128 / threads as u128) as u64;

        // UmbraHash CPU search (opt-in). Returns (nonce, hash=result, mix_hash).
        let umbra_result: Option<(u64, String, String)> = if umbra_mode {
            let hh = umbrahash::header_hash(
                block_version, height, timestamp, 0, difficulty, &merkle_root, &parents,
                prev_state_commitment.as_deref(),
            );
            let target = PowValidator::difficulty_to_target_bytes(difficulty);
            let cache = umbrahash::cache_for_epoch(umbrahash::epoch_of(height));
            let prog_seed = umbrahash::prog_seed_from_height(height);
            #[cfg(feature = "gpu-opencl")]
            {
                if let Some(g) = umbra_gpu.as_mut() {
                    umbra_mine_gpu(
                        g, &cache, umbrahash::epoch_of(height), &hh, &target, prog_seed, &found,
                        &hash_count, &start, height,
                    )
                } else {
                    umbra_mine_cpu(
                        &cache, &hh, &target, prog_seed, threads, &found, &hash_count, &start, height,
                    )
                }
            }
            #[cfg(not(feature = "gpu-opencl"))]
            {
                umbra_mine_cpu(
                    &cache, &hh, &target, prog_seed, threads, &found, &hash_count, &start, height,
                )
            }
        } else {
            None
        };

        // ShadowHash search (default). GPU path serves ShadowHash only; both are
        // skipped in UmbraHash mode. Structured as a match (not a labeled block)
        // so the default build carries no unused-label warning.
        #[cfg(feature = "gpu-opencl")]
        let gpu_outcome: Option<Option<(u64, String)>> = if umbra_mode {
            None
        } else {
            gpu_miner.as_ref().map(|g| {
                gpu_search(
                    g, height, timestamp, difficulty, &merkle_root, &parents,
                    prev_state_commitment.as_deref(), &found, &hash_count, &start,
                )
            })
        };
        #[cfg(not(feature = "gpu-opencl"))]
        let gpu_outcome: Option<Option<(u64, String)>> = None;

        let result: Option<(u64, String)> = if umbra_mode {
            None
        } else {
            match gpu_outcome {
            Some(outcome) => outcome,
            None => {
                use rayon::prelude::*;
                (0..threads).into_par_iter().find_map_any(|thread_id| {
                let start_nonce = thread_id as u64 * nonces_per_thread;
                let end_nonce = if thread_id == threads - 1 {
                    max_mine_nonce
                } else {
                    start_nonce.saturating_add(nonces_per_thread).min(max_mine_nonce)
                };

                let mut nonce = start_nonce;
                loop {
                    if t_found.load(Ordering::Relaxed) {
                        return None;
                    }

                    let hash = shadow_hash_raw_full(
                        2, // version — ms-timestamp era; MUST match the header's version (line ~397)
                        height,
                        timestamp,
                        nonce,
                        0, // extra_nonce
                        t_difficulty,
                        &t_merkle,
                        &t_parents,
                        prev_state_commitment.as_deref(),
                    );

                    t_hash_count.fetch_add(1, Ordering::Relaxed);

                    if meets_difficulty(&hash, t_difficulty) {
                        t_found.store(true, Ordering::Relaxed);
                        t_found_nonce.store(nonce, Ordering::Relaxed);
                        return Some((nonce, hash));
                    }

                    if nonce == end_nonce {
                        return None; // exhausted range
                    }
                    nonce = nonce.wrapping_add(1);

                    // Progress report (thread 0 only)
                    if thread_id == 0 && nonce.wrapping_sub(start_nonce).is_multiple_of(500_000) {
                        let elapsed = start.elapsed().as_secs_f64();
                        let total = t_hash_count.load(Ordering::Relaxed);
                        let rate = total as f64 / elapsed.max(0.001);
                        print!(
                            "\r[mining] height={} hashes={:.1}M rate={:.0} H/s ({} threads)   ",
                            height,
                            total as f64 / 1_000_000.0,
                            rate,
                            threads,
                        );
                        let _ = std::io::stdout().flush();
                    }
                }
                })
            }
            }
        };

        let elapsed = start.elapsed().as_secs_f64();
        let total_hashes = hash_count.load(Ordering::Relaxed);
        let hashrate = total_hashes as f64 / elapsed.max(0.001);

        let (nonce, hash, mix_hash) = if umbra_mode {
            match umbra_result {
                Some(r) => r,
                None => {
                    slog_warn!("miner", "no_valid_nonce_found");
                    continue;
                }
            }
        } else {
            match result {
                Some((n, h)) => (n, h, String::new()),
                None => {
                    slog_warn!("miner", "no_valid_nonce_found");
                    continue;
                }
            }
        };

        // Clear progress line
        print!("\r{}\r", " ".repeat(80));

        let fees_sdag = template.total_fees as f64 / 100_000_000.0;
        println!(
            "â›ڈ  Block #{} mined! hash={}... nonce={} time={:.1}s rate={:.0} H/s fees={:.8} SDAG",
            height,
            hash.get(..16).unwrap_or(&hash),
            nonce,
            elapsed,
            hashrate,
            fees_sdag
        );

        // â•گâ•گâ•گ STEP 4: Build full block and submit â•گâ•گâ•گ
        let block = Block {
            header: BlockHeader {
                version: block_version, // 2 = ShadowHash; UMBRA_POW_VERSION = UmbraHash
                hash: hash.clone(),
                parents,
                merkle_root,
                timestamp,
                nonce,
                difficulty,
                height,
                blue_score: 0,
                selected_parent: Some(prev_hash),
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
                mix_hash, // hex(mix) for UmbraHash, empty for ShadowHash
                // M5: the commitment the miner mined into the preimage (same value
                // the validator recomputes from the parents); stamped so the
                // submitted block's hash re-derives correctly.
                prev_state_commitment,
            },
            body: BlockBody {
                transactions: block_txs,
            },
        };

        total_mined += 1;

        // Guard against duplicate submissions when template/state did not
        // advance yet and we re-mined the exact same header.
        if hash == last_submitted_hash {
            slog_warn!("miner", "duplicate_block_skipped", hash => &hash[..16.min(hash.len())], height => height);
            std::thread::sleep(std::time::Duration::from_millis(200));
            continue;
        }

        // Re-check template freshness before submit. If tip/difficulty/parents
        // moved while we were hashing, drop this stale block instead of
        // flooding the node with guaranteed rejections.
        if let Some(fresh) = rpc_get_template(&rpc_addr, rpc_auth.bearer_token.as_deref()) {
            let fresh_key = TemplateKey::from_template(&fresh);
            if fresh_key != template_key {
                last_submitted_template = Some(template_key.clone());
                slog_warn!("miner", "stale_template_drop",
                    mined_height => height,
                    mined_diff => difficulty,
                    fresh_height => fresh.height,
                    fresh_diff => fresh.difficulty);
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        }

        if let Some(last) = last_submit_attempt_at {
            let min_gap = Duration::from_millis(MIN_SUBMIT_INTERVAL_MS);
            let elapsed_since_last = last.elapsed();
            if elapsed_since_last < min_gap {
                std::thread::sleep(min_gap - elapsed_since_last);
            }
        }
        last_submit_attempt_at = Some(Instant::now());

        match rpc_submit_block(&rpc_addr, &block, rpc_auth.bearer_token.as_deref()) {
            SubmitResult::Accepted => {
                last_submitted_hash = hash.clone();
                last_submitted_template = Some(template_key.clone());
                stale_reject_streak = 0;
                total_accepted += 1;
                println!("    âœ… Accepted by node (queued for consensus)");
            }
            SubmitResult::Unauthorized(reason) => {
                let reason_lc = reason.to_ascii_lowercase();
                last_submitted_hash.clear();
                last_submitted_template = None;
                slog_error!("miner", "block_rejected", reason => &reason);
                // Auto-recover from token expiry/missing auth without requiring
                // manual miner restart. If login succeeds, clear template guard
                // so we can immediately retry on fresh auth.
                if (reason_lc.contains("authentication required")
                    || reason_lc.contains("authorization: bearer"))
                    && rpc_auth.password.as_deref().is_some()
                {
                    if let Some(token) =
                        rpc_login(&rpc_addr, &rpc_auth.username, rpc_auth.password.as_deref())
                    {
                        rpc_auth.bearer_token = Some(token);
                        last_submitted_hash.clear();
                        last_submitted_template = None;
                        slog_info!("miner", "rpc_relogin_ok", user => &rpc_auth.username);
                        std::thread::sleep(std::time::Duration::from_millis(150));
                    } else {
                        slog_warn!("miner", "rpc_relogin_failed", user => &rpc_auth.username);
                        std::thread::sleep(std::time::Duration::from_secs(2));
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
            SubmitResult::Rejected(reason) => {
                let reason_lc = reason.to_ascii_lowercase();
                if reason_lc.contains("rate limit exceeded") {
                    slog_warn!("miner", "rpc_rate_limited", reason => &reason);
                    // Keep this template pinned to avoid reminting the same
                    // stale work in a tight loop.
                    last_submitted_hash = hash.clone();
                    last_submitted_template = Some(template_key.clone());
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    continue;
                }
                // Template moved while we were hashing (height/difficulty/parents).
                // Keep guards pinned so we don't re-mine doomed work until the
                // node template actually advances.
                if reason_lc.contains("stale template")
                    || reason_lc.contains("difficulty mismatch")
                    || reason_lc.contains("too few parents")
                    || reason_lc.contains("parent set does not intersect")
                {
                    stale_reject_streak = stale_reject_streak.saturating_add(1);
                    last_submitted_hash = hash.clone();
                    last_submitted_template = Some(template_key.clone());
                    let backoff_ms = (150u64).saturating_mul(stale_reject_streak.min(10) as u64);
                    slog_warn!("miner", "stale_or_parent_reject",
                        reason => &reason,
                        streak => stale_reject_streak,
                        backoff_ms => backoff_ms);
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    continue;
                }
                stale_reject_streak = 0;
                last_submitted_hash = hash.clone();
                last_submitted_template = Some(template_key.clone());
                slog_error!("miner", "block_rejected", reason => &reason);
            }
            SubmitResult::ConnError => {
                slog_warn!("miner", "block_submit_conn_error");
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }

        // Stats every 10 blocks
        if total_mined.is_multiple_of(10) {
            let session_secs = session_start.elapsed().as_secs_f64();
            let avg_rate = if session_secs > 0.0 {
                total_mined as f64 / session_secs * 60.0
            } else {
                0.0
            };
            let reward_sdag = emission as f64 / 100_000_000.0;
            println!(
                "ًں“ٹ Stats: {} mined, {} accepted | {:.1} blocks/min | reward={:.2} SDAG | height={}",
                total_mined, total_accepted, avg_rate, reward_sdag, height
            );
        }
    }
}

// â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
// RPC Communication
// â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

struct BlockTemplate {
    height: u64,
    prev_hash: String,
    parent_hashes: Vec<String>,
    difficulty: u64,
    total_fees: u64,
    /// Minimum valid block timestamp (max parent ts + 1) supplied by the node
    /// so the miner never violates R4 (monotonic DAG time) on sub-second blocks.
    min_timestamp: u64,
    /// Mempool transactions the node selected for this block (validated,
    /// conflict-free). The miner includes them so user transactions confirm;
    /// the coinbase claims their fees. Empty when the mempool is empty.
    transactions: Vec<Transaction>,
    /// M5 deferred state commitment the node computed for this template (over
    /// select_parent(parent_hashes)). The miner stamps it into
    /// header.prev_state_commitment and mines it into the PoW preimage; the
    /// validator recomputes + rejects a mismatch. `None` on pre-M5 nodes.
    prev_state_commitment: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TemplateKey {
    height: u64,
    difficulty: u64,
    prev_hash: String,
    parents: Vec<String>,
}

impl TemplateKey {
    fn from_template(template: &BlockTemplate) -> Self {
        let mut parents = template.parent_hashes.clone();
        if parents.is_empty() {
            parents.push(template.prev_hash.clone());
        }
        parents.sort();
        parents.dedup();
        Self {
            height: template.height,
            difficulty: template.difficulty,
            prev_hash: template.prev_hash.clone(),
            parents,
        }
    }
}

enum SubmitResult {
    Accepted,
    Unauthorized(String),
    Rejected(String),
    ConnError,
}

const MAX_RESPONSE: usize = 1_000_000; // 1 MB
const MAX_HEADER_LINES: usize = 100;
// Minimum gap between block submissions. Set below the 100 ms target so the
// miner can sustain ~10 blocks/sec (the ms-timestamp target). Safe because the
// co-located miner connects over loopback (127.0.0.1), which the node's RPC
// rate limiter exempts; a remote miner would still be rate-limited upstream.
const MIN_SUBMIT_INTERVAL_MS: u64 = 50;

fn rpc_call(addr: &str, method: &str, params: &str, bearer_token: Option<&str>) -> Option<String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":[{}]}}"#,
        method, params
    );

    let mut stream = TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    let auth_header = bearer_token
        .filter(|t| !t.trim().is_empty())
        .map(|t| format!("Authorization: Bearer {}\r\n", t))
        .unwrap_or_default();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        addr, auth_header, body.len(), body
    );

    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;

    // Read HTTP response properly: headers first, then body by Content-Length.
    // Using read_to_string fails on Linux because read_timeout triggers
    // EAGAIN (os error 11) which .ok()? silently swallows as None.
    let mut reader = std::io::BufReader::new(&stream);
    let mut content_length: usize = 0;
    let mut content_length_seen = false;
    let mut unsupported_transfer_encoding = false;

    // Read headers line by line until empty line
    let mut header_count = 0usize;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break;
                } // End of headers
                header_count += 1;
                if header_count > MAX_HEADER_LINES {
                    slog_error!("miner", "rpc_header_overflow", max_headers => MAX_HEADER_LINES);
                    return None;
                }
                // Case-insensitive Content-Length matching
                if let Some((name, value)) = trimmed.split_once(':') {
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        if content_length_seen {
                            slog_error!("miner", "rpc_duplicate_content_length");
                            return None;
                        }
                        content_length_seen = true;
                        content_length = match value.trim().parse::<usize>() {
                            Ok(n) => n,
                            Err(_) => {
                                slog_error!("miner", "rpc_invalid_content_length", raw => value.trim());
                                return None;
                            }
                        };
                    } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
                        unsupported_transfer_encoding = true;
                    }
                }
            }
            Err(e) => {
                slog_error!("miner", "rpc_header_read_failed", error => e);
                return None;
            }
        }
    }
    if unsupported_transfer_encoding || !content_length_seen {
        slog_error!("miner", "rpc_invalid_response_headers",
            transfer_encoding => unsupported_transfer_encoding,
            content_length_seen => content_length_seen);
        return None;
    }

    // Read exactly content_length bytes for the body
    if content_length == 0 {
        return None;
    }
    if content_length > MAX_RESPONSE {
        slog_error!("miner", "rpc_response_too_large", bytes => content_length, max => MAX_RESPONSE);
        return None;
    }
    let mut body_buf = vec![0u8; content_length];
    match reader.read_exact(&mut body_buf) {
        Ok(()) => {}
        Err(e) => {
            slog_error!("miner", "rpc_read_failed", bytes => content_length, error => e);
            return None;
        }
    }
    String::from_utf8(body_buf).ok()
}

/// Split the coinbase reward: the base `emission` is split `miner_percent`/rest
/// between miner and dev, and ALL `fees` go to the miner. This is the split that
/// satisfies the consensus coinbase check (validate_coinbase_for_network):
/// `total == emission + fees`, `dev == emission - miner_base` (>= the dev floor),
/// and `miner == miner_base + fees` (<= miner_base + declared_fees). Returns
/// `(miner_amount, dev_amount)`.
fn coinbase_split(emission: u64, fees: u64, miner_percent: u64) -> (u64, u64) {
    let miner_base = (emission as u128 * miner_percent as u128 / 100) as u64;
    let dev = emission - miner_base;
    let miner = miner_base.saturating_add(fees);
    (miner, dev)
}

fn rpc_get_template(addr: &str, bearer_token: Option<&str>) -> Option<BlockTemplate> {
    let response = rpc_call(addr, "getblocktemplate", "", bearer_token)?;

    let parsed: serde_json::Value = serde_json::from_str(&response).ok()?;
    let result = parsed.get("result")?;

    let height = result.get("height").and_then(|v| v.as_u64())?;
    let prev_hash = result
        .get("prev_hash")
        .and_then(|v| v.as_str())?
        .to_string();
    let difficulty = result
        .get("difficulty")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    let total_fees = result
        .get("total_fees")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Parse DAG parent hashes -- the tips the miner must reference
    let parent_hashes = result
        .get("parent_hashes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_else(|| vec![prev_hash.clone()]);

    let min_timestamp = result
        .get("min_timestamp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // M5: deferred state commitment (null on pre-M5 nodes -> None).
    let prev_state_commitment = result
        .get("prev_state_commitment")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Transactions the node selected for inclusion. Absent/empty => coinbase-only
    // block. A tx that fails to deserialize is skipped (never included blindly).
    let transactions: Vec<Transaction> = result
        .get("transactions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| serde_json::from_value::<Transaction>(t.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    Some(BlockTemplate {
        height,
        prev_hash,
        parent_hashes,
        difficulty,
        total_fees,
        min_timestamp,
        transactions,
        prev_state_commitment,
    })
}

fn rpc_submit_block(addr: &str, block: &Block, bearer_token: Option<&str>) -> SubmitResult {
    // Serialize transactions via serde so the RPC server can reconstruct them.
    // Without transactions, DagShield rejects the block ("empty block body").
    let txs_json = match serde_json::to_value(&block.body.transactions) {
        Ok(v) => v,
        Err(e) => {
            slog_error!("miner", "tx_serialization_failed", error => e);
            return SubmitResult::Rejected(format!("TX serialization failed: {}", e));
        }
    };
    let block_obj = serde_json::json!({
        "hash":         block.header.hash,
        "height":       block.header.height,
        "timestamp":    block.header.timestamp,
        "nonce":        block.header.nonce,
        "extra_nonce":  block.header.extra_nonce,
        "difficulty":   block.header.difficulty,
        "merkle_root":  block.header.merkle_root,
        "parents":      block.header.parents,
        "version":      block.header.version,
        "mix_hash":     block.header.mix_hash, // UmbraHash PoW mix (empty for ShadowHash)
        // M5: MUST transmit so the node reconstructs the exact header it mined —
        // the commitment is in the PoW preimage, so omitting it => hash mismatch.
        "prev_state_commitment": block.header.prev_state_commitment,
        "transactions": txs_json,
    });

    let block_str = match serde_json::to_string(&block_obj) {
        Ok(s) => s,
        Err(e) => {
            slog_error!("miner", "block_serialization_failed", error => e);
            return SubmitResult::Rejected(format!("block serialization failed: {}", e));
        }
    };
    let params = format!(r#""{}""#, block_str.replace('"', r#"\""#));
    match rpc_call(addr, "submitblock", &params, bearer_token) {
        Some(response) => {
            match serde_json::from_str::<serde_json::Value>(&response) {
                Ok(parsed) => {
                    // Check if the response contains a non-null error field
                    match parsed.get("error") {
                        Some(err) if !err.is_null() => {
                            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or_default();
                            let reason = err
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or_else(|| err.as_str().unwrap_or("unknown error"))
                                .to_string();
                            if code == -32001 || reason.to_ascii_lowercase().contains("authentication required") {
                                SubmitResult::Unauthorized(reason)
                            } else {
                                SubmitResult::Rejected(reason)
                            }
                        }
                        _ => SubmitResult::Accepted,
                    }
                }
                Err(_) => {
                    // Unparseable response -- treat as rejection
                    SubmitResult::Rejected(response[..response.len().min(200)].to_string())
                }
            }
        }
        None => SubmitResult::ConnError,
    }
}

fn rpc_login(addr: &str, username: &str, password: Option<&str>) -> Option<String> {
    let password = password?.trim();
    if password.is_empty() {
        return None;
    }
    let params_json = serde_json::json!({
        "username": username,
        "password": password
    });
    let params = serde_json::to_string(&params_json).ok()?;
    let response = rpc_call(addr, "login", &params, None)?;
    let parsed: serde_json::Value = serde_json::from_str(&response).ok()?;
    parsed
        .get("result")
        .and_then(|r| r.get("token"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
}

fn resolve_rpc_auth(args: &[String], network: &NetworkMode, rpc_addr: &str) -> RpcAuthConfig {
    let mut cfg = RpcAuthConfig {
        bearer_token: None,
        username: parse_flag(
            args,
            "--rpc-user",
            &std::env::var("SHADOWDAG_RPC_USER").unwrap_or_else(|_| "admin".to_string()),
        ),
        password: None,
    };

    if let Ok(tok) = std::env::var("SHADOWDAG_RPC_TOKEN") {
        let t = tok.trim();
        if !t.is_empty() {
            cfg.bearer_token = Some(t.to_string());
            return cfg;
        }
    }
    if let Ok(Some(tok)) = parse_flag_opt(args, "--rpc-token") {
        let t = tok.trim();
        if !t.is_empty() {
            cfg.bearer_token = Some(t.to_string());
            return cfg;
        }
    }

    if let Ok(pw) = std::env::var("SHADOWDAG_RPC_PASSWORD") {
        let p = pw.trim();
        if !p.is_empty() {
            cfg.password = Some(p.to_string());
            return cfg;
        }
    }
    if let Ok(Some(pw)) = parse_flag_opt(args, "--rpc-password") {
        let p = pw.trim();
        if !p.is_empty() {
            cfg.password = Some(p.to_string());
            return cfg;
        }
    }

    // Best-effort local default for single-node operation.
    let is_local = rpc_addr.starts_with("127.0.0.1:") || rpc_addr.starts_with("localhost:");
    if is_local {
        let network_dir = match network {
            NetworkMode::Testnet => "testnet",
            NetworkMode::Regtest => "regtest",
            NetworkMode::Mainnet => "mainnet",
        };
        let pw_file = std::env::var("SHADOWDAG_RPC_PASSWORD_FILE")
            .ok()
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var("HOME").ok().map(|h| {
                    std::path::PathBuf::from(h)
                        .join(".shadowdag")
                        .join(network_dir)
                        .join("rpc_password")
                })
            });
        if let Some(path) = pw_file {
            if let Ok(raw) = std::fs::read_to_string(path) {
                let p = raw.trim();
                if !p.is_empty() {
                    cfg.password = Some(p.to_string());
                }
            }
        }
    }

    cfg
}

// â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
// Helpers
// â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

fn print_help() {
    println!("ShadowDAG Miner v1.0.0");
    println!();
    println!("USAGE:");
    println!("  shadowdag-miner [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --address=<SD1...>                   Mining reward address (required)");
    println!("  --network=<mainnet|testnet|regtest>  Network (default: mainnet)");
    println!("  --threads=<n>                        Mining threads (default: CPU count)");
    println!("  --rpc=<host:port>                    Node RPC address (default: 127.0.0.1:port)");
    println!("  --rpc-token=<token>                  Bearer token for authenticated RPC");
    println!("  --rpc-user=<name>                    RPC login username (default: admin)");
    println!("  --rpc-password=<pass>                RPC login password");
    println!("  --help, -h                           Show this help");
    println!("  --version, -v                        Show version");
    println!();
    println!("EXAMPLES:");
    println!("  shadowdag-miner --address=SD1abc... --network=testnet");
    println!("  shadowdag-miner --threads=8 --rpc=127.0.0.1:9332");
}

fn parse_flag(args: &[String], name: &str, default: &str) -> String {
    match parse_flag_opt(args, name) {
        Ok(Some(val)) => val,
        Ok(None) => default.to_string(), // flag not present at all â€” use default
        Err(msg) => {
            eprintln!("Error: {}", msg);
            std::process::exit(1);
        }
    }
}

/// Parse an optional CLI flag. Returns:
/// - Ok(Some(value)) if flag is present with a value
/// - Ok(None) if flag is not present at all
/// - Err if flag is present but missing its value
fn parse_flag_opt(args: &[String], name: &str) -> Result<Option<String>, String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return match args.get(i + 1) {
                Some(val) if !val.starts_with("--") => Ok(Some(val.clone())),
                _ => Err(format!("{} requires a value", name)),
            };
        }
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) {
            if val.is_empty() {
                return Err(format!("{} requires a non-empty value", name));
            }
            return Ok(Some(val.to_string()));
        }
    }
    Ok(None)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// UmbraHash GPU nonce search: ensure the epoch dataset is resident in VRAM,
/// then loop `umbra_mine` batches until a nonce whose result <= target is found
/// (re-verified on the CPU consensus path before returning).
#[cfg(feature = "gpu-opencl")]
#[allow(clippy::too_many_arguments)]
fn umbra_mine_gpu(
    g: &mut shadowdag::engine::mining::gpu::umbra::UmbraGpuMiner,
    cache: &[u8],
    epoch: u64,
    header_hash: &[u8; 32],
    target: &[u8; 32],
    prog_seed: u64,
    found: &Arc<AtomicBool>,
    hash_count: &Arc<AtomicU64>,
    start: &Instant,
    height: u64,
) -> Option<(u64, String, String)> {
    if let Err(e) = g.ensure_dataset(cache, epoch) {
        eprintln!("[umbra-gpu] dataset gen failed: {}", e);
        return None;
    }
    let batch = g.batch() as u64;
    let cap: u64 = 4_000_000_000;
    let mut base: u64 = 0;
    while base < cap {
        if found.load(Ordering::Relaxed) {
            return None;
        }
        match g.mine(header_hash, target, prog_seed, base) {
            Ok(Some(nonce)) => {
                // Authoritative CPU re-check (consensus path) + header fields.
                let (mix, result) = umbrahash::hashimoto_light(
                    cache,
                    umbrahash::DATASET_BYTES,
                    header_hash,
                    nonce,
                    prog_seed,
                );
                if umbrahash::verify_light(
                    cache, umbrahash::DATASET_BYTES, header_hash, nonce, prog_seed, &mix, target,
                ) {
                    found.store(true, Ordering::Relaxed);
                    return Some((nonce, hex::encode(result), hex::encode(mix)));
                }
                eprintln!("[umbra-gpu] WARNING: GPU nonce {} rejected by CPU re-check", nonce);
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("[umbra-gpu] error: {}", e);
                return None;
            }
        }
        hash_count.fetch_add(batch, Ordering::Relaxed);
        let el = start.elapsed().as_secs_f64();
        let tot = hash_count.load(Ordering::Relaxed);
        print!(
            "\r[umbra-gpu] height={} hashes={:.2}M rate={:.0} H/s   ",
            height,
            tot as f64 / 1_000_000.0,
            tot as f64 / el.max(0.001)
        );
        let _ = std::io::stdout().flush();
        base = base.saturating_add(batch);
    }
    None
}

/// UmbraHash CPU nonce search (rayon across threads). Each thread runs the
/// cache-only `hashimoto_light` (no 1 GiB dataset) and returns the first
/// `(nonce, hash=result_hex, mix_hash=mix_hex)` whose result <= target. This is
/// the memory-hard, ASIC-resistant PoW; a resident-dataset / GPU path would be
/// faster but this is correct and needs no multi-GB generation.
#[allow(clippy::too_many_arguments)]
fn umbra_mine_cpu(
    cache: &[u8],
    header_hash: &[u8; 32],
    target: &[u8; 32],
    prog_seed: u64,
    threads: usize,
    found: &Arc<AtomicBool>,
    hash_count: &Arc<AtomicU64>,
    start: &Instant,
    height: u64,
) -> Option<(u64, String, String)> {
    use rayon::prelude::*;
    let max_nonce = u64::MAX - 1;
    let per_thread = (max_nonce as u128 / threads as u128) as u64;
    (0..threads).into_par_iter().find_map_any(|tid| {
        let s = tid as u64 * per_thread;
        let e = if tid == threads - 1 {
            max_nonce
        } else {
            s.saturating_add(per_thread).min(max_nonce)
        };
        let mut nonce = s;
        loop {
            if found.load(Ordering::Relaxed) {
                return None;
            }
            let (mix, result) = umbrahash::hashimoto_light(
                cache,
                umbrahash::DATASET_BYTES,
                header_hash,
                nonce,
                prog_seed,
            );
            hash_count.fetch_add(1, Ordering::Relaxed);
            // result <= target (big-endian) → valid solution.
            if result <= *target {
                found.store(true, Ordering::Relaxed);
                return Some((nonce, hex::encode(result), hex::encode(mix)));
            }
            if nonce == e {
                return None;
            }
            nonce = nonce.wrapping_add(1);
            if tid == 0 && nonce.wrapping_sub(s).is_multiple_of(2_000) {
                let el = start.elapsed().as_secs_f64();
                let tot = hash_count.load(Ordering::Relaxed);
                print!(
                    "\r[umbra-mining] height={} hashes={} rate={:.0} H/s   ",
                    height,
                    tot,
                    tot as f64 / el.max(0.001)
                );
                let _ = std::io::stdout().flush();
            }
        }
    })
}

/// GPU nonce search for one block template. Loops OpenCL batches until a nonce
/// whose ShadowHash meets the target is found (re-verified on the CPU consensus
/// path before returning), another thread flags `found`, or the per-template
/// nonce window is exhausted (returns None → the outer loop refetches).
#[cfg(feature = "gpu-opencl")]
#[allow(clippy::too_many_arguments)]
fn gpu_search(
    gpu: &shadowdag::engine::mining::gpu::opencl::OpenClMiner,
    height: u64,
    timestamp: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
    prev_state_commitment: Option<&str>,
    found: &Arc<AtomicBool>,
    hash_count: &Arc<AtomicU64>,
    start: &Instant,
) -> Option<(u64, String)> {
    use shadowdag::engine::mining::algorithms::shadowhash::{
        serialize_header_template, HEADER_NONCE_OFFSET,
    };

    if difficulty == 0 {
        return None; // genesis-only edge; let the CPU path handle it
    }
    let target = difficulty_target_bytes(difficulty)?;
    let tmpl = serialize_header_template(2, height, timestamp, 0, difficulty, merkle_root, parents, prev_state_commitment);
    if tmpl.len() > 512 {
        eprintln!("[gpu] header {}B exceeds kernel cap; using CPU", tmpl.len());
        return None;
    }

    let batch = gpu.batch() as u64;
    let cap: u64 = 400_000_000; // refresh the template periodically
    let mut base: u64 = 0;
    while base < cap {
        if found.load(Ordering::Relaxed) {
            return None;
        }
        match gpu.mine_batch(&tmpl, HEADER_NONCE_OFFSET, &target, base) {
            Ok(Some(nonce)) => {
                // Authoritative re-check on the consensus CPU hash.
                let hash = shadow_hash_raw_full(
                    2, height, timestamp, nonce, 0, difficulty, merkle_root, parents,
                    prev_state_commitment,
                );
                if meets_difficulty(&hash, difficulty) {
                    found.store(true, Ordering::Relaxed);
                    return Some((nonce, hash));
                }
                eprintln!("[gpu] WARNING: GPU nonce {} rejected by CPU re-check; skipping", nonce);
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("[gpu] error: {} — falling back to CPU", e);
                return None;
            }
        }
        hash_count.fetch_add(batch, Ordering::Relaxed);
        let elapsed = start.elapsed().as_secs_f64();
        let total = hash_count.load(Ordering::Relaxed);
        print!(
            "\r[gpu-mining] height={} hashes={:.2}M rate={:.0} H/s   ",
            height,
            total as f64 / 1_000_000.0,
            total as f64 / elapsed.max(0.001)
        );
        let _ = std::io::stdout().flush();
        base = base.saturating_add(batch);
    }
    None
}

/// The 256-bit PoW target for `difficulty`, as 32 big-endian bytes (matches the
/// kernel's byte-wise `hash <= target` comparison). None on any parse failure.
#[cfg(feature = "gpu-opencl")]
fn difficulty_target_bytes(difficulty: u64) -> Option<[u8; 32]> {
    let hex_str =
        shadowdag::engine::mining::pow::pow_validator::PowValidator::difficulty_to_target(difficulty);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut t = [0u8; 32];
    t.copy_from_slice(&bytes);
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The coinbase split MUST satisfy the consensus rule the node enforces in
    /// validate_coinbase_for_network, for any (emission, fees): total is exactly
    /// emission+fees, the dev output is the base emission share, and the miner
    /// output never exceeds base + declared fees. This is what lets a block that
    /// includes mempool txs (claiming their fees) be accepted.
    #[test]
    fn coinbase_split_satisfies_consensus_bounds() {
        let miner_percent = ConsensusParams::MINER_PERCENT; // 95
        for &(emission, fees) in &[
            (1_000_000_000u64, 0u64),
            (1_000_000_000, 394),
            (10, 5),
            (777, 1_000),
            (0, 250),
        ] {
            let (miner, dev) = coinbase_split(emission, fees, miner_percent);
            let miner_base = (emission as u128 * miner_percent as u128 / 100) as u64;
            let dev_base = emission - miner_base;

            // total == emission + fees (exact post-execution check).
            assert_eq!(
                miner + dev,
                emission + fees,
                "total must equal emission + fees"
            );
            // dev output == base emission share (>= the enforced dev floor).
            assert_eq!(dev, dev_base, "dev must be the base emission share");
            // miner output <= base + declared fees (the enforced ceiling).
            assert!(
                miner <= miner_base + fees,
                "miner must not exceed base + fees"
            );
            // All fees go to the miner, none siphoned to dev.
            assert_eq!(miner, miner_base + fees);
        }
    }
}

