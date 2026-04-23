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

        if total_mined == 0 {
            slog_info!("miner", "connected_to_node", height => height - 1, difficulty => difficulty);
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // â•گâ•گâ•گ STEP 2: Build coinbase transaction â•گâ•گâ•گ
        let emission = EmissionSchedule::block_reward(height);
        // Coinbase reward = emission only.
        // Fees can only be included when the miner also includes the
        // corresponding mempool transactions in the block body.
        // The node validates: coinbase_total == emission + applied_fees.
        let miner_reward = (emission * ConsensusParams::MINER_PERCENT) / 100;
        let dev_reward = emission - miner_reward;

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
                },
                TxOutput {
                    address: owner_address.clone(),
                    amount: dev_reward,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
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

        let merkle_root = MerkleTree::build(std::slice::from_ref(&coinbase), height, &parents);

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

        let result: Option<(u64, String)> = {
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
                        1, // version
                        height,
                        timestamp,
                        nonce,
                        0, // extra_nonce
                        t_difficulty,
                        &t_merkle,
                        &t_parents,
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
        };

        let elapsed = start.elapsed().as_secs_f64();
        let total_hashes = hash_count.load(Ordering::Relaxed);
        let hashrate = total_hashes as f64 / elapsed.max(0.001);

        let (nonce, hash) = match result {
            Some(r) => r,
            None => {
                slog_warn!("miner", "no_valid_nonce_found");
                continue;
            }
        };

        // Clear progress line
        print!("\r{}\r", " ".repeat(80));

        let fees_sdag = template.total_fees as f64 / 100_000_000.0;
        println!(
            "â›ڈ  Block #{} mined! hash={}... nonce={} time={:.1}s rate={:.0} H/s fees={:.8} SDAG",
            height,
            &hash[..16],
            nonce,
            elapsed,
            hashrate,
            fees_sdag
        );

        // â•گâ•گâ•گ STEP 4: Build full block and submit â•گâ•گâ•گ
        let block = Block {
            header: BlockHeader {
                version: 1,
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
            },
            body: BlockBody {
                transactions: vec![coinbase],
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
const MIN_SUBMIT_INTERVAL_MS: u64 = 700; // keep below write rate-limit (100 req/min)

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

    // Read headers line by line until empty line
    let mut header_count = 0;
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
                if header_count > 100 {
                    break;
                }
                // Case-insensitive Content-Length matching
                if trimmed.len() > 15 && trimmed[..15].eq_ignore_ascii_case("content-length:") {
                    content_length = trimmed[15..].trim().parse().unwrap_or(0);
                }
            }
            Err(_) => break,
        }
    }

    // Read exactly content_length bytes for the body
    if content_length > 0 {
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
    } else {
        // Fallback: read whatever is available
        let mut buf = vec![0u8; 65536];
        match reader.read(&mut buf) {
            Ok(n) if n > 0 => String::from_utf8(buf[..n].to_vec()).ok(),
            _ => None,
        }
    }
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

    Some(BlockTemplate {
        height,
        prev_hash,
        parent_hashes,
        difficulty,
        total_fees,
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

