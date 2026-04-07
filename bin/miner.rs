// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// shadowdag-miner — Multi-threaded mining binary with RPC integration
//
// Usage:
//   shadowdag-miner --address=SD1your...       # Mine to address
//   shadowdag-miner --threads=8                 # Set thread count
//   shadowdag-miner --rpc=127.0.0.1:19332       # RPC address
//   shadowdag-miner --network=testnet           # Mine on testnet
// ═══════════════════════════════════════════════════════════════════════════

use shadowdag::engine::mining::algorithms::shadowhash::{shadow_hash_raw_full, meets_difficulty};
use shadowdag::config::genesis::genesis::create_genesis_block_for;
use shadowdag::config::consensus::consensus_params::ConsensusParams;
use shadowdag::config::consensus::emission_schedule::EmissionSchedule;
use shadowdag::config::node::node_config::NetworkMode;
use shadowdag::domain::block::block::Block;
use shadowdag::domain::block::block_header::BlockHeader;
use shadowdag::domain::block::block_body::BlockBody;
use shadowdag::domain::block::merkle_tree::MerkleTree;
use shadowdag::domain::transaction::transaction::{Transaction, TxOutput, TxType};
use sha2::{Sha256, Digest};
use serde_json;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::io::{Read, Write, BufRead};
use std::net::TcpStream;
use shadowdag::errors::NodeError;
use shadowdag::{slog_info, slog_warn, slog_error, slog_fatal};

fn main() {
    shadowdag::telemetry::logging::structured::init();
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_help(); return;
    }
    if has_flag(&args, "--version") || has_flag(&args, "-v") {
        println!("ShadowDAG Miner v1.1.0"); return;
    }

    if let Err(e) = run_miner(&args) {
        slog_fatal!("miner", "startup_failed", error => &e);
        eprintln!("[miner] Run 'shadowdag-miner --help' for usage information.");
        std::process::exit(1);
    }
}

fn run_miner(args: &[String]) -> Result<(), NodeError> {
    // Parse flags
    let miner_address = parse_flag(args, "--address",
        "SD1ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00");
    let network_str = parse_flag(args, "--network", "mainnet");
    let network: NetworkMode = network_str.parse().map_err(|_| {
        NodeError::Init(format!("invalid --network '{}'. Use: mainnet, testnet, or regtest", network_str))
    })?;
    let threads: usize = parse_flag(args, "--threads",
        &num_cpus().to_string()).parse().unwrap_or(4).min(256).max(1);

    let rpc_port = match network {
        NetworkMode::Testnet => 19332,
        NetworkMode::Regtest => 29332,
        _ => 9332,
    };
    let rpc_addr = parse_flag(&args, "--rpc", &format!("127.0.0.1:{}", rpc_port));

    let owner_address = ConsensusParams::OWNER_REWARD_ADDRESS.to_string();
    let genesis = create_genesis_block_for(&network);

    // Initialize rayon thread pool — fail loudly if it can't be built
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        eprintln!("[miner] WARNING: Failed to build rayon thread pool: {}", e);
        eprintln!("[miner] Falling back to default thread pool");
    }

    println!("╔══════════════════════════════════════════════╗");
    println!("║     S H A D O W D A G  —  Miner v1.1         ║");
    println!("║     Multi-Threaded ShadowHash Mining           ║");
    println!("╚══════════════════════════════════════════════╝");
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
    let session_start = Instant::now();

    slog_info!("miner", "mining_loop_started");

    loop {
        // ═══ STEP 1: Get fresh template from node EVERY block ═══
        // This ensures we always mine on top of the latest tip.
        let template = match rpc_get_template(&rpc_addr) {
            Some(t) => t,
            None => {
                if total_mined == 0 {
                    slog_warn!("miner", "rpc_connect_failed", addr => &rpc_addr, retry_sec => 5);
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        };

        let height    = template.height;
        let prev_hash = template.prev_hash;
        let difficulty = template.difficulty;

        if total_mined == 0 {
            slog_info!("miner", "connected_to_node", height => height - 1, difficulty => difficulty);
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // ═══ STEP 2: Build coinbase transaction ═══
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
                TxOutput { address: miner_address.clone(), amount: miner_reward, commitment: None, range_proof: None, ephemeral_pubkey: None },
                TxOutput { address: owner_address.clone(), amount: dev_reward, commitment: None, range_proof: None, ephemeral_pubkey: None },
            ],
            fee: 0,
            timestamp,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
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

        // ═══ STEP 3: Multi-threaded mining ═══
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

        // Divide nonce space among threads
        let nonces_per_thread = (u64::MAX as u128 / threads as u128) as u64;

        let result: Option<(u64, String)> = {
            use rayon::prelude::*;
            (0..threads).into_par_iter().find_map_any(|thread_id| {
                let start_nonce = thread_id as u64 * nonces_per_thread;
                let end_nonce = if thread_id == threads - 1 {
                    u64::MAX
                } else {
                    start_nonce + nonces_per_thread
                };

                let mut nonce = start_nonce;
                loop {
                    if t_found.load(Ordering::Relaxed) {
                        return None;
                    }

                    let hash = shadow_hash_raw_full(
                        1,              // version
                        height,
                        timestamp,
                        nonce,
                        0,              // extra_nonce
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
                    if thread_id == 0 && nonce.wrapping_sub(start_nonce) % 500_000 == 0 {
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
            "⛏  Block #{} mined! hash={}... nonce={} time={:.1}s rate={:.0} H/s fees={:.8} SDAG",
            height, &hash[..16], nonce, elapsed, hashrate, fees_sdag
        );

        // ═══ STEP 4: Build full block and submit ═══
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
            },
            body: BlockBody {
                transactions: vec![coinbase],
            },
        };

        total_mined += 1;

        match rpc_submit_block(&rpc_addr, &block) {
            SubmitResult::Accepted => {
                total_accepted += 1;
                println!("    ✅ Accepted by node (queued for consensus)");
            }
            SubmitResult::Rejected(reason) => {
                slog_error!("miner", "block_rejected", reason => &reason);
            }
            SubmitResult::ConnError => {
                slog_warn!("miner", "block_submit_conn_error");
            }
        }

        // Stats every 10 blocks
        if total_mined % 10 == 0 {
            let session_secs = session_start.elapsed().as_secs_f64();
            let avg_rate = if session_secs > 0.0 { total_mined as f64 / session_secs * 60.0 } else { 0.0 };
            let reward_sdag = emission as f64 / 100_000_000.0;
            println!(
                "📊 Stats: {} mined, {} accepted | {:.1} blocks/min | reward={:.2} SDAG | height={}",
                total_mined, total_accepted, avg_rate, reward_sdag, height
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RPC Communication
// ═══════════════════════════════════════════════════════════════════════════

struct BlockTemplate {
    height:        u64,
    prev_hash:     String,
    parent_hashes: Vec<String>,
    difficulty:    u64,
    total_fees:    u64,
}

enum SubmitResult {
    Accepted,
    Rejected(String),
    ConnError,
}

const MAX_RESPONSE: usize = 1_000_000; // 1 MB

fn rpc_call(addr: &str, method: &str, params: &str) -> Option<String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":[{}]}}"#,
        method, params
    );

    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).ok();

    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        addr, body.len(), body
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
            Ok(0) => break,  // EOF
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() { break; } // End of headers
                header_count += 1;
                if header_count > 100 { break; }
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

fn rpc_get_template(addr: &str) -> Option<BlockTemplate> {
    let response = rpc_call(addr, "getblocktemplate", "")?;

    let height = extract_json_u64(&response, "height")?;
    let prev_hash = extract_json_str(&response, "prev_hash")?;
    let difficulty = extract_json_u64(&response, "difficulty").unwrap_or(1);
    let total_fees = extract_json_u64(&response, "total_fees").unwrap_or(0);

    // Parse DAG parent hashes — the tips the miner must reference
    let parent_hashes = extract_json_str_array(&response, "parent_hashes")
        .unwrap_or_else(|| vec![prev_hash.clone()]);

    Some(BlockTemplate { height, prev_hash, parent_hashes, difficulty, total_fees })
}

fn rpc_submit_block(addr: &str, block: &Block) -> SubmitResult {
    // Serialize transactions via serde so the RPC server can reconstruct them.
    // Without transactions, DagShield rejects the block ("empty block body").
    let txs_json = serde_json::to_value(&block.body.transactions).unwrap_or_default();
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

    let block_str = serde_json::to_string(&block_obj).unwrap_or_default();
    let params = format!(r#""{}""#, block_str.replace('"', r#"\""#));
    match rpc_call(addr, "submitblock", &params) {
        Some(response) => {
            if response.contains("\"error\"") && !response.contains("\"error\":null") {
                // Extract error message
                let reason = extract_json_str(&response, "message")
                    .unwrap_or_else(|| response[..response.len().min(200)].to_string());
                SubmitResult::Rejected(reason)
            } else {
                SubmitResult::Accepted
            }
        }
        None => SubmitResult::ConnError,
    }
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let pattern = format!(r#""{}":"#, key);
    let pos = json.find(&pattern)? + pattern.len();
    let rest = &json[pos..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].trim().parse().ok()
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{}":""#, key);
    let pos = json.find(&pattern)? + pattern.len();
    let rest = &json[pos..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extract a JSON array of strings: "key":["a","b","c"]
fn extract_json_str_array(json: &str, key: &str) -> Option<Vec<String>> {
    let pattern = format!(r#""{}":["#, key);
    let pos = json.find(&pattern)? + pattern.len();
    let rest = &json[pos..];
    let end = rest.find(']')?;
    let inner = &rest[..end];
    if inner.trim().is_empty() {
        return Some(vec![]);
    }
    let items: Vec<String> = inner.split(',')
        .filter_map(|s| {
            let s = s.trim().trim_matches('"');
            if s.is_empty() { None } else { Some(s.to_string()) }
        })
        .collect();
    Some(items)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn print_help() {
    println!("ShadowDAG Miner v1.1.0");
    println!();
    println!("USAGE:");
    println!("  shadowdag-miner [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --address=<SD1...>                   Mining reward address (required)");
    println!("  --network=<mainnet|testnet|regtest>  Network (default: mainnet)");
    println!("  --threads=<n>                        Mining threads (default: CPU count)");
    println!("  --rpc=<host:port>                    Node RPC address (default: 127.0.0.1:port)");
    println!("  --help, -h                           Show this help");
    println!("  --version, -v                        Show version");
    println!();
    println!("EXAMPLES:");
    println!("  shadowdag-miner --address=SD1abc... --network=testnet");
    println!("  shadowdag-miner --threads=8 --rpc=127.0.0.1:9332");
}

fn parse_flag(args: &[String], name: &str, default: &str) -> String {
    for (i, arg) in args.iter().enumerate() {
        if arg == name { return args.get(i + 1).cloned().unwrap_or(default.to_string()); }
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) { return val.to_string(); }
    }
    default.to_string()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}
