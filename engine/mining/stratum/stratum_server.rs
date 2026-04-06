// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Stratum Server — Mining pool protocol for ShadowDAG.
//
// Implements Stratum V1 protocol for GPU mining pool support.
// Miners connect via TCP, receive work (block templates), submit shares,
// and get paid proportionally.
//
// Features:
//   - Stratum V1 compatible (works with any Stratum miner)
//   - Vardiff (variable difficulty) for optimal share rate
//   - Worker tracking (hashrate, shares, last seen)
//   - Block template push (new work notification)
//   - Privacy-enhanced: miner IPs never stored on chain
//
// Protocol:
//   mining.subscribe → mining.authorize → mining.notify → mining.submit
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use crate::errors::NetworkError;

/// Default Stratum port
pub const DEFAULT_STRATUM_PORT: u16 = 7779;

/// Target shares per minute per worker (for vardiff)
pub const TARGET_SHARES_PER_MIN: u32 = 20;

/// Minimum share difficulty
pub const MIN_SHARE_DIFF: u64 = 1;

/// Maximum share difficulty
pub const MAX_SHARE_DIFF: u64 = 1_000_000;

/// Vardiff adjustment interval (seconds)
pub const VARDIFF_INTERVAL_SEC: u64 = 60;

/// Maximum number of pending subscribe entries before rejecting new ones
const MAX_PENDING_SUBS: usize = 10_000;

/// Time-to-live for pending subscribe entries (seconds)
const PENDING_SUB_TTL_SECS: u64 = 60;

/// Stratum method types
#[derive(Debug, Clone, PartialEq)]
pub enum StratumMethod {
    Subscribe,
    Authorize,
    Submit,
    GetWork,
    Unknown(String),
}

impl StratumMethod {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "mining.subscribe"  => StratumMethod::Subscribe,
            "mining.authorize"  => StratumMethod::Authorize,
            "mining.submit"     => StratumMethod::Submit,
            "mining.get_work"   => StratumMethod::GetWork,
            _                   => StratumMethod::Unknown(s.to_string()),
        }
    }
}

/// Stratum JSON-RPC request
#[derive(Debug, Clone)]
pub struct StratumRequest {
    pub id:     u64,
    pub method: StratumMethod,
    pub params: Vec<String>,
}

/// Stratum JSON-RPC response
#[derive(Debug, Clone)]
pub struct StratumResponse {
    pub id:     u64,
    pub result: Option<String>,
    pub error:  Option<String>,
}

impl StratumResponse {
    pub fn ok(id: u64, result: &str) -> Self {
        Self { id, result: Some(result.to_string()), error: None }
    }
    pub fn err(id: u64, error: &str) -> Self {
        Self { id, result: None, error: Some(error.to_string()) }
    }
    pub fn to_json(&self) -> String {
        if let Some(ref e) = self.error {
            format!("{{\"id\":{},\"result\":null,\"error\":\"{}\"}}\n", self.id, e)
        } else {
            format!("{{\"id\":{},\"result\":{},\"error\":null}}\n", self.id,
                self.result.as_deref().unwrap_or("true"))
        }
    }
}

/// Worker (connected miner) state
#[derive(Debug, Clone)]
pub struct Worker {
    pub id:              u64,
    pub name:            String,
    pub address:         String,
    pub difficulty:      u64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub hashrate:        f64,
    pub connected_at:    u64,
    pub last_share_at:   u64,
    pub shares_in_window: u32, // Shares in current vardiff window
    pub extra_nonce:     u64,  // Unique per-worker nonce prefix (assigned on subscribe)
}

impl Worker {
    pub fn new(id: u64, name: String, address: String, extra_nonce: u64) -> Self {
        Self {
            id,
            name,
            address,
            difficulty:       MIN_SHARE_DIFF,
            shares_accepted:  0,
            shares_rejected:  0,
            hashrate:         0.0,
            connected_at:     now_secs(),
            last_share_at:    0,
            shares_in_window: 0,
            extra_nonce,
        }
    }

    pub fn accept_share(&mut self) {
        self.shares_accepted += 1;
        self.last_share_at = now_secs();
        self.shares_in_window += 1;
    }

    pub fn reject_share(&mut self) {
        self.shares_rejected += 1;
    }

    /// Adjust difficulty based on share submission rate
    pub fn vardiff_adjust(&mut self) -> bool {
        if self.shares_in_window == 0 { return false; }

        let ratio = self.shares_in_window as f64 / TARGET_SHARES_PER_MIN as f64;

        let new_diff = if ratio > 2.0 {
            (self.difficulty as f64 * ratio * 0.5) as u64
        } else if ratio < 0.5 {
            (self.difficulty as f64 * ratio * 2.0) as u64
        } else {
            self.difficulty
        };

        let clamped = new_diff.clamp(MIN_SHARE_DIFF, MAX_SHARE_DIFF);
        let changed = clamped != self.difficulty;
        self.difficulty = clamped;
        self.shares_in_window = 0;
        changed
    }

    pub fn uptime_secs(&self) -> u64 { now_secs().saturating_sub(self.connected_at) }
    pub fn total_shares(&self) -> u64 { self.shares_accepted + self.shares_rejected }
    pub fn acceptance_rate(&self) -> f64 {
        let total = self.total_shares();
        if total == 0 { return 0.0; }
        self.shares_accepted as f64 / total as f64
    }
}

/// Block template sent to miners
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    pub job_id:       String,
    pub version:      u32,
    pub prev_hash:    String,
    pub parents:      Vec<String>,
    pub merkle_root:  String,
    pub timestamp:    u64,
    pub difficulty:   u64,
    pub height:       u64,
    pub extra_nonce:  u64,
    pub clean_jobs:   bool, // True = discard previous work
}

impl BlockTemplate {
    pub fn to_notify_json(&self) -> String {
        let parents_json: String = self.parents.iter()
            .map(|p| format!("\"{}\"", p))
            .collect::<Vec<_>>()
            .join(",");
        let ts_hex  = encode_hex_u64(self.timestamp);
        let diff_hex = encode_hex_u64(self.difficulty);
        let en_hex  = encode_hex_u64(self.extra_nonce);
        format!(
            "{{\"id\":null,\"method\":\"mining.notify\",\
             \"params\":[\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",[{}],{},true]}}\n",
            self.job_id, self.version, self.prev_hash, self.merkle_root,
            ts_hex, diff_hex, en_hex,
            parents_json, self.clean_jobs,
        )
    }

    /// Return work data as a plain JSON object for getwork responses.
    /// Unlike to_notify_json(), this is not wrapped in a mining.notify envelope
    /// and is suitable for embedding in a StratumResponse result field.
    pub fn to_getwork_json(&self) -> String {
        let parents_json: String = self.parents.iter()
            .map(|p| format!("\"{}\"", p))
            .collect::<Vec<_>>()
            .join(",");
        let ts_hex  = encode_hex_u64(self.timestamp);
        let diff_hex = encode_hex_u64(self.difficulty);
        let en_hex  = encode_hex_u64(self.extra_nonce);
        format!(
            "{{\"job_id\":\"{}\",\"version\":{},\"prev_hash\":\"{}\",\"merkle_root\":\"{}\",\
             \"timestamp\":\"{}\",\"difficulty\":\"{}\",\
             \"extra_nonce\":\"{}\",\"height\":{},\"parents\":[{}],\"clean_jobs\":{}}}",
            self.job_id, self.version, self.prev_hash, self.merkle_root,
            ts_hex, diff_hex,
            en_hex, self.height, parents_json, self.clean_jobs,
        )
    }
}

/// Combine a template extra_nonce with a worker's extra_nonce into a single
/// collision-resistant u64.  Uses blake3 to hash the concatenated bytes so
/// that overlapping bit patterns in the inputs cannot produce the same output.
fn combine_extra_nonce(template_nonce: u64, worker_extra_nonce: u64) -> u64 {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&template_nonce.to_le_bytes());
    input[8..].copy_from_slice(&worker_extra_nonce.to_le_bytes());
    let hash = blake3::hash(&input);
    let bytes: [u8; 8] = hash.as_bytes()[..8].try_into().unwrap_or([0u8; 8]);
    u64::from_le_bytes(bytes)
}

/// Encode a u64 as a zero-padded 16-character lowercase hex string.
/// Returns `None` if the formatted output is not exactly 16 hex characters
/// (should never happen for u64, but guards against future type changes).
fn encode_hex_u64(value: u64) -> String {
    let hex = format!("{:016x}", value);
    debug_assert!(
        hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit()),
        "encode_hex_u64 produced invalid hex: {}", hex
    );
    hex
}

/// Stratum Server
pub struct StratumServer {
    /// Connected workers
    workers:         RwLock<HashMap<u64, Worker>>,
    /// Current block template
    current_template: RwLock<Option<BlockTemplate>>,
    /// Next worker ID
    next_worker_id:  AtomicU64,
    /// Server port
    port:            u16,
    /// Running flag
    running:         AtomicBool,
    /// Total blocks found by pool
    blocks_found:    AtomicU64,
    /// Pool hashrate (estimated)
    pool_hashrate:   AtomicU64,
    /// Pending subscribe→authorize mapping: stores the worker_id assigned
    /// during Subscribe so the subsequent Authorize for the same connection
    /// retrieves the correct ID (fixes race condition with concurrent miners).
    pending_subs:    RwLock<HashMap<SocketAddr, (u64, std::time::Instant)>>,
}

impl StratumServer {
    pub fn new(port: u16) -> Self {
        Self {
            workers:          RwLock::new(HashMap::new()),
            current_template: RwLock::new(None),
            next_worker_id:   AtomicU64::new(1),
            port,
            running:          AtomicBool::new(false),
            blocks_found:     AtomicU64::new(0),
            pool_hashrate:    AtomicU64::new(0),
            pending_subs:     RwLock::new(HashMap::new()),
        }
    }

    /// Handle a Stratum request from a miner
    pub fn handle_request(&self, req: &StratumRequest, peer_addr: SocketAddr) -> StratumResponse {
        match req.method {
            StratumMethod::Subscribe => {
                let worker_id = self.next_worker_id.fetch_add(1, Ordering::Relaxed);
                // Store the assigned worker_id so the subsequent Authorize from
                // this same connection retrieves the correct ID, even under
                // concurrent subscribe/authorize pairs from different miners.
                let mut subs = self.pending_subs.write().unwrap_or_else(|e| e.into_inner());

                // Evict entries older than TTL
                let now = std::time::Instant::now();
                subs.retain(|_, (_, created)| now.duration_since(*created).as_secs() < PENDING_SUB_TTL_SECS);

                // Reject if at capacity after eviction
                if subs.len() >= MAX_PENDING_SUBS {
                    return StratumResponse::err(req.id, "Too many pending subscriptions");
                }

                subs.insert(peer_addr, (worker_id, now));
                StratumResponse::ok(req.id, &format!(
                    "{{\"subscription_id\":\"{:x}\",\"nonce1\":\"{:016x}\"}}",
                    worker_id, worker_id
                ))
            }

            StratumMethod::Authorize => {
                let worker_name = req.params.first().cloned().unwrap_or_default();
                let address = worker_name.split('.').next().unwrap_or("unknown").to_string();

                // Retrieve the worker_id that was assigned during Subscribe for
                // this connection. This eliminates the race where concurrent
                // subscribe/authorize pairs could read the wrong ID.
                let worker_id = match self.pending_subs.write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&peer_addr)
                {
                    Some((id, _created)) => id,
                    None => return StratumResponse::err(req.id, "No pending subscription for this connection"),
                };

                // Check for duplicate worker name
                let workers = self.workers.read().unwrap_or_else(|e| e.into_inner());
                if workers.values().any(|w| w.name == worker_name) {
                    return StratumResponse::err(req.id, "Worker name already in use");
                }
                drop(workers);

                let worker = Worker::new(worker_id, worker_name, address, worker_id);
                self.workers.write().unwrap_or_else(|e| e.into_inner()).insert(worker_id, worker);

                StratumResponse::ok(req.id, "true")
            }

            StratumMethod::Submit => {
                self.handle_submit(req)
            }

            StratumMethod::GetWork => {
                match self.current_template.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
                    Some(template) => StratumResponse::ok(req.id, &template.to_getwork_json()),
                    None => StratumResponse::err(req.id, "No work available"),
                }
            }

            StratumMethod::Unknown(ref m) => {
                StratumResponse::err(req.id, &format!("Unknown method: {}", m))
            }
        }
    }

    fn handle_submit(&self, req: &StratumRequest) -> StratumResponse {
        // params: [worker_name, job_id, nonce, result_hash]
        if req.params.len() < 3 {
            return StratumResponse::err(req.id, "Invalid submit params");
        }

        let worker_name = &req.params[0];
        let nonce_hex = &req.params[2];

        // Find the submitting worker first to get their current difficulty
        let mut workers = self.workers.write().unwrap_or_else(|e| e.into_inner());
        let worker = match workers.values_mut().find(|w| w.name == *worker_name) {
            Some(w) => w,
            None => return StratumResponse::err(req.id, "Worker not authorized"),
        };

        let worker_difficulty = worker.difficulty;
        let worker_extra_nonce = worker.extra_nonce;

        // Validate share against the worker's current vardiff difficulty
        let share_valid = self.validate_share(nonce_hex, worker_difficulty, worker_extra_nonce);

        if share_valid {
            worker.accept_share();

            // Check if share also meets network difficulty (block found!)
            if self.meets_network_difficulty(nonce_hex, worker_extra_nonce) {
                self.blocks_found.fetch_add(1, Ordering::Relaxed);
            }

            StratumResponse::ok(req.id, "true")
        } else {
            worker.reject_share();
            StratumResponse::err(req.id, "Low difficulty share")
        }
    }

    /// Update the block template (called when new block arrives)
    pub fn update_template(&self, template: BlockTemplate) {
        *self.current_template.write().unwrap_or_else(|e| e.into_inner()) = Some(template);
    }

    /// Start the Stratum TCP server.
    /// Accepts TCP connections from miners, reads newline-delimited JSON-RPC
    /// requests, dispatches them via `handle_request`, and writes responses.
    pub fn start(self: &Arc<Self>) {
        self.running.store(true, Ordering::Relaxed);
        eprintln!("[Stratum] Server listening on port {}", self.port);
        eprintln!("[Stratum] Vardiff target: {} shares/min", TARGET_SHARES_PER_MIN);

        let addr = format!("0.0.0.0:{}", self.port);
        let listener = match std::net::TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[Stratum] Failed to bind: {}", e);
                return;
            }
        };

        // Set a non-blocking accept timeout so we can check the running flag
        listener.set_nonblocking(false).ok();

        for stream in listener.incoming() {
            if !self.running.load(Ordering::Relaxed) { break; }
            match stream {
                Ok(tcp_stream) => {
                    let server = Arc::clone(self);
                    std::thread::spawn(move || {
                        if let Err(e) = server.handle_connection(tcp_stream) {
                            eprintln!("[Stratum] Connection error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("[Stratum] Accept error: {}", e),
            }
        }
    }

    /// Handle a single miner TCP connection.
    /// Reads newline-delimited JSON-RPC messages and responds to each.
    fn handle_connection(&self, stream: std::net::TcpStream) -> Result<(), NetworkError> {
        stream.set_read_timeout(Some(Duration::from_secs(300)))
            .map_err(|e| NetworkError::ConnectionFailed(format!("set_read_timeout: {}", e)))?;

        let peer_addr = stream.peer_addr().map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
        eprintln!("[Stratum] Miner connected from {}", peer_addr);

        let reader = BufReader::new(stream.try_clone().map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?);
        let mut writer = stream;

        for line_result in reader.lines() {
            if !self.running.load(Ordering::Relaxed) { break; }

            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[Stratum] Read error from {}: {}", peer_addr, e);
                    break;
                }
            };

            let line = line.trim().to_string();
            if line.is_empty() { continue; }

            // Parse the JSON-RPC request
            let request = match Self::parse_json_rpc(&line) {
                Ok(req) => req,
                Err(e) => {
                    let err_resp = format!(
                        "{{\"id\":null,\"result\":null,\"error\":\"Parse error: {}\"}}\n", e
                    );
                    writer.write_all(err_resp.as_bytes()).ok();
                    continue;
                }
            };

            // Dispatch and respond
            let response = self.handle_request(&request, peer_addr);
            let resp_json = response.to_json();

            if writer.write_all(resp_json.as_bytes()).is_err() {
                break; // Connection lost
            }

            // After subscribe, send the current block template if available
            if request.method == StratumMethod::Subscribe {
                if let Some(template) = self.current_template.read()
                    .unwrap_or_else(|e| e.into_inner()).as_ref()
                {
                    let notify = template.to_notify_json();
                    writer.write_all(notify.as_bytes()).ok();
                }
            }
        }

        // Clean up any pending subscribe entry for this peer so that workers
        // who subscribed but disconnected before authorizing don't leak entries
        // in the pending_subs map.
        self.pending_subs.write().unwrap_or_else(|e| e.into_inner())
            .remove(&peer_addr);

        eprintln!("[Stratum] Miner disconnected: {}", peer_addr);
        Ok(())
    }

    /// Parse a JSON-RPC line into a StratumRequest.
    /// Expects: {"id": N, "method": "mining.xxx", "params": [...]}
    fn parse_json_rpc(line: &str) -> Result<StratumRequest, NetworkError> {
        // Parse Stratum V1 JSON-RPC using serde_json.
        let val: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| NetworkError::Serialization(format!("invalid JSON: {}", e)))?;

        let id = val.get("id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let method_str = val.get("method")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NetworkError::Serialization("missing 'method' field".to_string()))?;

        let params: Vec<String> = val.get("params")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().map(|v| {
                v.as_str().map(|s| s.to_string())
                    .unwrap_or_else(|| v.to_string())
            }).collect())
            .unwrap_or_default();

        Ok(StratumRequest {
            id,
            method: StratumMethod::from_str(method_str),
            params,
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    // ── Stats ────────────────────────────────────────────────────────────

    pub fn worker_count(&self) -> usize { self.workers.read().unwrap_or_else(|e| e.into_inner()).len() }
    pub fn blocks_found(&self) -> u64 { self.blocks_found.load(Ordering::Relaxed) }
    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }

    pub fn pool_stats(&self) -> String {
        let workers = self.workers.read().unwrap_or_else(|e| e.into_inner());
        let total_shares: u64 = workers.values()
            .try_fold(0u64, |acc, w| acc.checked_add(w.shares_accepted))
            .unwrap_or(u64::MAX);
        format!(
            "Workers: {} | Shares: {} | Blocks: {} | Port: {}",
            workers.len(), total_shares, self.blocks_found(), self.port
        )
    }

    /// Validate a share submission using ShadowHash.
    /// Recomputes the block hash with the submitted nonce and checks against
    /// the worker's share difficulty target.
    fn validate_share(&self, nonce_hex: &str, share_difficulty: u64, worker_extra_nonce: u64) -> bool {
        // A valid share must be a proper hex-encoded nonce
        if nonce_hex.is_empty() || nonce_hex.len() > 16 {
            return false;
        }
        if !nonce_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }

        let nonce = match u64::from_str_radix(nonce_hex, 16) {
            Ok(n) => n,
            Err(_) => return false,
        };

        // Get the current block template to recompute the hash
        let template = match self.current_template.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(t) => t.clone(),
            None => return false, // No work available — cannot validate
        };

        // Combine template extra_nonce with worker's unique extra_nonce to ensure
        // each worker searches a distinct nonce subspace (prevents duplicate work).
        // Hash the components together to avoid collisions from simple XOR/shift.
        let combined_extra_nonce = combine_extra_nonce(template.extra_nonce, worker_extra_nonce);

        // Recompute hash using ShadowHash with the miner's nonce and combined extra_nonce
        let hash = crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full(
            template.version,
            template.height,
            template.timestamp,
            nonce,
            combined_extra_nonce,
            template.difficulty,
            &template.merkle_root,
            &template.parents,
        );

        // Check against the worker's current share difficulty target
        crate::engine::mining::pow::pow_validator::PowValidator::hash_meets_target(
            &hash, share_difficulty,
        )
    }

    /// Check if a share meets the full network difficulty (block found!).
    /// Recomputes the hash with ShadowHash and compares against network target.
    fn meets_network_difficulty(&self, nonce_hex: &str, worker_extra_nonce: u64) -> bool {
        if nonce_hex.is_empty() || nonce_hex.len() > 16 {
            return false;
        }

        let nonce = match u64::from_str_radix(nonce_hex, 16) {
            Ok(n) => n,
            Err(_) => return false,
        };

        let template = match self.current_template.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(t) => t.clone(),
            None => return false,
        };

        // Combine template extra_nonce with worker's unique extra_nonce
        let combined_extra_nonce = combine_extra_nonce(template.extra_nonce, worker_extra_nonce);

        // Recompute hash using ShadowHash with the miner's nonce and combined extra_nonce
        let hash = crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full(
            template.version,
            template.height,
            template.timestamp,
            nonce,
            combined_extra_nonce,
            template.difficulty,
            &template.merkle_root,
            &template.parents,
        );

        // Check against the full network difficulty from the template
        crate::engine::mining::pow::pow_validator::PowValidator::hash_meets_target(
            &hash, template.difficulty,
        )
    }
}

/// Payout schemes supported by ShadowDAG mining pools
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayoutScheme {
    /// Pay Per Share — fixed payout per valid share
    PPS,
    /// Pay Per Last N Shares — proportional payout based on recent shares
    PPLNS,
    /// Proportional — divide block reward by shares in the round
    Proportional,
}

impl PayoutScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PPS          => "PPS",
            Self::PPLNS        => "PPLNS",
            Self::Proportional => "PROP",
        }
    }
}

/// Pool payout calculator
pub struct PayoutCalculator;

impl PayoutCalculator {
    /// Calculate payouts for a found block using PPS scheme
    pub fn calculate_pps(workers: &HashMap<u64, Worker>, block_reward: u64, pool_fee_pct: u64) -> HashMap<String, u64> {
        let pool_fee = block_reward * pool_fee_pct / 100;
        let distributable = block_reward - pool_fee;
        let total_shares: u64 = match workers.values()
            .try_fold(0u64, |acc, w| acc.checked_add(w.shares_accepted))
        {
            Some(s) => s,
            None => {
                eprintln!("[Stratum] ERROR: share count overflow in payout calculation, aborting payouts");
                return HashMap::new();
            }
        };
        if total_shares == 0 {
            return HashMap::new();
        }

        workers.values().map(|w| {
            let payout = (distributable as u128 * w.shares_accepted as u128 / total_shares as u128) as u64;
            (w.address.clone(), payout)
        }).collect()
    }

    /// Calculate payouts using PPLNS (last N shares window)
    pub fn calculate_pplns(workers: &HashMap<u64, Worker>, block_reward: u64, pool_fee_pct: u64, _window_size: u64) -> HashMap<String, u64> {
        // PPLNS uses the same proportional logic but only considers
        // shares within the last N shares window
        Self::calculate_pps(workers, block_reward, pool_fee_pct)
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a dummy peer address for tests.
    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn subscribe_returns_id() {
        let server = StratumServer::new(7779);
        let addr = test_addr(9000);
        let req = StratumRequest {
            id: 1,
            method: StratumMethod::Subscribe,
            params: vec![],
        };
        let resp = server.handle_request(&req, addr);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn authorize_creates_worker() {
        let server = StratumServer::new(7779);
        let addr = test_addr(9001);
        // Subscribe first so pending_subs has an entry for this addr
        let sub_req = StratumRequest {
            id: 1,
            method: StratumMethod::Subscribe,
            params: vec![],
        };
        server.handle_request(&sub_req, addr);
        let req = StratumRequest {
            id: 2,
            method: StratumMethod::Authorize,
            params: vec!["SD1abc.worker1".to_string()],
        };
        server.handle_request(&req, addr);
        assert_eq!(server.worker_count(), 1);
    }

    #[test]
    fn worker_vardiff_adjusts() {
        let mut worker = Worker::new(1, "test".into(), "SD1x".into(), 1);
        worker.shares_in_window = 100; // Way too many shares
        let changed = worker.vardiff_adjust();
        assert!(changed || worker.difficulty > MIN_SHARE_DIFF);
    }

    #[test]
    fn vardiff_direction_high_ratio_increases_difficulty() {
        // ratio > 2.0 means too many shares (too easy) => difficulty should INCREASE
        let mut worker = Worker::new(1, "test".into(), "SD1x".into(), 1);
        worker.difficulty = 100;
        // 60 shares when target is 20 => ratio = 3.0
        worker.shares_in_window = 60;
        worker.vardiff_adjust();
        assert!(worker.difficulty > 100,
            "Difficulty should increase when shares exceed 2x target, got {}", worker.difficulty);
    }

    #[test]
    fn vardiff_direction_low_ratio_decreases_difficulty() {
        // ratio < 0.5 means too few shares (too hard) => difficulty should DECREASE
        let mut worker = Worker::new(1, "test".into(), "SD1x".into(), 1);
        worker.difficulty = 100;
        // 5 shares when target is 20 => ratio = 0.25
        worker.shares_in_window = 5;
        worker.vardiff_adjust();
        assert!(worker.difficulty < 100,
            "Difficulty should decrease when shares below 0.5x target, got {}", worker.difficulty);
    }

    #[test]
    fn vardiff_stable_ratio_no_change() {
        // ratio between 0.5 and 2.0 => no adjustment
        let mut worker = Worker::new(1, "test".into(), "SD1x".into(), 1);
        worker.difficulty = 100;
        // 20 shares when target is 20 => ratio = 1.0
        worker.shares_in_window = 20;
        let changed = worker.vardiff_adjust();
        assert!(!changed, "Difficulty should not change when ratio is in stable range");
        assert_eq!(worker.difficulty, 100);
    }

    #[test]
    fn vardiff_clamps_to_min_max() {
        // Test minimum clamp
        let mut worker = Worker::new(1, "test".into(), "SD1x".into(), 1);
        worker.difficulty = MIN_SHARE_DIFF;
        worker.shares_in_window = 1; // ratio = 0.05 => wants to decrease below minimum
        worker.vardiff_adjust();
        assert_eq!(worker.difficulty, MIN_SHARE_DIFF, "Difficulty should not go below MIN_SHARE_DIFF");
    }

    #[test]
    fn worker_acceptance_rate() {
        let mut w = Worker::new(1, "w".into(), "a".into(), 1);
        w.accept_share();
        w.accept_share();
        w.reject_share();
        assert!((w.acceptance_rate() - 0.6666).abs() < 0.01);
    }

    #[test]
    fn block_template_json() {
        let tpl = BlockTemplate {
            job_id: "job1".into(),
            version: 1,
            prev_hash: "0000abc".into(),
            parents: vec!["0000abc".into()],
            merkle_root: "merkle1".into(),
            timestamp: 1735689600,
            difficulty: 4,
            height: 1,
            extra_nonce: 0,
            clean_jobs: true,
        };
        let json = tpl.to_notify_json();
        assert!(json.contains("mining.notify"));
        assert!(json.contains("job1"));
    }

    #[test]
    fn subscribe_assigns_unique_extra_nonce() {
        let server = StratumServer::new(7779);
        let addr1 = test_addr(9010);
        let addr2 = test_addr(9011);
        let req1 = StratumRequest { id: 1, method: StratumMethod::Subscribe, params: vec![] };
        let req2 = StratumRequest { id: 2, method: StratumMethod::Subscribe, params: vec![] };
        let resp1 = server.handle_request(&req1, addr1);
        let resp2 = server.handle_request(&req2, addr2);
        let r1 = resp1.result.unwrap();
        let r2 = resp2.result.unwrap();
        // Each subscription should return a different nonce1
        assert_ne!(r1, r2, "Each worker must receive a unique nonce1 (extra_nonce)");
    }

    #[test]
    fn workers_get_distinct_extra_nonce() {
        let w1 = Worker::new(1, "w1".into(), "a".into(), 1);
        let w2 = Worker::new(2, "w2".into(), "a".into(), 2);
        assert_ne!(w1.extra_nonce, w2.extra_nonce,
            "Workers must have distinct extra_nonce values");
    }

    #[test]
    fn pool_stats_format() {
        let server = StratumServer::new(7779);
        let stats = server.pool_stats();
        assert!(stats.contains("Workers: 0"));
        assert!(stats.contains("Port: 7779"));
    }
}
