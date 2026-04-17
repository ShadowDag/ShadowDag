// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Explorer HTTP Server — lightweight web UI for browsing the blockchain.
//
// Architecture:
//   - Thread-per-connection HTTP server (same pattern as the RPC server)
//   - GET /          → embedded single-page HTML dashboard
//   - GET /api/*     → JSON endpoints that query the node's RPC state
//   - All other      → 404
//
// The explorer reuses the same SharedState (Arc<Mutex<RpcState>>) that the
// RPC server uses, so it has direct access to BlockStore, UtxoSet, Mempool,
// PeerManager, etc. without any HTTP proxying.
// ═══════════════════════════════════════════════════════════════════════════

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::config::consensus::consensus_params::ConsensusParams;
use crate::service::network::rpc::rpc_server::RpcState;
use crate::{slog_error, slog_info};

pub mod html;

type SharedState = Arc<Mutex<RpcState>>;

const MAX_EXPLORER_CONNECTIONS: usize = 100;
const EXPLORER_READ_TIMEOUT_SECS: u64 = 5;
const MAX_REQUEST_LINE_BYTES: usize = 4096;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;

pub struct ExplorerServer {
    port: u16,
    state: SharedState,
    running: Arc<AtomicBool>,
}

impl ExplorerServer {
    pub fn new(port: u16, state: SharedState) -> Self {
        Self {
            port,
            state,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self) -> Result<(), String> {
        let bind_host = std::env::var("SHADOWDAG_EXPLORER_BIND")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let addr = format!("{}:{}", bind_host, self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("Explorer bind failed on {}: {}", addr, e))?;
        self.running.store(true, Ordering::SeqCst);
        slog_info!("explorer", "listening", addr => &addr);

        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let active_connections = Arc::new(AtomicUsize::new(0));

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(stream) => {
                        let prev = active_connections.fetch_add(1, Ordering::AcqRel);
                        if prev >= MAX_EXPLORER_CONNECTIONS {
                            active_connections.fetch_sub(1, Ordering::Relaxed);
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        }
                        let state = Arc::clone(&state);
                        let active_connections = Arc::clone(&active_connections);
                        std::thread::spawn(move || {
                            Self::handle_connection(stream, &state);
                            active_connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        slog_error!("explorer", "accept_error", error => e);
                    }
                }
            }
        });

        Ok(())
    }

    fn handle_connection(mut stream: TcpStream, state: &SharedState) {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(
            EXPLORER_READ_TIMEOUT_SECS,
        )));

        let clone = match stream.try_clone() {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut reader = BufReader::new(clone);
        let mut request_line = String::new();
        let req_read = {
            let mut limited = (&mut reader).take(MAX_REQUEST_LINE_BYTES as u64);
            limited.read_line(&mut request_line)
        };
        if req_read.is_err() {
            return;
        }
        if request_line.len() >= MAX_REQUEST_LINE_BYTES && !request_line.ends_with('\n') {
            Self::send_response(&mut stream, 414, "text/plain", b"Request line too long");
            return;
        }

        // Consume remaining headers (we only need the first line)
        let mut header_line = String::new();
        let mut header_lines = 0usize;
        let mut header_bytes = 0usize;
        loop {
            header_line.clear();
            match reader.read_line(&mut header_line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    header_lines += 1;
                    header_bytes += header_line.len();
                    if header_lines > MAX_HEADER_LINES || header_bytes > MAX_HEADER_BYTES {
                        Self::send_response(&mut stream, 431, "text/plain", b"Request headers too large");
                        return;
                    }
                    if header_line.trim().is_empty() {
                        break;
                    }
                }
            }
        }

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }
        let method = parts[0];
        let path = parts[1];

        // Input sanitization: reject oversized paths (DoS prevention)
        if path.len() > 512 {
            Self::send_response(&mut stream, 414, "text/plain", b"URI Too Long");
            return;
        }

        if method != "GET" {
            Self::send_response(&mut stream, 405, "text/plain", b"Method Not Allowed");
            return;
        }

        match path {
            "/" | "/index.html" => {
                Self::send_response(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    html::EXPLORER_HTML.as_bytes(),
                );
            }
            "/api/stats" => Self::api_stats(&mut stream, state),
            "/api/blocks" => Self::api_blocks(&mut stream, state),
            "/api/pool" => Self::api_pool(&mut stream),
            "/api/mempool" => Self::api_mempool(&mut stream, state),
            "/api/dag" => Self::api_dag(&mut stream, state),
            "/api/network" => Self::api_network(&mut stream, state),
            "/api/richlist" => Self::api_richlist(&mut stream, state),
            p if p.starts_with("/api/block/") => {
                let id = &p["/api/block/".len()..];
                Self::api_block_detail(&mut stream, state, id);
            }
            p if p.starts_with("/api/tx/") => {
                let hash = &p["/api/tx/".len()..];
                Self::api_tx_detail(&mut stream, state, hash);
            }
            p if p.starts_with("/api/address/") => {
                let addr = &p["/api/address/".len()..];
                Self::api_address(&mut stream, state, addr);
            }
            p if p.starts_with("/api/search/") => {
                let query = &p["/api/search/".len()..];
                Self::api_search(&mut stream, state, query);
            }
            _ => {
                Self::send_response(&mut stream, 404, "text/plain", b"Not Found");
            }
        }
    }

    fn api_stats(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(s) => {
                json!({
                    "best_height": s.best_height,
                    "best_hash": s.best_hash,
                    "block_count": s.block_store.count(),
                    "peer_count": s.peer_manager.count(),
                    "mempool_size": s.mempool.count(),
                    "network": s.network_name,
                    "version": s.node_version,
                    "p2p_port": s.p2p_port,
                    "rpc_port": s.rpc_port,
                    "chain_name": ConsensusParams::CHAIN_NAME,
                    "chain_id": format!("0x{:08X}", ConsensusParams::CHAIN_ID),
                    "max_supply": ConsensusParams::MAX_SUPPLY,
                    "algorithm": "ShadowHash (SHA256+Blake3+SHA3-256+AntiASIC)",
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_blocks(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(s) => {
                let height = s.best_height;
                let mut blocks = Vec::new();
                let start = if height > 20 { height - 20 } else { 0 };
                for h in (start..=height).rev() {
                    let hashes = s.block_store.get_block_hashes_at_height(h);
                    for hash in hashes {
                        if let Some(block) = s.block_store.get_block(&hash) {
                            blocks.push(json!({
                                "hash": block.header.hash,
                                "height": block.header.height,
                                "timestamp": block.header.timestamp,
                                "difficulty": block.header.difficulty,
                                "tx_count": block.body.transactions.len(),
                                "parents": block.header.parents.len(),
                            }));
                        }
                        if blocks.len() >= 40 {
                            break;
                        }
                    }
                    if blocks.len() >= 40 {
                        break;
                    }
                }
                json!({ "blocks": blocks, "best_height": height })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_block_detail(stream: &mut TcpStream, state: &SharedState, id: &str) {
        let data = match state.lock() {
            Ok(s) => {
                // Try as hash first, then as height
                let block = s.block_store.get_block(id).or_else(|| {
                    id.parse::<u64>().ok().and_then(|h| {
                        let hashes = s.block_store.get_block_hashes_at_height(h);
                        hashes.first().and_then(|hash| s.block_store.get_block(hash))
                    })
                });
                match block {
                    Some(b) => json!({
                        "hash": b.header.hash,
                        "height": b.header.height,
                        "timestamp": b.header.timestamp,
                        "difficulty": b.header.difficulty,
                        "version": b.header.version,
                        "nonce": b.header.nonce,
                        "merkle_root": b.header.merkle_root,
                        "parents": b.header.parents,
                        "tx_count": b.body.transactions.len(),
                        "transactions": b.body.transactions.iter().map(|tx| {
                            json!({
                                "hash": tx.hash,
                                "inputs": tx.inputs.len(),
                                "outputs": tx.outputs.len(),
                                "fee": tx.fee,
                            })
                        }).collect::<Vec<_>>(),
                    }),
                    None => json!({"error": "block not found"}),
                }
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_address(stream: &mut TcpStream, state: &SharedState, addr: &str) {
        let data = match state.lock() {
            Ok(s) => {
                let balance = s.utxo_store.get_balance(addr);
                json!({
                    "address": addr,
                    "balance": balance,
                    "balance_sdag": balance as f64 / 100_000_000.0,
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_pool(stream: &mut TcpStream) {
        let data = if let Some(stratum) =
            crate::service::network::rpc::rpc_server::STRATUM_INSTANCE.get()
        {
            json!({
                "status": "active",
                "workers": stratum.worker_count(),
                "blocks_found": stratum.blocks_found(),
                "pool_fee_pct": 2,
            })
        } else {
            json!({
                "status": "disabled",
                "workers": 0,
                "blocks_found": 0,
                "pool_fee_pct": 2,
            })
        };
        Self::send_json(stream, &data);
    }

    fn api_tx_detail(stream: &mut TcpStream, state: &SharedState, hash: &str) {
        let data = match state.lock() {
            Ok(s) => {
                // Search through recent blocks for the transaction
                let height = s.best_height;
                let start = if height > 200 { height - 200 } else { 0 };
                let mut found = None;
                'outer: for h in (start..=height).rev() {
                    let hashes = s.block_store.get_block_hashes_at_height(h);
                    for bh in hashes {
                        if let Some(block) = s.block_store.get_block(&bh) {
                            for tx in &block.body.transactions {
                                if tx.hash == hash {
                                    found = Some((tx.clone(), block.header.hash.clone(), block.header.height));
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
                // Also check mempool
                if found.is_none() {
                    for tx in s.mempool.get_all_transactions() {
                        if tx.hash == hash {
                            found = Some((tx, String::new(), 0));
                            break;
                        }
                    }
                }
                match found {
                    Some((tx, block_hash, block_height)) => json!({
                        "hash": tx.hash,
                        "block_hash": block_hash,
                        "block_height": block_height,
                        "is_coinbase": tx.is_coinbase,
                        "fee": tx.fee,
                        "timestamp": tx.timestamp,
                        "tx_type": format!("{:?}", tx.tx_type),
                        "inputs": tx.inputs.iter().map(|i| json!({
                            "txid": i.txid,
                            "index": i.index,
                            "owner": i.owner,
                        })).collect::<Vec<_>>(),
                        "outputs": tx.outputs.iter().map(|o| json!({
                            "address": o.address,
                            "amount": o.amount,
                        })).collect::<Vec<_>>(),
                        "total_output": tx.outputs.iter().map(|o| o.amount).sum::<u64>(),
                        "confirmed": !block_hash.is_empty(),
                    }),
                    None => json!({"error": "transaction not found"}),
                }
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_mempool(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(s) => {
                let txs = s.mempool.get_all_transactions();
                let count = txs.len();
                let total_fees: u64 = txs.iter().map(|t| t.fee).sum();
                let items: Vec<_> = txs.iter().take(50).map(|tx| {
                    json!({
                        "hash": tx.hash,
                        "fee": tx.fee,
                        "timestamp": tx.timestamp,
                        "tx_type": format!("{:?}", tx.tx_type),
                        "inputs": tx.inputs.len(),
                        "outputs": tx.outputs.len(),
                        "total_output": tx.outputs.iter().map(|o| o.amount).sum::<u64>(),
                    })
                }).collect();
                json!({
                    "count": count,
                    "total_fees": total_fees,
                    "transactions": items,
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_dag(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(s) => {
                let height = s.best_height;
                let start = if height > 30 { height - 30 } else { 0 };
                let mut nodes = Vec::new();
                let mut edges = Vec::new();
                for h in start..=height {
                    let hashes = s.block_store.get_block_hashes_at_height(h);
                    for hash in &hashes {
                        if let Some(block) = s.block_store.get_block(hash) {
                            nodes.push(json!({
                                "id": &block.header.hash[..12],
                                "hash": block.header.hash,
                                "height": block.header.height,
                                "tx_count": block.body.transactions.len(),
                                "timestamp": block.header.timestamp,
                            }));
                            for parent in &block.header.parents {
                                edges.push(json!({
                                    "from": &parent[..std::cmp::min(12, parent.len())],
                                    "to": &block.header.hash[..12],
                                }));
                            }
                        }
                    }
                }
                json!({
                    "nodes": nodes,
                    "edges": edges,
                    "best_height": height,
                    "depth": height.saturating_sub(start),
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_network(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(s) => {
                let peer_count = s.peer_manager.count();
                json!({
                    "peer_count": peer_count,
                    "node_version": s.node_version,
                    "network": s.network_name,
                    "p2p_port": s.p2p_port,
                    "rpc_port": s.rpc_port,
                    "best_height": s.best_height,
                    "best_hash": s.best_hash,
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_richlist(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(_s) => {
                // Rich-list requires a dedicated indexed view of address balances.
                // Full UTXO scans are intentionally not exposed by UtxoSet to avoid
                // expensive unbounded RPC work and accidental data-layer coupling.
                json!({
                    "total_addresses": 0,
                    "richlist": [],
                    "note": "Richlist index is not enabled on this node build",
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_search(stream: &mut TcpStream, state: &SharedState, query: &str) {
        let data = match state.lock() {
            Ok(s) => {
                // Determine query type and search accordingly
                let q = query.trim();
                // Check if it's a number (height)
                if let Ok(height) = q.parse::<u64>() {
                    let hashes = s.block_store.get_block_hashes_at_height(height);
                    if !hashes.is_empty() {
                        return Self::send_json(stream, &json!({"type": "block", "id": hashes[0]}));
                    }
                }
                // Check if it's an address (starts with S)
                if q.starts_with('S') || q.starts_with('s') {
                    let balance = s.utxo_store.get_balance(q);
                    return Self::send_json(stream, &json!({"type": "address", "id": q, "balance": balance}));
                }
                // Try as block hash
                if s.block_store.get_block(q).is_some() {
                    return Self::send_json(stream, &json!({"type": "block", "id": q}));
                }
                // Try as transaction hash (search recent blocks)
                let height = s.best_height;
                let start = if height > 100 { height - 100 } else { 0 };
                for h in (start..=height).rev() {
                    for bh in s.block_store.get_block_hashes_at_height(h) {
                        if let Some(block) = s.block_store.get_block(&bh) {
                            for tx in &block.body.transactions {
                                if tx.hash == q {
                                    return Self::send_json(stream, &json!({"type": "tx", "id": q}));
                                }
                            }
                        }
                    }
                }
                json!({"type": "not_found", "query": q})
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn send_json(stream: &mut TcpStream, data: &serde_json::Value) {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        Self::send_response(stream, 200, "application/json", body.as_bytes());
    }

    fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let status_text = match status {
            200 => "OK",
            404 => "Not Found",
            405 => "Method Not Allowed",
            414 => "URI Too Long",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            _ => "Unknown",
        };
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            status, status_text, content_type, body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }
}
