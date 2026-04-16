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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::config::consensus::consensus_params::ConsensusParams;
use crate::service::network::rpc::rpc_server::RpcState;
use crate::{slog_error, slog_info};

pub mod html;

type SharedState = Arc<Mutex<RpcState>>;

const MAX_EXPLORER_CONNECTIONS: usize = 100;
const EXPLORER_READ_TIMEOUT_SECS: u64 = 5;

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
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("Explorer bind failed on {}: {}", addr, e))?;
        self.running.store(true, Ordering::SeqCst);
        slog_info!("explorer", "listening", addr => &addr);

        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);

        std::thread::spawn(move || {
            let mut active_connections = 0usize;
            for stream in listener.incoming() {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(stream) => {
                        if active_connections >= MAX_EXPLORER_CONNECTIONS {
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        }
                        active_connections += 1;
                        let state = Arc::clone(&state);
                        std::thread::spawn(move || {
                            Self::handle_connection(stream, &state);
                        });
                        // Approximate: we don't decrement on completion (lightweight)
                        if active_connections > 10 {
                            active_connections -= 1;
                        }
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
        if reader.read_line(&mut request_line).is_err() {
            return;
        }

        // Consume remaining headers (we only need the first line)
        let mut header_line = String::new();
        loop {
            header_line.clear();
            match reader.read_line(&mut header_line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
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
            p if p.starts_with("/api/block/") => {
                let id = &p["/api/block/".len()..];
                Self::api_block_detail(&mut stream, state, id);
            }
            p if p.starts_with("/api/address/") => {
                let addr = &p["/api/address/".len()..];
                Self::api_address(&mut stream, state, addr);
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

    fn send_json(stream: &mut TcpStream, data: &serde_json::Value) {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        Self::send_response(stream, 200, "application/json", body.as_bytes());
    }

    fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let status_text = match status {
            200 => "OK",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "Unknown",
        };
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Connection: close\r\n\
             \r\n",
            status, status_text, content_type, body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }
}
