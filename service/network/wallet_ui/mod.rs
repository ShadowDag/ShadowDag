// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Desktop Wallet Web UI — a local-only HTTP server that provides a
// graphical wallet interface through the browser.
//
// Architecture:
//   - Thread-per-connection HTTP server (same pattern as Explorer/RPC)
//   - Binds to 127.0.0.1 ONLY (never exposed to the network)
//   - GET /          → embedded single-page wallet HTML
//   - GET /api/*     → JSON endpoints for wallet operations
//   - POST /api/*    → JSON endpoints for send/create operations
//
// The wallet UI shares the node's SharedState for balance queries and
// transaction broadcasting, while wallet-specific operations (keys, signing)
// go through the Wallet and WalletDB modules.
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

const MAX_WALLET_CONNECTIONS: usize = 10;
const WALLET_READ_TIMEOUT_SECS: u64 = 10;
const MAX_REQUEST_LINE_BYTES: usize = 4096;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HOST_HEADER_BYTES: usize = 256;

pub struct WalletUiServer {
    port: u16,
    state: SharedState,
    running: Arc<AtomicBool>,
}

impl WalletUiServer {
    pub fn new(port: u16, state: SharedState) -> Self {
        Self {
            port,
            state,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self) -> Result<(), String> {
        // Wallet UI is ALWAYS localhost-only for security
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("Wallet UI bind failed on {}: {}", addr, e))?;
        self.running.store(true, Ordering::SeqCst);
        slog_info!("wallet_ui", "listening", addr => &addr);

        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let active = Arc::new(AtomicUsize::new(0));

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(stream) => {
                        let prev = active.fetch_add(1, Ordering::AcqRel);
                        if prev >= MAX_WALLET_CONNECTIONS {
                            active.fetch_sub(1, Ordering::Relaxed);
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        }
                        let state = Arc::clone(&state);
                        let active = Arc::clone(&active);
                        std::thread::spawn(move || {
                            Self::handle_connection(stream, &state);
                            active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        slog_error!("wallet_ui", "accept_error", error => e);
                    }
                }
            }
        });

        Ok(())
    }

    fn handle_connection(mut stream: TcpStream, state: &SharedState) {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(
            WALLET_READ_TIMEOUT_SECS,
        )));

        let clone = match stream.try_clone() {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut reader = BufReader::new(clone);

        // ── Read request line ──
        let mut request_line = String::new();
        {
            let mut limited = (&mut reader).take(MAX_REQUEST_LINE_BYTES as u64);
            if limited.read_line(&mut request_line).is_err() {
                return;
            }
        }
        if request_line.len() >= MAX_REQUEST_LINE_BYTES && !request_line.ends_with('\n') {
            Self::send_response(&mut stream, 414, "text/plain", b"Request line too long");
            return;
        }

        // ── Read headers ──
        let mut content_length: usize = 0;
        let mut content_length_seen = false;
        let mut bad_content_length = false;
        let mut host_header: Option<String> = None;
        let mut origin_header: Option<String> = None;
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
                        Self::send_response(&mut stream, 431, "text/plain", b"Headers too large");
                        return;
                    }
                    let trimmed = header_line.trim();
                    let lower = trimmed.to_ascii_lowercase();
                    if lower.starts_with("content-length:") {
                        if content_length_seen {
                            bad_content_length = true;
                        }
                        content_length_seen = true;
                        if let Some((_, val)) = trimmed.split_once(':') {
                            match val.trim().parse::<usize>() {
                                Ok(n) => content_length = n,
                                Err(_) => bad_content_length = true,
                            }
                        } else {
                            bad_content_length = true;
                        }
                    } else if lower.starts_with("host:") {
                        if let Some((_, val)) = trimmed.split_once(':') {
                            let host = val.trim();
                            if host.len() <= MAX_HOST_HEADER_BYTES {
                                host_header = Some(host.to_string());
                            }
                        }
                    } else if lower.starts_with("origin:") {
                        if let Some((_, val)) = trimmed.split_once(':') {
                            let origin = val.trim();
                            if origin.len() <= MAX_HOST_HEADER_BYTES {
                                origin_header = Some(origin.to_string());
                            }
                        }
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

        if method != "GET" && method != "POST" {
            Self::send_response(&mut stream, 405, "text/plain", b"Method Not Allowed");
            return;
        }

        if bad_content_length {
            Self::send_response(&mut stream, 400, "text/plain", b"Malformed Content-Length");
            return;
        }

        if path.len() > 512 {
            Self::send_response(&mut stream, 414, "text/plain", b"URI Too Long");
            return;
        }

        if !Self::is_safe_local_request(host_header.as_deref(), origin_header.as_deref()) {
            Self::send_response(&mut stream, 403, "text/plain", b"Forbidden");
            return;
        }

        // ── Read body for POST ──
        let body = if method == "POST" && content_length > 0 {
            if content_length > MAX_BODY_BYTES {
                Self::send_response(&mut stream, 413, "text/plain", b"Body too large");
                return;
            }
            let mut buf = vec![0u8; content_length];
            if reader.read_exact(&mut buf).is_err() {
                Self::send_response(&mut stream, 400, "text/plain", b"Bad request body");
                return;
            }
            String::from_utf8_lossy(&buf).to_string()
        } else {
            String::new()
        };

        // ── Route ──
        match (method, path) {
            ("GET", "/" | "/index.html") => {
                Self::send_response(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    html::WALLET_HTML.as_bytes(),
                );
            }
            ("GET", "/api/wallet/overview") => Self::api_overview(&mut stream, state),
            ("GET", "/api/wallet/network") => Self::api_network_info(&mut stream, state),
            ("GET", p) if p.starts_with("/api/wallet/balance/") => {
                let addr = &p["/api/wallet/balance/".len()..];
                Self::api_balance(&mut stream, state, addr);
            }
            ("POST", "/api/wallet/send") => Self::api_send(&mut stream, state, &body),
            _ => {
                Self::send_response(&mut stream, 404, "text/plain", b"Not Found");
            }
        }
    }

    // ── API Handlers ──

    fn api_overview(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(s) => {
                json!({
                    "node_version": s.node_version,
                    "network": s.network_name,
                    "best_height": s.best_height,
                    "best_hash": s.best_hash,
                    "peer_count": s.peer_manager.count(),
                    "mempool_size": s.mempool.count(),
                    "chain_name": ConsensusParams::CHAIN_NAME,
                    "max_supply": ConsensusParams::MAX_SUPPLY,
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_network_info(stream: &mut TcpStream, state: &SharedState) {
        let data = match state.lock() {
            Ok(s) => {
                json!({
                    "network": s.network_name,
                    "p2p_port": s.p2p_port,
                    "rpc_port": s.rpc_port,
                    "peer_count": s.peer_manager.count(),
                    "best_height": s.best_height,
                })
            }
            Err(_) => json!({"error": "state locked"}),
        };
        Self::send_json(stream, &data);
    }

    fn api_balance(stream: &mut TcpStream, state: &SharedState, addr: &str) {
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

    fn api_send(stream: &mut TcpStream, _state: &SharedState, body: &str) {
        // Parse the send request
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(body);
        let data = match parsed {
            Ok(req) => {
                let to = req.get("to").and_then(|v| v.as_str()).unwrap_or("");
                let amount = req.get("amount").and_then(|v| v.as_str()).unwrap_or("0");

                if to.is_empty() || amount == "0" {
                    json!({"error": "Missing 'to' address or 'amount'"})
                } else {
                    // The actual send is done via CLI wallet or RPC.
                    // The web UI shows the user what to do.
                    json!({
                        "status": "prepared",
                        "to": to,
                        "amount": amount,
                        "message": "Use the CLI wallet to sign and broadcast: shadowdag-wallet send <to> <amount>",
                        "rpc_method": "sendrawtransaction",
                    })
                }
            }
            Err(e) => json!({"error": format!("Invalid JSON: {}", e)}),
        };
        Self::send_json(stream, &data);
    }

    // ── HTTP helpers ──

    fn send_json(stream: &mut TcpStream, data: &serde_json::Value) {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        Self::send_response(stream, 200, "application/json", body.as_bytes());
    }

    fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let status_text = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            403 => "Forbidden",
            413 => "Payload Too Large",
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

    fn is_safe_local_request(host: Option<&str>, origin: Option<&str>) -> bool {
        // Mitigate DNS-rebinding and browser CSRF against localhost wallet UI.
        // Accept only localhost loopback hostnames for browser-facing requests.
        if let Some(h) = host {
            let h = h.to_ascii_lowercase();
            let host_only = h.split(':').next().unwrap_or("").trim();
            if host_only != "127.0.0.1" && host_only != "localhost" && host_only != "[::1]" {
                return false;
            }
        }
        if let Some(o) = origin {
            let o = o.to_ascii_lowercase();
            if !(o.starts_with("http://127.0.0.1")
                || o.starts_with("http://localhost")
                || o.starts_with("http://[::1]"))
            {
                return false;
            }
        }
        true
    }
}
