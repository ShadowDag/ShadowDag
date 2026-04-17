// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// shadowdag-wallet-ui — Standalone desktop wallet web interface
//
// Runs independently without a full node. Connects to a running node's
// RPC endpoint for blockchain data (balance, height, peers, etc.).
//
// Usage:
//   shadowdag-wallet-ui                            # Default (localhost:8081, RPC localhost:9332)
//   shadowdag-wallet-ui --port=8081                # Custom wallet UI port
//   shadowdag-wallet-ui --rpc=127.0.0.1:19332      # Connect to testnet RPC
//   shadowdag-wallet-ui --network=testnet           # Testnet mode
//   shadowdag-wallet-ui --open                      # Auto-open browser
// =============================================================================

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const MAX_CONNECTIONS: usize = 10;
const READ_TIMEOUT_SECS: u64 = 10;
const MAX_REQUEST_LINE: usize = 4096;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HOST_HEADER_BYTES: usize = 256;
const RPC_TIMEOUT_SECS: u64 = 5;

// ─────────────────────────────────────────────────────────────────────────────
// HTML (embedded)
// ─────────────────────────────────────────────────────────────────────────────

const WALLET_HTML: &str = include_str!("../service/network/wallet_ui/html_standalone.html");

// ─────────────────────────────────────────────────────────────────────────────
// RPC Client — talks to a running ShadowDAG node
// ─────────────────────────────────────────────────────────────────────────────

fn rpc_call(rpc_addr: &str, method: &str, params: &[serde_json::Value]) -> serde_json::Value {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::time::Duration;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let body_str = body.to_string();

    let stream = match TcpStream::connect_timeout(
        &rpc_addr.parse().unwrap_or_else(|_| "127.0.0.1:9332".parse().unwrap()),
        Duration::from_secs(RPC_TIMEOUT_SECS),
    ) {
        Ok(s) => s,
        Err(e) => {
            return serde_json::json!({"error": format!("Cannot connect to node RPC at {}: {}", rpc_addr, e)});
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)));

    let mut stream = stream;
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        rpc_addr,
        body_str.len(),
        body_str
    );

    if stream.write_all(request.as_bytes()).is_err() {
        return serde_json::json!({"error": "Failed to send RPC request"});
    }
    let _ = stream.flush();

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return serde_json::json!({"error": "Failed to read RPC response"});
    }

    // Extract JSON body from HTTP response
    if let Some(idx) = response.find("\r\n\r\n") {
        let json_str = &response[idx + 4..];
        match serde_json::from_str::<serde_json::Value>(json_str) {
            Ok(val) => {
                if let Some(result) = val.get("result") {
                    return result.clone();
                }
                if let Some(error) = val.get("error") {
                    return serde_json::json!({"error": error});
                }
                val
            }
            Err(_) => serde_json::json!({"error": "Invalid JSON from RPC"}),
        }
    } else {
        serde_json::json!({"error": "Malformed HTTP response from RPC"})
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Server
// ─────────────────────────────────────────────────────────────────────────────

fn handle_connection(mut stream: TcpStream, rpc_addr: &str, network: &str) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(READ_TIMEOUT_SECS)));

    let clone = match stream.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut reader = BufReader::new(clone);

    // ── Request line ──
    let mut request_line = String::new();
    {
        let mut limited = (&mut reader).take(MAX_REQUEST_LINE as u64);
        if limited.read_line(&mut request_line).is_err() {
            return;
        }
    }
    if request_line.len() >= MAX_REQUEST_LINE && !request_line.ends_with('\n') {
        send_response(&mut stream, 414, "text/plain", b"Request line too long");
        return;
    }

    // ── Headers ──
    let mut content_length: usize = 0;
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
                    send_response(&mut stream, 431, "text/plain", b"Headers too large");
                    return;
                }
                let lower = header_line.trim().to_ascii_lowercase();
                if lower.starts_with("content-length:") {
                    if let Some((_, val)) = header_line.trim().split_once(':') {
                        content_length = val.trim().parse().unwrap_or(0);
                    }
                } else if lower.starts_with("host:") {
                    if let Some((_, val)) = header_line.trim().split_once(':') {
                        let h = val.trim();
                        if h.len() <= MAX_HOST_HEADER_BYTES {
                            host_header = Some(h.to_string());
                        }
                    }
                } else if lower.starts_with("origin:") {
                    if let Some((_, val)) = header_line.trim().split_once(':') {
                        let o = val.trim();
                        if o.len() <= MAX_HOST_HEADER_BYTES {
                            origin_header = Some(o.to_string());
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
        send_response(&mut stream, 405, "text/plain", b"Method Not Allowed");
        return;
    }

    if path.len() > 512 {
        send_response(&mut stream, 414, "text/plain", b"URI Too Long");
        return;
    }

    // DNS rebinding protection
    if !is_safe_local(host_header.as_deref(), origin_header.as_deref()) {
        send_response(&mut stream, 403, "text/plain", b"Forbidden");
        return;
    }

    // ── Body (POST) ──
    let body = if method == "POST" && content_length > 0 {
        if content_length > MAX_BODY_BYTES {
            send_response(&mut stream, 413, "text/plain", b"Body too large");
            return;
        }
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_err() {
            send_response(&mut stream, 400, "text/plain", b"Bad request body");
            return;
        }
        String::from_utf8_lossy(&buf).to_string()
    } else {
        String::new()
    };

    // ── Route ──
    match (method, path) {
        ("GET", "/" | "/index.html") => {
            send_response(&mut stream, 200, "text/html; charset=utf-8", WALLET_HTML.as_bytes());
        }
        ("GET", "/api/wallet/overview") => {
            api_overview(&mut stream, rpc_addr, network);
        }
        ("GET", "/api/wallet/network") => {
            api_network(&mut stream, rpc_addr);
        }
        ("GET", p) if p.starts_with("/api/wallet/balance/") => {
            let addr = &p["/api/wallet/balance/".len()..];
            api_balance(&mut stream, rpc_addr, addr);
        }
        ("POST", "/api/wallet/send") => {
            api_send(&mut stream, rpc_addr, &body);
        }
        _ => {
            send_response(&mut stream, 404, "text/plain", b"Not Found");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// API Handlers — proxy to node RPC
// ─────────────────────────────────────────────────────────────────────────────

fn api_overview(stream: &mut TcpStream, rpc_addr: &str, network: &str) {
    let info = rpc_call(rpc_addr, "getnetworkinfo", &[]);
    let height_val = rpc_call(rpc_addr, "getblockcount", &[]);
    let mempool = rpc_call(rpc_addr, "gettxpool", &[]);

    let height = if height_val.is_number() {
        height_val.as_u64().unwrap_or(0)
    } else {
        height_val.get("height").and_then(|v| v.as_u64()).unwrap_or(0)
    };

    let peer_count = info.get("peer_count")
        .or_else(|| info.get("connections"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let version = info.get("version")
        .or_else(|| info.get("node_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("1.0.0");

    let mempool_size = if mempool.is_number() {
        mempool.as_u64().unwrap_or(0)
    } else {
        mempool.get("size")
            .or_else(|| mempool.get("count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };

    let connected = !info.get("error").is_some() || peer_count > 0 || height > 0;

    let data = serde_json::json!({
        "node_version": version,
        "network": network,
        "best_height": height,
        "best_hash": info.get("best_hash").and_then(|v| v.as_str()).unwrap_or(""),
        "peer_count": peer_count,
        "mempool_size": mempool_size,
        "chain_name": "ShadowDAG",
        "max_supply": 2_100_000_000_000_000_000u64,
        "connected": connected,
    });
    send_json(stream, &data);
}

fn api_network(stream: &mut TcpStream, rpc_addr: &str) {
    let info = rpc_call(rpc_addr, "getnetworkinfo", &[]);
    let height_val = rpc_call(rpc_addr, "getblockcount", &[]);

    let height = if height_val.is_number() {
        height_val.as_u64().unwrap_or(0)
    } else {
        height_val.get("height").and_then(|v| v.as_u64()).unwrap_or(0)
    };

    let data = serde_json::json!({
        "network": info.get("network").and_then(|v| v.as_str()).unwrap_or("unknown"),
        "p2p_port": info.get("p2p_port").and_then(|v| v.as_u64()).unwrap_or(0),
        "rpc_port": info.get("rpc_port").and_then(|v| v.as_u64()).unwrap_or(0),
        "peer_count": info.get("peer_count")
            .or_else(|| info.get("connections"))
            .and_then(|v| v.as_u64()).unwrap_or(0),
        "best_height": height,
        "rpc_endpoint": rpc_addr,
    });
    send_json(stream, &data);
}

fn api_balance(stream: &mut TcpStream, rpc_addr: &str, addr: &str) {
    let result = rpc_call(
        rpc_addr,
        "getbalancebyaddress",
        &[serde_json::Value::String(addr.to_string())],
    );

    let balance = if result.is_number() {
        result.as_u64().unwrap_or(0)
    } else {
        result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0)
    };

    let data = serde_json::json!({
        "address": addr,
        "balance": balance,
        "balance_sdag": balance as f64 / 100_000_000.0,
    });
    send_json(stream, &data);
}

fn api_send(stream: &mut TcpStream, rpc_addr: &str, body: &str) {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(body);
    let data = match parsed {
        Ok(req) => {
            let to = req.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let amount = req.get("amount").and_then(|v| v.as_str()).unwrap_or("0");

            if to.is_empty() || amount == "0" {
                serde_json::json!({"error": "Missing 'to' address or 'amount'"})
            } else {
                serde_json::json!({
                    "status": "prepared",
                    "to": to,
                    "amount": amount,
                    "message": format!(
                        "Sign and broadcast via CLI:\n  shadowdag-wallet send {} {}\n\nOr via RPC:\n  curl -X POST http://{} -d '{{\"jsonrpc\":\"2.0\",\"method\":\"sendrawtransaction\",\"params\":[\"<signed_hex>\"],\"id\":1}}'",
                        to, amount, rpc_addr
                    ),
                    "rpc_endpoint": rpc_addr,
                })
            }
        }
        Err(e) => serde_json::json!({"error": format!("Invalid JSON: {}", e)}),
    };
    send_json(stream, &data);
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn send_json(stream: &mut TcpStream, data: &serde_json::Value) {
    let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
    send_response(stream, 200, "application/json", body.as_bytes());
}

fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
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

fn is_safe_local(host: Option<&str>, origin: Option<&str>) -> bool {
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

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("ShadowDAG Wallet UI v1.0.0");
        return;
    }

    let port: u16 = parse_flag(&args, "--port").unwrap_or(8081);
    let rpc_addr = parse_flag_str(&args, "--rpc").unwrap_or_else(|| "127.0.0.1:9332".to_string());
    let network = parse_flag_str(&args, "--network").unwrap_or_else(|| {
        // Auto-detect from RPC port
        if rpc_addr.contains("19332") {
            "testnet".to_string()
        } else if rpc_addr.contains("29332") {
            "regtest".to_string()
        } else {
            "mainnet".to_string()
        }
    });
    let auto_open = args.iter().any(|a| a == "--open");

    println!("======================================================");
    println!("     S H A D O W D A G  —  Desktop Wallet UI");
    println!("======================================================");
    println!();
    println!("  Wallet UI : http://127.0.0.1:{}", port);
    println!("  Node RPC  : {}", rpc_addr);
    println!("  Network   : {}", network);
    println!();
    println!("  Press Ctrl+C to stop.");
    println!();

    let bind = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR: Cannot bind to {}: {}", bind, e);
            eprintln!("  Try a different port: --port=8082");
            std::process::exit(1);
        }
    };

    // Auto-open browser
    if auto_open {
        let url = format!("http://127.0.0.1:{}", port);
        #[cfg(target_os = "windows")]
        { let _ = std::process::Command::new("cmd").args(["/c", "start", &url]).spawn(); }
        #[cfg(target_os = "macos")]
        { let _ = std::process::Command::new("open").arg(&url).spawn(); }
        #[cfg(target_os = "linux")]
        { let _ = std::process::Command::new("xdg-open").arg(&url).spawn(); }
    }

    let running = Arc::new(AtomicBool::new(true));
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for stream in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                let prev = active.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                if prev >= MAX_CONNECTIONS {
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let rpc = rpc_addr.clone();
                let net = network.clone();
                let active = Arc::clone(&active);
                std::thread::spawn(move || {
                    handle_connection(stream, &rpc, &net);
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
            Err(_) => continue,
        }
    }
}

fn parse_flag(args: &[String], name: &str) -> Option<u16> {
    for arg in args {
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) {
            return val.parse().ok();
        }
    }
    None
}

fn parse_flag_str(args: &[String], name: &str) -> Option<String> {
    for arg in args {
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) {
            return Some(val.to_string());
        }
    }
    None
}

fn print_help() {
    println!("ShadowDAG Wallet UI v1.0.0");
    println!();
    println!("Standalone desktop wallet with browser interface.");
    println!("Connects to a running ShadowDAG node via RPC.");
    println!();
    println!("USAGE:");
    println!("  shadowdag-wallet-ui [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --port=<port>         Wallet UI HTTP port (default: 8081)");
    println!("  --rpc=<host:port>     Node RPC address (default: 127.0.0.1:9332)");
    println!("  --network=<network>   Network name: mainnet, testnet, regtest");
    println!("  --open                Auto-open browser on start");
    println!("  --help, -h            Show this help");
    println!("  --version, -v         Show version");
    println!();
    println!("EXAMPLES:");
    println!("  shadowdag-wallet-ui                              # Mainnet default");
    println!("  shadowdag-wallet-ui --rpc=127.0.0.1:19332        # Connect to testnet");
    println!("  shadowdag-wallet-ui --port=9090 --open           # Custom port + open browser");
    println!();
    println!("NOTES:");
    println!("  - The wallet UI runs on localhost ONLY (never network-exposed)");
    println!("  - A ShadowDAG node must be running for balance/network queries");
    println!("  - Transaction signing is done via the CLI wallet (shadowdag-wallet)");
}
