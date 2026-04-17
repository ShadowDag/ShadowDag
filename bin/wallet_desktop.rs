// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// shadowdag-wallet-desktop — Native desktop wallet application
//
// A standalone .exe that opens a native window (WebView2 on Windows) with
// the full wallet interface embedded. No browser required.
//
// Build:
//   cargo build --release --bin shadowdag-wallet-desktop --features desktop
//
// Usage:
//   shadowdag-wallet-desktop                        # Default (RPC localhost:9332)
//   shadowdag-wallet-desktop --rpc=127.0.0.1:19332  # Connect to testnet
//   shadowdag-wallet-desktop --network=testnet       # Force network name
// =============================================================================

// Hide the console window on Windows release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop};
use tao::window::WindowBuilder;
use wry::WebViewBuilder;

const WALLET_HTML: &str = include_str!("../service/network/wallet_ui/html_standalone.html");

const MAX_CONNECTIONS: usize = 8;
const READ_TIMEOUT_SECS: u64 = 5;
const MAX_REQUEST_LINE: usize = 4096;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const RPC_TIMEOUT_SECS: u64 = 5;

// ─────────────────────────────────────────────────────────────────────────────
// RPC Client
// ─────────────────────────────────────────────────────────────────────────────

fn rpc_call(rpc_addr: &str, method: &str, params: &[serde_json::Value]) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let body_str = body.to_string();

    let addr = match rpc_addr.parse() {
        Ok(a) => a,
        Err(_) => return serde_json::json!({"error": "Invalid RPC address"}),
    };
    let stream = match TcpStream::connect_timeout(
        &addr,
        std::time::Duration::from_secs(RPC_TIMEOUT_SECS),
    ) {
        Ok(s) => s,
        Err(e) => {
            return serde_json::json!({"error": format!("Cannot connect to node: {}", e)});
        }
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(RPC_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(RPC_TIMEOUT_SECS)));

    let mut stream = stream;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        rpc_addr, body_str.len(), body_str
    );

    if stream.write_all(request.as_bytes()).is_err() {
        return serde_json::json!({"error": "RPC write failed"});
    }
    let _ = stream.flush();

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return serde_json::json!({"error": "RPC read failed"});
    }

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
            Err(_) => serde_json::json!({"error": "Invalid RPC JSON"}),
        }
    } else {
        serde_json::json!({"error": "Bad RPC response"})
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Local API Server (background thread)
// ─────────────────────────────────────────────────────────────────────────────

fn start_api_server(rpc_addr: String, network: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind API server");
    let port = listener.local_addr().unwrap().port();
    let active = Arc::new(AtomicUsize::new(0));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let prev = active.fetch_add(1, Ordering::AcqRel);
                    if prev >= MAX_CONNECTIONS {
                        active.fetch_sub(1, Ordering::Relaxed);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let rpc = rpc_addr.clone();
                    let net = network.clone();
                    let active = Arc::clone(&active);
                    std::thread::spawn(move || {
                        handle_api(stream, &rpc, &net);
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(_) => continue,
            }
        }
    });

    port
}

fn handle_api(mut stream: TcpStream, rpc_addr: &str, network: &str) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(READ_TIMEOUT_SECS)));

    let clone = match stream.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut reader = BufReader::new(clone);

    let mut request_line = String::new();
    {
        let mut limited = (&mut reader).take(MAX_REQUEST_LINE as u64);
        if limited.read_line(&mut request_line).is_err() {
            return;
        }
    }

    // Consume headers, extract content-length
    let mut content_length: usize = 0;
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
                    return;
                }
                let lower = header_line.trim().to_ascii_lowercase();
                if lower.starts_with("content-length:") {
                    if let Some((_, val)) = header_line.trim().split_once(':') {
                        content_length = val.trim().parse().unwrap_or(0);
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

    // Read body for POST
    let body = if method == "POST" && content_length > 0 && content_length <= MAX_BODY_BYTES {
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_err() {
            return;
        }
        String::from_utf8_lossy(&buf).to_string()
    } else {
        String::new()
    };

    // CORS headers for webview
    let cors = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n";

    if method == "OPTIONS" {
        let resp = format!(
            "HTTP/1.1 204 No Content\r\n{}Connection: close\r\n\r\n",
            cors
        );
        let _ = stream.write_all(resp.as_bytes());
        return;
    }

    let json = match (method, path) {
        ("GET", "/api/wallet/overview") => api_overview(rpc_addr, network),
        ("GET", "/api/wallet/network") => api_network(rpc_addr),
        ("GET", p) if p.starts_with("/api/wallet/balance/") => {
            let addr = &p["/api/wallet/balance/".len()..];
            api_balance(rpc_addr, addr)
        }
        ("POST", "/api/wallet/send") => api_send(rpc_addr, &body),
        _ => serde_json::json!({"error": "not found"}),
    };

    let body_str = serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string());
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
        body_str.len(),
        cors,
        body_str
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// API Handlers
// ─────────────────────────────────────────────────────────────────────────────

fn api_overview(rpc_addr: &str, network: &str) -> serde_json::Value {
    let info = rpc_call(rpc_addr, "getnetworkinfo", &[]);
    let height_val = rpc_call(rpc_addr, "getblockcount", &[]);
    let mempool = rpc_call(rpc_addr, "gettxpool", &[]);

    let height = if height_val.is_number() {
        height_val.as_u64().unwrap_or(0)
    } else {
        height_val
            .get("height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };

    let peer_count = info
        .get("peer_count")
        .or_else(|| info.get("connections"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let version = info
        .get("version")
        .or_else(|| info.get("node_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("1.0.0");

    let mempool_size = if mempool.is_number() {
        mempool.as_u64().unwrap_or(0)
    } else {
        mempool
            .get("size")
            .or_else(|| mempool.get("count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };

    serde_json::json!({
        "node_version": version,
        "network": network,
        "best_height": height,
        "best_hash": info.get("best_hash").and_then(|v| v.as_str()).unwrap_or(""),
        "peer_count": peer_count,
        "mempool_size": mempool_size,
        "chain_name": "ShadowDAG",
        "max_supply": 2_100_000_000_000_000_000u64,
    })
}

fn api_network(rpc_addr: &str) -> serde_json::Value {
    let info = rpc_call(rpc_addr, "getnetworkinfo", &[]);
    let height_val = rpc_call(rpc_addr, "getblockcount", &[]);

    let height = if height_val.is_number() {
        height_val.as_u64().unwrap_or(0)
    } else {
        height_val
            .get("height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };

    serde_json::json!({
        "network": info.get("network").and_then(|v| v.as_str()).unwrap_or("unknown"),
        "p2p_port": info.get("p2p_port").and_then(|v| v.as_u64()).unwrap_or(0),
        "rpc_port": info.get("rpc_port").and_then(|v| v.as_u64()).unwrap_or(0),
        "peer_count": info.get("peer_count").or_else(|| info.get("connections")).and_then(|v| v.as_u64()).unwrap_or(0),
        "best_height": height,
        "rpc_endpoint": rpc_addr,
    })
}

fn api_balance(rpc_addr: &str, addr: &str) -> serde_json::Value {
    let result = rpc_call(
        rpc_addr,
        "getbalancebyaddress",
        &[serde_json::Value::String(addr.to_string())],
    );

    let balance = if result.is_number() {
        result.as_u64().unwrap_or(0)
    } else {
        result
            .get("balance")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };

    serde_json::json!({
        "address": addr,
        "balance": balance,
        "balance_sdag": balance as f64 / 100_000_000.0,
    })
}

fn api_send(rpc_addr: &str, body: &str) -> serde_json::Value {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(req) => {
            let to = req.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let amount = req.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
            if to.is_empty() || amount == "0" {
                serde_json::json!({"error": "Missing 'to' or 'amount'"})
            } else {
                serde_json::json!({
                    "status": "prepared",
                    "to": to,
                    "amount": amount,
                    "message": format!("Sign via CLI:\n  shadowdag-wallet send {} {}", to, amount),
                    "rpc_endpoint": rpc_addr,
                })
            }
        }
        Err(e) => serde_json::json!({"error": format!("Invalid JSON: {}", e)}),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main — native window
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("ShadowDAG Desktop Wallet v1.0.0");
        println!();
        println!("USAGE: shadowdag-wallet-desktop [OPTIONS]");
        println!();
        println!("OPTIONS:");
        println!("  --rpc=<host:port>     Node RPC (default: 127.0.0.1:9332)");
        println!("  --network=<name>      Network: mainnet, testnet, regtest");
        println!("  --help, -h            Show help");
        return;
    }

    let rpc_addr = parse_flag(&args, "--rpc").unwrap_or_else(|| "127.0.0.1:9332".to_string());
    let network = parse_flag(&args, "--network").unwrap_or_else(|| {
        if rpc_addr.contains("19332") {
            "testnet".to_string()
        } else if rpc_addr.contains("29332") {
            "regtest".to_string()
        } else {
            "mainnet".to_string()
        }
    });

    // Start background API server
    let api_port = start_api_server(rpc_addr.clone(), network.clone());

    // Inject the API server URL into the HTML
    let html = WALLET_HTML.replace(
        "const API='';",
        &format!("const API='http://127.0.0.1:{}';", api_port),
    );

    // Create native window with webview
    let event_loop = EventLoop::new();

    let window = WindowBuilder::new()
        .with_title(format!("ShadowDAG Wallet — {}", network))
        .with_inner_size(LogicalSize::new(1280.0, 860.0))
        .with_min_inner_size(LogicalSize::new(800.0, 600.0))
        .build(&event_loop)
        .expect("Failed to create window");

    let builder = WebViewBuilder::new_as_child(&window)
        .with_html(&html);

    #[cfg(debug_assertions)]
    let builder = builder.with_devtools(true);

    let _webview = builder.build().expect("Failed to create webview");

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
    });
}

fn parse_flag(args: &[String], name: &str) -> Option<String> {
    for arg in args {
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) {
            return Some(val.to_string());
        }
    }
    None
}
