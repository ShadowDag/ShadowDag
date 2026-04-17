// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Contract IDE — Web-based smart contract development environment.
//
// Standalone HTTP server (default port 3000):
//   - ShadowASM code editor with syntax highlighting
//   - In-process compilation via Assembler::assemble()
//   - Contract operations forwarded to node's RPC via localhost HTTP
// ═══════════════════════════════════════════════════════════════════════════

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde_json::{json, Value};

use crate::runtime::vm::core::assembler::Assembler;
use crate::runtime::vm::lang as shadowlang;
use crate::slog_info;

pub mod html;

const IDE_READ_TIMEOUT_SECS: u64 = 10;
const MAX_POST_BODY: usize = 512 * 1024;
const MAX_IDE_CONNECTIONS: usize = 200;
const MAX_REQUEST_LINE_BYTES: usize = 4096;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;

pub struct ContractIdeServer {
    port: u16,
    rpc_port: u16,
    running: AtomicBool,
}

impl ContractIdeServer {
    pub fn new(port: u16, rpc_port: u16) -> Self {
        Self {
            port,
            rpc_port,
            running: AtomicBool::new(false),
        }
    }

    pub fn start(&self) -> Result<(), String> {
        let bind_host = std::env::var("SHADOWDAG_IDE_BIND")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let addr = format!("{}:{}", bind_host, self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("IDE bind failed on {}: {}", addr, e))?;
        self.running.store(true, Ordering::SeqCst);
        slog_info!("ide", "listening", addr => &addr);

        let rpc_port = self.rpc_port;
        let active_connections = Arc::new(AtomicUsize::new(0));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(stream) = stream {
                    let prev = active_connections.fetch_add(1, Ordering::AcqRel);
                    if prev >= MAX_IDE_CONNECTIONS {
                        active_connections.fetch_sub(1, Ordering::Relaxed);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let active_connections = Arc::clone(&active_connections);
                    std::thread::spawn(move || {
                        Self::handle_connection(stream, rpc_port);
                        active_connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
            }
        });

        Ok(())
    }

    /// Send a JSON-RPC request to the node's RPC server on localhost.
    fn rpc_call(rpc_port: u16, method: &str, params: &Value) -> Value {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        })
        .to_string();

        let request = format!(
            "POST / HTTP/1.1\r\n\
             Host: 127.0.0.1:{}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            rpc_port,
            body.len(),
            body
        );

        let addr = format!("127.0.0.1:{}", rpc_port);
        let mut stream = match TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(e) => return json!({"error": format!("RPC unreachable: {}", e)}),
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        if stream.write_all(request.as_bytes()).is_err() {
            return json!({"error": "failed to send RPC request"});
        }
        let _ = stream.flush();

        // Read response
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);

        // Parse HTTP response — find the JSON body after \r\n\r\n
        if let Some(pos) = response.find("\r\n\r\n") {
            let json_body = &response[pos + 4..];
            serde_json::from_str(json_body).unwrap_or(json!({"error": "invalid RPC response"}))
        } else {
            serde_json::from_str(&response).unwrap_or(json!({"error": "malformed RPC response"}))
        }
    }

    fn handle_connection(mut stream: TcpStream, rpc_port: u16) {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(IDE_READ_TIMEOUT_SECS)));

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

        // Parse headers
        let mut content_length: usize = 0;
        let mut malformed_content_length = false;
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
                    let lower = header_line.to_lowercase();
                    if lower.starts_with("content-length:") {
                        if let Some(len) = lower.split(':').nth(1) {
                            match len.trim().parse::<usize>() {
                                Ok(v) => content_length = v,
                                Err(_) => malformed_content_length = true,
                            }
                        }
                    }
                }
            }
        }

        if malformed_content_length {
            Self::send_response(&mut stream, 400, "text/plain", b"Malformed Content-Length");
            return;
        }

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }
        let method = parts[0];
        let path = parts[1];

        // Handle CORS preflight
        if method == "OPTIONS" {
            Self::send_response(&mut stream, 204, "text/plain", b"");
            return;
        }

        // Read POST body
        let body = if method == "POST" && content_length > 0 {
            if content_length > MAX_POST_BODY {
                Self::send_response(&mut stream, 413, "text/plain", b"Request body too large");
                return;
            }
            let len = content_length;
            let mut buf = vec![0u8; len];
            if reader.read_exact(&mut buf).is_err() {
                return;
            }
            String::from_utf8_lossy(&buf).to_string()
        } else {
            String::new()
        };

        match (method, path) {
            ("GET", "/" | "/index.html") => {
                Self::send_response(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    html::IDE_HTML.as_bytes(),
                );
            }

            ("POST", "/api/compile") => Self::api_compile(&mut stream, &body),
            ("POST", "/api/compile-lang") => Self::api_compile_lang(&mut stream, &body),

            ("POST", "/api/deploy") => {
                let p: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                let params = json!([
                    p.get("bytecode").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("deployer").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("gas").and_then(|v| v.as_u64()).unwrap_or(10_000_000),
                ]);
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "deploy_contract", &params));
            }

            ("POST", "/api/call") => {
                let p: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                let params = json!([
                    p.get("contract").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("caller").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("gas").and_then(|v| v.as_u64()).unwrap_or(1_000_000),
                ]);
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "call_contract", &params));
            }

            ("POST", "/api/estimate") => {
                let p: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                let params = json!([
                    p.get("contract").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("caller").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
                ]);
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "estimategas", &params));
            }

            ("GET", p) if p.starts_with("/api/code/") => {
                let addr = &p["/api/code/".len()..];
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "get_contract_code", &json!([addr])));
            }

            ("GET", p) if p.starts_with("/api/storage/") => {
                let rest = &p["/api/storage/".len()..];
                let parts: Vec<&str> = rest.splitn(2, '/').collect();
                if parts.len() == 2 {
                    Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "get_storage_at", &json!([parts[0], parts[1]])));
                } else {
                    Self::send_json(&mut stream, &json!({"error": "usage: /api/storage/{addr}/{slot}"}));
                }
            }

            ("GET", p) if p.starts_with("/api/receipt/") => {
                let hash = &p["/api/receipt/".len()..];
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "get_transaction_receipt", &json!([hash])));
            }

            ("GET", "/api/examples") => Self::api_examples(&mut stream),

            ("GET", p) if p.starts_with("/api/example/") => {
                let name = &p["/api/example/".len()..];
                Self::api_example_source(&mut stream, name);
            }

            _ => {
                Self::send_response(&mut stream, 404, "text/plain", b"Not Found");
            }
        }
    }

    /// Compile ShadowLang (high-level Solidity-like) source to bytecode.
    /// First transpiles to ShadowASM, then assembles to bytecode.
    fn api_compile_lang(stream: &mut TcpStream, body: &str) {
        let parsed: Value = serde_json::from_str(body).unwrap_or(json!({}));
        let source = match parsed.get("source").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                Self::send_json(stream, &json!({"success": false, "error": "missing 'source' field"}));
                return;
            }
        };

        // Input sanitization: limit source code size to 64 KB
        if source.len() > 64 * 1024 {
            Self::send_json(stream, &json!({"success": false, "error": "source code exceeds 64 KB limit"}));
            return;
        }

        // Step 1: Transpile ShadowLang → ShadowASM
        let asm = match shadowlang::compile(source) {
            Ok(a) => a,
            Err(e) => {
                Self::send_json(stream, &json!({
                    "success": false,
                    "error": e.to_string(),
                    "phase": "transpile",
                }));
                return;
            }
        };

        // Step 2: Assemble ShadowASM → bytecode
        match Assembler::assemble(&asm) {
            Ok(bytecode) => {
                let hex: String = bytecode.iter().map(|b| format!("{:02x}", b)).collect();
                Self::send_json(stream, &json!({
                    "success": true,
                    "asm": asm,
                    "bytecode": hex,
                    "size": bytecode.len(),
                    "language": "ShadowLang",
                }));
            }
            Err(e) => {
                Self::send_json(stream, &json!({
                    "success": false,
                    "error": e.to_string(),
                    "phase": "assemble",
                    "asm": asm,
                }));
            }
        }
    }

    fn api_compile(stream: &mut TcpStream, body: &str) {
        let parsed: Value = serde_json::from_str(body).unwrap_or(json!({}));
        let source = match parsed.get("source").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                Self::send_json(stream, &json!({"success": false, "error": "missing 'source' field"}));
                return;
            }
        };

        // Input sanitization: limit source code size to 64 KB
        if source.len() > 64 * 1024 {
            Self::send_json(stream, &json!({"success": false, "error": "source code exceeds 64 KB limit"}));
            return;
        }

        match Assembler::assemble(source) {
            Ok(bytecode) => {
                let hex: String = bytecode.iter().map(|b| format!("{:02x}", b)).collect();
                let mut functions = Vec::new();
                let mut events = Vec::new();
                for line in source.lines() {
                    let t = line.trim();
                    if let Some(rest) = t.strip_prefix(";; @fn ") {
                        functions.push(rest.trim().to_string());
                    } else if let Some(rest) = t.strip_prefix(";; @event ") {
                        events.push(rest.trim().to_string());
                    }
                }
                Self::send_json(stream, &json!({
                    "success": true,
                    "bytecode": hex,
                    "size": bytecode.len(),
                    "abi": { "functions": functions, "events": events }
                }));
            }
            Err(e) => {
                Self::send_json(stream, &json!({"success": false, "error": e.to_string()}));
            }
        }
    }

    fn api_examples(stream: &mut TcpStream) {
        Self::send_json(stream, &json!({
            "examples": [
                {"name": "counter", "description": "Simple state counter (SLOAD/SSTORE)", "file": "counter.sasm"},
                {"name": "token", "description": "ERC20-like token contract", "file": "token.sasm"},
                {"name": "escrow", "description": "Two-party escrow pattern", "file": "escrow.sasm"},
                {"name": "token_wallet", "description": "Token wallet for transfers", "file": "token_wallet.sasm"},
                {"name": "factory_create2", "description": "CREATE2 deployment factory", "file": "factory_create2.sasm"},
                {"name": "logs_filter", "description": "Event logging demo", "file": "logs_filter.sasm"},
            ]
        }));
    }

    fn api_example_source(stream: &mut TcpStream, name: &str) {
        let source = match name {
            "counter" | "counter.sasm" => include_str!("../../../examples/counter.sasm"),
            "token" | "token.sasm" => include_str!("../../../examples/token.sasm"),
            "escrow" | "escrow.sasm" => include_str!("../../../examples/escrow.sasm"),
            "token_wallet" | "token_wallet.sasm" => include_str!("../../../examples/token_wallet.sasm"),
            "factory_create2" | "factory_create2.sasm" => include_str!("../../../examples/factory_create2.sasm"),
            "logs_filter" | "logs_filter.sasm" => include_str!("../../../examples/logs_filter.sasm"),
            _ => {
                Self::send_json(stream, &json!({"error": "example not found"}));
                return;
            }
        };
        Self::send_json(stream, &json!({"name": name, "source": source}));
    }

    fn send_json(stream: &mut TcpStream, data: &Value) {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        Self::send_response(stream, 200, "application/json", body.as_bytes());
    }

    fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let status_text = match status {
            200 => "OK",
            204 => "No Content",
            404 => "Not Found",
            _ => "Error",
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
