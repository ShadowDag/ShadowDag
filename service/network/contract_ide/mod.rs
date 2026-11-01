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
const MAX_HOST_HEADER_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 512;
const MAX_RPC_RESPONSE_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const MAX_CONTRACT_ID_BYTES: usize = 128;
const MAX_STORAGE_SLOT_BYTES: usize = 128;
const MAX_RECEIPT_HASH_BYTES: usize = 128;
const MAX_EXAMPLE_NAME_BYTES: usize = 64;
const MAX_BYTECODE_BYTES: usize = 512 * 1024;
const MAX_CALLDATA_BYTES: usize = 64 * 1024;

pub struct ContractIdeServer {
    port: u16,
    rpc_port: u16,
    running: AtomicBool,
}

impl ContractIdeServer {
    fn host_name_only(host: &str) -> String {
        let h = host.trim().to_ascii_lowercase();
        if h.starts_with('[') {
            if let Some(end) = h.find(']') {
                return h[..=end].to_string();
            }
            return h;
        }
        h.split(':').next().unwrap_or("").trim().to_string()
    }

    fn origin_host_only(origin: &str) -> Option<String> {
        let o = origin.trim().to_ascii_lowercase();
        let rest = if let Some(s) = o.strip_prefix("http://") {
            s
        } else if let Some(s) = o.strip_prefix("https://") {
            s
        } else {
            return None;
        };
        let authority = rest.split('/').next().unwrap_or("");
        if authority.is_empty() {
            return None;
        }
        Some(Self::host_name_only(authority))
    }

    fn is_safe_local_request(host: Option<&str>, origin: Option<&str>) -> bool {
        let Some(h) = host else {
            // Require Host explicitly to reduce ambiguity and proxy quirks.
            return false;
        };
        let host_only = Self::host_name_only(h);
        if host_only != "127.0.0.1" && host_only != "localhost" && host_only != "[::1]" {
            return false;
        }
        if let Some(o) = origin {
            let Some(origin_host) = Self::origin_host_only(o) else {
                return false;
            };
            if origin_host != "127.0.0.1" && origin_host != "localhost" && origin_host != "[::1]"
            {
                return false;
            }
        }
        true
    }

    fn looks_like_identifier(s: &str, max_len: usize) -> bool {
        !s.is_empty()
            && s.len() <= max_len
            && s.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ':' || c == '.'
            })
    }

    fn looks_like_hex_payload(s: &str, max_len: usize) -> bool {
        if s.is_empty() || s.len() > max_len {
            return false;
        }
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_hexdigit())
    }

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
        // Security hardening: IDE is a high-privilege local tool and must not be
        // exposed on public interfaces. Reject non-loopback binds.
        let bind_lower = bind_host.to_ascii_lowercase();
        let is_loopback = matches!(bind_lower.as_str(), "127.0.0.1" | "localhost" | "::1" | "[::1]");
        if !is_loopback {
            return Err(format!(
                "Refusing to bind Contract IDE to non-loopback host '{}'. Use 127.0.0.1/localhost only.",
                bind_host
            ));
        }
        let addr = format!("{}:{}", bind_host, self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("IDE bind failed on {}: {}", addr, e))?;
        self.running.store(true, Ordering::SeqCst);
        slog_info!("ide", "listening", addr => &addr);

        let rpc_port = self.rpc_port;
        let active_connections = Arc::new(AtomicUsize::new(0));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
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
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));
        if stream.write_all(request.as_bytes()).is_err() {
            return json!({"error": "failed to send RPC request"});
        }
        let _ = stream.flush();

        let mut reader = BufReader::new(&stream);
        let mut content_length: usize = 0;
        let mut content_length_seen = false;
        let mut unsupported_transfer_encoding = false;
        let mut header_lines = 0usize;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    header_lines += 1;
                    if header_lines > MAX_HEADER_LINES {
                        return json!({"error": "RPC headers too large"});
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = trimmed.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            if content_length_seen {
                                return json!({"error": "invalid RPC response"});
                            }
                            content_length_seen = true;
                            content_length = match value.trim().parse::<usize>() {
                                Ok(n) => n,
                                Err(_) => return json!({"error": "invalid RPC response"}),
                            };
                        } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
                            unsupported_transfer_encoding = true;
                        }
                    }
                }
                Err(_) => return json!({"error": "failed to read RPC response headers"}),
            }
        }
        if unsupported_transfer_encoding || !content_length_seen {
            return json!({"error": "invalid RPC response"});
        }
        let response_body = if content_length > 0 {
            if content_length > MAX_RPC_RESPONSE_BYTES {
                return json!({"error": "RPC response too large"});
            }
            let mut body = vec![0u8; content_length];
            if reader.read_exact(&mut body).is_err() {
                return json!({"error": "failed to read RPC response body"});
            }
            match String::from_utf8(body) {
                Ok(s) => s,
                Err(_) => return json!({"error": "invalid RPC response"}),
            }
        } else {
            String::new()
        };

        serde_json::from_str(&response_body).unwrap_or(json!({"error": "invalid RPC response"}))
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
                }
            }
        }

        if malformed_content_length {
            Self::send_response(&mut stream, 400, "text/plain", b"Malformed Content-Length");
            return;
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }
        let method = parts[0];
        let path = parts[1];
        if path.len() > MAX_PATH_BYTES {
            Self::send_response(&mut stream, 414, "text/plain", b"URI Too Long");
            return;
        }

        // DNS rebinding / CSRF guard: IDE must be accessed from loopback origins only.
        if !Self::is_safe_local_request(host_header.as_deref(), origin_header.as_deref()) {
            Self::send_response(&mut stream, 403, "text/plain", b"Forbidden");
            return;
        }

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
            match String::from_utf8(buf) {
                Ok(s) => s,
                Err(_) => {
                    Self::send_response(&mut stream, 400, "text/plain", b"Invalid UTF-8 body");
                    return;
                }
            }
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
                let bytecode = p.get("bytecode").and_then(|v| v.as_str()).unwrap_or("");
                let deployer = p.get("deployer").and_then(|v| v.as_str()).unwrap_or("");
                if !Self::looks_like_hex_payload(bytecode, MAX_BYTECODE_BYTES)
                    || !Self::looks_like_identifier(deployer, MAX_CONTRACT_ID_BYTES)
                {
                    Self::send_json(&mut stream, &json!({"error": "invalid deploy payload"}));
                    return;
                }
                let params = json!([
                    bytecode,
                    deployer,
                    p.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("gas").and_then(|v| v.as_u64()).unwrap_or(10_000_000),
                ]);
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "deploy_contract", &params));
            }

            ("POST", "/api/call") => {
                let p: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                let contract = p.get("contract").and_then(|v| v.as_str()).unwrap_or("");
                let calldata = p.get("calldata").and_then(|v| v.as_str()).unwrap_or("");
                let caller = p.get("caller").and_then(|v| v.as_str()).unwrap_or("");
                if !Self::looks_like_identifier(contract, MAX_CONTRACT_ID_BYTES)
                    || !Self::looks_like_hex_payload(calldata, MAX_CALLDATA_BYTES)
                    || !Self::looks_like_identifier(caller, MAX_CONTRACT_ID_BYTES)
                {
                    Self::send_json(&mut stream, &json!({"error": "invalid call payload"}));
                    return;
                }
                let params = json!([
                    contract,
                    calldata,
                    caller,
                    p.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
                    p.get("gas").and_then(|v| v.as_u64()).unwrap_or(1_000_000),
                ]);
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "call_contract", &params));
            }

            ("POST", "/api/estimate") => {
                let p: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                let contract = p.get("contract").and_then(|v| v.as_str()).unwrap_or("");
                let calldata = p.get("calldata").and_then(|v| v.as_str()).unwrap_or("");
                let caller = p.get("caller").and_then(|v| v.as_str()).unwrap_or("");
                if !Self::looks_like_identifier(contract, MAX_CONTRACT_ID_BYTES)
                    || !Self::looks_like_hex_payload(calldata, MAX_CALLDATA_BYTES)
                    || !Self::looks_like_identifier(caller, MAX_CONTRACT_ID_BYTES)
                {
                    Self::send_json(&mut stream, &json!({"error": "invalid estimate payload"}));
                    return;
                }
                let params = json!([
                    contract,
                    calldata,
                    caller,
                    p.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
                ]);
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "estimategas", &params));
            }

            ("GET", p) if p.starts_with("/api/code/") => {
                let addr = &p["/api/code/".len()..];
                if !Self::looks_like_identifier(addr, MAX_CONTRACT_ID_BYTES) {
                    Self::send_json(&mut stream, &json!({"error": "invalid contract id"}));
                    return;
                }
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "get_contract_code", &json!([addr])));
            }

            ("GET", p) if p.starts_with("/api/storage/") => {
                let rest = &p["/api/storage/".len()..];
                let parts: Vec<&str> = rest.splitn(2, '/').collect();
                if parts.len() == 2 {
                    if !Self::looks_like_identifier(parts[0], MAX_CONTRACT_ID_BYTES)
                        || !Self::looks_like_identifier(parts[1], MAX_STORAGE_SLOT_BYTES)
                    {
                        Self::send_json(&mut stream, &json!({"error": "invalid storage path"}));
                        return;
                    }
                    Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "get_storage_at", &json!([parts[0], parts[1]])));
                } else {
                    Self::send_json(&mut stream, &json!({"error": "usage: /api/storage/{addr}/{slot}"}));
                }
            }

            ("GET", p) if p.starts_with("/api/receipt/") => {
                let hash = &p["/api/receipt/".len()..];
                if !Self::looks_like_hex_payload(hash, MAX_RECEIPT_HASH_BYTES) {
                    Self::send_json(&mut stream, &json!({"error": "invalid receipt hash"}));
                    return;
                }
                Self::send_json(&mut stream, &Self::rpc_call(rpc_port, "get_transaction_receipt", &json!([hash])));
            }

            ("GET", "/api/examples") => Self::api_examples(&mut stream),

            ("GET", p) if p.starts_with("/api/example/") => {
                let name = &p["/api/example/".len()..];
                if !Self::looks_like_identifier(name, MAX_EXAMPLE_NAME_BYTES) {
                    Self::send_json(&mut stream, &json!({"error": "invalid example name"}));
                    return;
                }
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
