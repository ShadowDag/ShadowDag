//! ShadowDAG Rust SDK — programmatic interface for smart contracts.
//!
//! Provides high-level functions for deploying, calling, and querying
//! contracts through the ShadowDAG JSON-RPC interface.
//!
//! # Transport
//!
//! The SDK speaks JSON-RPC 2.0 over plain HTTP/1.1, connecting via
//! `std::net::TcpStream`. This matches the hand-rolled HTTP server in
//! `service/network/rpc/rpc_server.rs` and deliberately avoids pulling
//! in a new dependency (`reqwest` / `hyper` / `ureq`). HTTPS is not yet
//! supported — the SDK rejects `https://` URLs explicitly so callers
//! know TLS is unavailable instead of silently downgrading.
//!
//! Both `with_auth()` and `with_timeout()` are honoured on the wire:
//! the token is sent as `Authorization: Bearer {token}` and the
//! timeout is applied to `connect`, `read`, and `write`.
//!
//! # Example
//! ```no_run
//! use shadowdag::sdk::shadowdag_sdk::ShadowDagSdk;
//!
//! let sdk = ShadowDagSdk::new("http://localhost:9332");
//! let addr = sdk.deploy_contract(&bytecode, "deployer", 0, 10_000_000)?;
//! let result = sdk.call_contract(&addr, &calldata, "caller", 0, 1_000_000)?;
//! let receipt = sdk.wait_for_receipt(&result.tx_hash, 30)?;
//! # Ok::<_, shadowdag::sdk::shadowdag_sdk::SdkError>(())
//! ```

use serde::{Serialize, Deserialize};
use serde_json::{json, Value};

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// ShadowDAG SDK client.
///
/// Speaks JSON-RPC 2.0 over plain HTTP/1.1 to a ShadowDAG node. Use
/// [`Self::with_auth`] and [`Self::with_timeout`] to customize the
/// `Authorization` header and the socket connect/read/write timeout.
pub struct ShadowDagSdk {
    rpc_url: String,
    auth_token: Option<String>,
    timeout_secs: u64,
}

/// Result of a contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub address: String,
    pub success: bool,
    pub gas_used: u64,
    pub tx_hash: Option<String>,
}

/// Result of a contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: String,
    pub tx_hash: Option<String>,
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: String,
    pub execution_success: bool,
    pub gas_used: u64,
    pub contract_address: Option<String>,
    pub return_data: Option<String>,
    pub revert_reason: Option<String>,
    pub logs: Vec<LogEntry>,
    pub block_height: Option<u64>,
    pub vm_version: u8,
}

/// Log entry from contract execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub contract: String,
    pub topics: Vec<String>,
    pub data: String,
    pub log_index: usize,
}

/// SDK error
#[derive(Debug)]
pub enum SdkError {
    Rpc(String),
    Timeout,
    NotFound,
    Other(String),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Rpc(msg) => write!(f, "RPC error: {}", msg),
            SdkError::Timeout => write!(f, "Request timeout"),
            SdkError::NotFound => write!(f, "Not found"),
            SdkError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl ShadowDagSdk {
    /// Create a new SDK client.
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            auth_token: None,
            timeout_secs: 30,
        }
    }

    /// Set authentication token.
    pub fn with_auth(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Set request timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Deploy a contract.
    pub fn deploy_contract(
        &self,
        bytecode: &[u8],
        deployer: &str,
        value: u64,
        gas_limit: u64,
    ) -> Result<DeployResult, SdkError> {
        let params = json!([
            hex::encode(bytecode),
            deployer,
            value,
            gas_limit
        ]);
        let resp = self.rpc_call("deploy_contract", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Call a contract (read-write).
    pub fn call_contract(
        &self,
        contract_addr: &str,
        calldata: &[u8],
        caller: &str,
        value: u64,
        gas_limit: u64,
    ) -> Result<CallResult, SdkError> {
        let params = json!([
            contract_addr,
            hex::encode(calldata),
            caller,
            value,
            gas_limit
        ]);
        let resp = self.rpc_call("call_contract", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Estimate gas for a call (dry-run).
    pub fn estimate_gas(
        &self,
        contract_addr: &str,
        calldata: &[u8],
        caller: &str,
        value: u64,
    ) -> Result<u64, SdkError> {
        let params = json!([
            contract_addr,
            hex::encode(calldata),
            caller,
            value
        ]);
        let resp = self.rpc_call("estimate_gas", params)?;
        resp.get("gas_used")
            .and_then(|v| v.as_u64())
            .ok_or(SdkError::Other("missing gas_used in response".into()))
    }

    /// Get a transaction receipt.
    pub fn get_receipt(&self, tx_hash: &str) -> Result<Receipt, SdkError> {
        let params = json!([tx_hash]);
        let resp = self.rpc_call("get_transaction_receipt", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Wait for a receipt with polling.
    pub fn wait_for_receipt(&self, tx_hash: &str, timeout_secs: u64) -> Result<Receipt, SdkError> {
        let start = std::time::Instant::now();
        loop {
            match self.get_receipt(tx_hash) {
                Ok(receipt) => return Ok(receipt),
                Err(SdkError::NotFound) => {
                    if start.elapsed().as_secs() > timeout_secs {
                        return Err(SdkError::Timeout);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Get contract code.
    pub fn get_code(&self, address: &str) -> Result<Vec<u8>, SdkError> {
        let params = json!([address]);
        let resp = self.rpc_call("get_contract_code", params)?;
        let hex_code = resp.get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        hex::decode(hex_code).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Get storage value at a slot.
    pub fn get_storage_at(&self, address: &str, slot: &str) -> Result<String, SdkError> {
        let params = json!([address, slot]);
        let resp = self.rpc_call("get_storage_at", params)?;
        Ok(resp.get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// Get logs with filter.
    pub fn get_logs(
        &self,
        address: Option<&str>,
        topic0: Option<&str>,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<LogEntry>, SdkError> {
        let mut filter = json!({});
        if let Some(a) = address { filter["address"] = json!(a); }
        if let Some(t) = topic0 { filter["topic0"] = json!(t); }
        if let Some(f) = from_block { filter["from_block"] = json!(f); }
        if let Some(t) = to_block { filter["to_block"] = json!(t); }
        let params = json!([filter]);
        let resp = self.rpc_call("get_logs", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Verify a deployed contract against a package.
    pub fn verify_contract(&self, address: &str, package_json: &str) -> Result<bool, SdkError> {
        let params = json!([address, package_json]);
        let resp = self.rpc_call("verify_contract", params)?;
        Ok(resp.get("verified").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    /// Get contract info.
    pub fn get_contract_info(&self, address: &str) -> Result<Value, SdkError> {
        let params = json!([address]);
        self.rpc_call("get_contract_info", params)
    }

    /// Raw RPC call helper — JSON-RPC 2.0 over HTTP/1.1.
    ///
    /// This is a minimal hand-rolled client (matching the project's
    /// `rpc_server.rs` style) with the following guarantees:
    ///
    /// - `self.timeout_secs` is applied to `connect`, `read`, and `write`.
    ///   A connect / read timeout surfaces as [`SdkError::Timeout`].
    /// - `self.auth_token`, if set, is sent as `Authorization: Bearer {token}`.
    /// - `https://` URLs are rejected with a clear error (no TLS support).
    /// - A JSON-RPC `error` field is propagated as [`SdkError::Rpc`].
    /// - An HTTP 404 maps to [`SdkError::NotFound`].
    /// - All other non-2xx statuses become [`SdkError::Rpc`] with body.
    fn rpc_call(&self, method: &str, params: Value) -> Result<Value, SdkError> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        let body = serde_json::to_string(&request)
            .map_err(|e| SdkError::Other(format!("serialize request: {}", e)))?;

        let (host, port, path) = parse_rpc_url(&self.rpc_url)?;

        // Resolve + connect with the configured timeout. We use
        // `to_socket_addrs` (not `TcpStream::connect(&str)`) so the
        // timeout actually applies to the connect phase.
        let addr_str = format!("{}:{}", host, port);
        let socket_addr = addr_str
            .to_socket_addrs()
            .map_err(|e| SdkError::Other(format!("resolve {}: {}", addr_str, e)))?
            .next()
            .ok_or_else(|| SdkError::Other(format!("no address for {}", addr_str)))?;

        let timeout = Duration::from_secs(self.timeout_secs);
        let mut stream = TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => SdkError::Timeout,
                _ => SdkError::Other(format!("connect {} failed: {}", addr_str, e)),
            }
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| SdkError::Other(format!("set_read_timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| SdkError::Other(format!("set_write_timeout: {}", e)))?;

        // Build the HTTP request. Header order is canonical; Connection:
        // close lets us use `read_to_end` as the termination signal, which
        // avoids having to parse chunked transfer encoding.
        let auth_line = match &self.auth_token {
            Some(token) => format!("Authorization: Bearer {}\r\n", token),
            None => String::new(),
        };
        let request_str = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             {}\
             Connection: close\r\n\
             \r\n\
             {}",
            path,
            host,
            body.len(),
            auth_line,
            body
        );
        stream
            .write_all(request_str.as_bytes())
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => SdkError::Timeout,
                _ => SdkError::Other(format!("write failed: {}", e)),
            })?;

        let mut raw_response = Vec::with_capacity(4096);
        stream
            .read_to_end(&mut raw_response)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => SdkError::Timeout,
                _ => SdkError::Other(format!("read failed: {}", e)),
            })?;

        // The response body can contain arbitrary bytes but a correctly
        // formed JSON-RPC response is always UTF-8. We lose nothing by
        // using `from_utf8_lossy` for the header search and then taking
        // the exact byte slice for the body.
        let header_end = raw_response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| SdkError::Other("malformed HTTP response: no header terminator".into()))?;
        let headers_bytes = &raw_response[..header_end];
        let body_bytes = &raw_response[header_end + 4..];

        let headers_str = std::str::from_utf8(headers_bytes)
            .map_err(|e| SdkError::Other(format!("non-UTF8 HTTP headers: {}", e)))?;
        let status_line = headers_str
            .lines()
            .next()
            .ok_or_else(|| SdkError::Other("empty HTTP response".into()))?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| SdkError::Other(format!("bad status line: {}", status_line)))?;

        let body_str = std::str::from_utf8(body_bytes)
            .map_err(|e| SdkError::Other(format!("non-UTF8 response body: {}", e)))?;

        if status == 404 {
            return Err(SdkError::NotFound);
        }
        if !(200..300).contains(&status) {
            return Err(SdkError::Rpc(format!("HTTP {}: {}", status, body_str)));
        }

        let json: Value = serde_json::from_str(body_str)
            .map_err(|e| SdkError::Other(format!("invalid JSON-RPC body: {}", e)))?;

        // JSON-RPC error field wins over a 200 status — nodes return
        // application-level errors this way.
        if let Some(err) = json.get("error") {
            if !err.is_null() {
                // 404 and NotFound are also sometimes expressed via
                // `error.code == -32601` (method not found) or a
                // message containing "not found"; surface those as
                // SdkError::NotFound so `wait_for_receipt` can poll.
                let msg = err.to_string().to_ascii_lowercase();
                if msg.contains("not found") {
                    return Err(SdkError::NotFound);
                }
                return Err(SdkError::Rpc(err.to_string()));
            }
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| SdkError::Other("JSON-RPC response missing 'result' field".into()))
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

// ── URL parsing ─────────────────────────────────────────────────────────

/// Parse a plain-HTTP RPC URL into `(host, port, path)`.
///
/// Accepts `http://host[:port][/path]` (scheme optional, defaults to
/// `http://`, default port 80, default path `/`). Rejects `https://`
/// because TLS is not implemented in the SDK.
fn parse_rpc_url(url: &str) -> Result<(String, u16, String), SdkError> {
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if url.starts_with("https://") {
        return Err(SdkError::Other(
            "https:// is not supported by the SDK (no TLS). Use http://".into(),
        ));
    } else {
        url
    };

    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };

    // Handle bracketed IPv6 `[::1]:port` first so the `:` inside the
    // address isn't mistaken for a port separator.
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| SdkError::Other(format!("unterminated IPv6 literal in URL: {}", url)))?;
        let host = &stripped[..end];
        let after = &stripped[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| SdkError::Other(format!("invalid port in URL: {}", url)))?
        } else {
            80
        };
        (host.to_string(), port)
    } else if let Some(i) = hostport.rfind(':') {
        let port = hostport[i + 1..]
            .parse::<u16>()
            .map_err(|_| SdkError::Other(format!("invalid port in URL: {}", url)))?;
        (hostport[..i].to_string(), port)
    } else {
        (hostport.to_string(), 80)
    };

    if host.is_empty() {
        return Err(SdkError::Other(format!("URL has no host: {}", url)));
    }

    Ok((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_creates_with_defaults() {
        let sdk = ShadowDagSdk::new("http://localhost:9332");
        assert_eq!(sdk.rpc_url(), "http://localhost:9332");
        assert!(sdk.auth_token.is_none());
        assert_eq!(sdk.timeout_secs, 30);
    }

    #[test]
    fn sdk_with_auth_and_timeout_are_honoured() {
        let sdk = ShadowDagSdk::new("http://localhost:9332")
            .with_auth("secret123")
            .with_timeout(60);
        assert!(sdk.auth_token.is_some());
        assert_eq!(sdk.timeout_secs, 60);
    }

    #[test]
    fn sdk_deploy_returns_error_when_no_node_running() {
        // A port we deliberately don't run anything on. Expect Rpc/Other,
        // but NOT the old "HTTP transport not yet connected" message.
        let sdk = ShadowDagSdk::new("http://127.0.0.1:1").with_timeout(1);
        let result = sdk.deploy_contract(&[0x00], "deployer", 0, 1000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            !msg.contains("HTTP transport not yet connected"),
            "SDK still reports transport as stub: {}",
            msg
        );
    }

    #[test]
    fn sdk_error_display() {
        assert_eq!(format!("{}", SdkError::Timeout), "Request timeout");
        assert_eq!(format!("{}", SdkError::NotFound), "Not found");
        assert!(format!("{}", SdkError::Rpc("test".into())).contains("test"));
    }

    #[test]
    fn parse_url_with_port_and_path() {
        let (h, p, path) = parse_rpc_url("http://localhost:9332/rpc").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 9332);
        assert_eq!(path, "/rpc");
    }

    #[test]
    fn parse_url_without_scheme_defaults_to_http() {
        let (h, p, path) = parse_rpc_url("example.com:8080").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_without_port_defaults_to_80() {
        let (h, p, path) = parse_rpc_url("http://example.com").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_ipv6_literal() {
        let (h, p, path) = parse_rpc_url("http://[::1]:9332/").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 9332);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_rejects_https() {
        let err = parse_rpc_url("https://example.com").unwrap_err();
        assert!(format!("{}", err).contains("https"));
    }

    #[test]
    fn parse_url_rejects_bad_port() {
        assert!(parse_rpc_url("http://example.com:abc").is_err());
    }

    #[test]
    fn parse_url_rejects_empty_host() {
        assert!(parse_rpc_url("http://").is_err());
    }

    #[test]
    fn sdk_rejects_https_at_call_time() {
        let sdk = ShadowDagSdk::new("https://example.com").with_timeout(1);
        let result = sdk.estimate_gas("SD1abc", &[], "caller", 0);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("https"));
    }
}
