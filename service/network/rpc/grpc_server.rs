// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// gRPC Server — High-performance binary RPC using length-prefixed protobuf-
// like encoding. Supports all the same methods as the JSON-RPC server but
// with lower latency and higher throughput.
//
// Protocol:
//   [4 bytes: msg_len][1 byte: method_id][payload bytes]
//
// Methods:
//   0x01: GetBlock       0x02: GetBlockByHash   0x03: GetBlockCount
//   0x04: GetInfo        0x05: SendTransaction  0x06: GetBalance
//   0x07: GetMempool     0x08: GetPeers         0x09: GetDagInfo
//   0x0A: GetTips        0x0B: GetUTXO          0x0C: Subscribe
//   0x0D: GetBpsInfo     0x0E: GetEmission      0x0F: GetContractState
//
// Ports:
//   Mainnet: 17777 (binary gRPC)
//   Testnet: 17778
// ═══════════════════════════════════════════════════════════════════════════

use crate::{slog_info, slog_error};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Default gRPC port
pub const DEFAULT_GRPC_PORT: u16 = 17777;

/// Maximum message size (4 MB)
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Maximum concurrent connections
pub const MAX_CONNECTIONS: usize = 256;

/// gRPC method IDs
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum GrpcMethod {
    /// Stub: not yet implemented -- returns error when called.
    GetBlock         = 0x01,
    /// Stub: not yet implemented -- returns error when called.
    GetBlockByHash   = 0x02,
    /// Stub: not yet implemented -- returns error when called.
    GetBlockCount    = 0x03,
    /// Implemented: returns node info (name, version, network, features).
    GetInfo          = 0x04,
    /// Stub: not yet implemented -- returns error when called.
    SendTransaction  = 0x05,
    /// Stub: not yet implemented -- returns error when called.
    GetBalance       = 0x06,
    /// Stub: not yet implemented -- returns error when called.
    GetMempool       = 0x07,
    /// Stub: not yet implemented -- returns error when called.
    GetPeers         = 0x08,
    /// Stub: not yet implemented -- returns error when called.
    GetDagInfo       = 0x09,
    /// Stub: not yet implemented -- returns error when called.
    GetTips          = 0x0A,
    /// Stub: not yet implemented -- returns error when called.
    GetUtxo          = 0x0B,
    /// Stub: not yet implemented -- returns error when called.
    Subscribe        = 0x0C,
    /// Implemented: returns BPS (blocks per second) configuration info.
    GetBpsInfo       = 0x0D,
    /// Implemented: returns emission schedule info.
    GetEmission      = 0x0E,
    /// Stub: not yet implemented -- returns error when called.
    GetContractState = 0x0F,
    // ShadowDAG exclusive
    /// Stub: not yet implemented -- returns error when called.
    GetPrivacyStats  = 0x10,
    /// Stub: not yet implemented -- returns error when called.
    GetShadowPool    = 0x11,
    /// Stub: not yet implemented -- returns error when called.
    GetVmGas         = 0x12,
    Unknown          = 0xFF,
}

impl GrpcMethod {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::GetBlock,       0x02 => Self::GetBlockByHash,
            0x03 => Self::GetBlockCount,  0x04 => Self::GetInfo,
            0x05 => Self::SendTransaction,0x06 => Self::GetBalance,
            0x07 => Self::GetMempool,     0x08 => Self::GetPeers,
            0x09 => Self::GetDagInfo,     0x0A => Self::GetTips,
            0x0B => Self::GetUtxo,        0x0C => Self::Subscribe,
            0x0D => Self::GetBpsInfo,     0x0E => Self::GetEmission,
            0x0F => Self::GetContractState,
            0x10 => Self::GetPrivacyStats,0x11 => Self::GetShadowPool,
            0x12 => Self::GetVmGas,
            _    => Self::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::GetBlock         => "GetBlock",
            Self::GetBlockByHash   => "GetBlockByHash",
            Self::GetBlockCount    => "GetBlockCount",
            Self::GetInfo          => "GetInfo",
            Self::SendTransaction  => "SendTransaction",
            Self::GetBalance       => "GetBalance",
            Self::GetMempool       => "GetMempool",
            Self::GetPeers         => "GetPeers",
            Self::GetDagInfo       => "GetDagInfo",
            Self::GetTips          => "GetTips",
            Self::GetUtxo          => "GetUtxo",
            Self::Subscribe        => "Subscribe",
            Self::GetBpsInfo       => "GetBpsInfo",
            Self::GetEmission      => "GetEmission",
            Self::GetContractState => "GetContractState",
            Self::GetPrivacyStats  => "GetPrivacyStats",
            Self::GetShadowPool    => "GetShadowPool",
            Self::GetVmGas         => "GetVmGas",
            Self::Unknown          => "Unknown",
        }
    }
}

/// gRPC request
#[derive(Debug)]
pub struct GrpcRequest {
    pub method:  GrpcMethod,
    pub payload: Vec<u8>,
    pub req_id:  u64,
}

/// gRPC response
#[derive(Debug)]
pub struct GrpcResponse {
    pub success:  bool,
    pub payload:  Vec<u8>,
    pub req_id:   u64,
    pub error:    Option<String>,
}

impl GrpcResponse {
    pub fn ok(req_id: u64, payload: Vec<u8>) -> Self {
        Self { success: true, payload, req_id, error: None }
    }
    pub fn err(req_id: u64, error: &str) -> Self {
        Self { success: false, payload: vec![], req_id, error: Some(error.to_string()) }
    }

    /// Serialize to wire format: [4B len][1B status][8B req_id][body]
    /// On success, body = payload. On failure, body = error message string.
    pub fn to_bytes(&self) -> Vec<u8> {
        let body = if self.success {
            self.payload.clone()
        } else {
            self.error.clone().unwrap_or_else(|| "Unknown error".into()).into_bytes()
        };
        let payload_len = 1 + 8 + body.len(); // status + req_id + body
        let mut buf = Vec::with_capacity(4 + payload_len);
        buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
        buf.push(if self.success { 1 } else { 0 });
        buf.extend_from_slice(&self.req_id.to_be_bytes());
        buf.extend_from_slice(&body);
        buf
    }
}

/// Subscription for push notifications
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id:     u64,
    pub method: GrpcMethod,
    pub active: bool,
}

/// Server statistics
pub struct GrpcStats {
    pub total_requests:  AtomicU64,
    pub total_errors:    AtomicU64,
    pub active_conns:    AtomicU64,
    pub subscriptions:   AtomicU64,
    pub bytes_sent:      AtomicU64,
    pub bytes_received:  AtomicU64,
}

impl Default for GrpcStats {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcStats {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            total_errors:   AtomicU64::new(0),
            active_conns:   AtomicU64::new(0),
            subscriptions:  AtomicU64::new(0),
            bytes_sent:     AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "gRPC Stats: requests={} errors={} conns={} subs={} sent={}B recv={}B",
            self.total_requests.load(Ordering::Relaxed),
            self.total_errors.load(Ordering::Relaxed),
            self.active_conns.load(Ordering::Relaxed),
            self.subscriptions.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
        )
    }
}

/// Request handler function type
pub type HandlerFn = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// gRPC Server
pub struct GrpcServer {
    port:     u16,
    running:  Arc<AtomicBool>,
    stats:    Arc<GrpcStats>,
    handlers: Arc<RwLock<HashMap<u8, HandlerFn>>>,
    /// Holds the bound address so stop() can connect to unblock accept().
    bound_addr: std::sync::Mutex<Option<std::net::SocketAddr>>,
}

impl GrpcServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            running:  Arc::new(AtomicBool::new(false)),
            stats:    Arc::new(GrpcStats::new()),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            bound_addr: std::sync::Mutex::new(None),
        }
    }

    /// Register a handler for a method
    pub fn register_handler<F>(&self, method: GrpcMethod, handler: F)
    where F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static
    {
        self.handlers.write().unwrap_or_else(|e| e.into_inner()).insert(method as u8, Arc::new(handler));
    }

    /// Register all default handlers
    pub fn register_defaults(&self) {
        self.register_handler(GrpcMethod::GetInfo, |_| {
            serde_json::json!({
                "name": "ShadowDAG",
                "version": "1.0.0",
                "network": std::env::var("SHADOWDAG_NETWORK").unwrap_or_else(|_| "mainnet".to_string()),
                "features": ["privacy", "smart_contracts", "32bps", "post_quantum"]
            }).to_string().into_bytes()
        });

        self.register_handler(GrpcMethod::GetBpsInfo, |_| {
            use crate::config::consensus::consensus_params::ConsensusParams;
            serde_json::json!({
                "current_bps": ConsensusParams::BLOCKS_PER_SECOND,
                "max_bps": 32,
                "max_tps": 320000,
                "profiles": ["standard(1)", "high(10)", "ultra(32)"]
            }).to_string().into_bytes()
        });

        self.register_handler(GrpcMethod::GetEmission, |_| {
            use crate::config::consensus::emission_schedule::EmissionSchedule;
            EmissionSchedule::info(0).into_bytes()
        });
    }

    /// Handle a raw request
    pub fn handle_raw(&self, method_byte: u8, payload: &[u8], req_id: u64) -> GrpcResponse {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        let method = GrpcMethod::from_byte(method_byte);
        if method == GrpcMethod::Unknown {
            self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
            return GrpcResponse::err(req_id, "Unknown method");
        }

        let handlers = self.handlers.read().unwrap_or_else(|e| e.into_inner());
        match handlers.get(&method_byte) {
            Some(handler) => {
                let result = handler(payload);
                GrpcResponse::ok(req_id, result)
            }
            None => {
                self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                GrpcResponse::err(req_id, &format!("Method {:?} ({}) is not yet implemented", method, method.name()))
            }
        }
    }

    /// Handle a single client connection: read requests and write responses.
    fn handle_connection(
        stream: &mut TcpStream,
        handlers: &RwLock<HashMap<u8, HandlerFn>>,
        stats: &GrpcStats,
    ) {
        // Set read timeout to prevent slow-loris attacks where a client holds
        // a connection slot indefinitely without sending data.
        if let Err(e) = stream.set_read_timeout(Some(std::time::Duration::from_secs(30))) {
            slog_error!("rpc", "grpc_set_read_timeout_failed", error => e);
            return;
        }

        loop {
            // Read 4-byte length prefix
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_err() {
                break; // Client disconnected or read error
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if !(9..=MAX_MESSAGE_SIZE).contains(&msg_len) {
                break; // Invalid message size
            }

            // Read payload (method_id + req_id + data)
            let mut payload = vec![0u8; msg_len];
            if stream.read_exact(&mut payload).is_err() {
                break;
            }

            // Reconstruct wire format for parse_request: [4B len][payload]
            let mut wire = Vec::with_capacity(4 + msg_len);
            wire.extend_from_slice(&len_buf);
            wire.extend_from_slice(&payload);

            let req = match parse_request(&wire) {
                Some(r) => r,
                None => break,
            };

            // Dispatch to handler
            stats.total_requests.fetch_add(1, Ordering::Relaxed);
            let method_byte = req.method as u8;
            let response = {
                let h = handlers.read().unwrap_or_else(|e| e.into_inner());
                match h.get(&method_byte) {
                    Some(handler) => {
                        let result = handler(&req.payload);
                        GrpcResponse::ok(req.req_id, result)
                    }
                    None => {
                        stats.total_errors.fetch_add(1, Ordering::Relaxed);
                        GrpcResponse::err(req.req_id, &format!("Method {:?} ({}) is not yet implemented", req.method, req.method.name()))
                    }
                }
            };

            // Write response back — only count bytes AFTER successful write
            let resp_bytes = response.to_bytes();
            if stream.write_all(&resp_bytes).is_err() {
                break;
            }
            stats.bytes_sent.fetch_add(resp_bytes.len() as u64, Ordering::Relaxed);

            stats.bytes_received.fetch_add((4 + msg_len) as u64, Ordering::Relaxed);
        }
    }

    /// Start the TCP server
    pub fn start(&self) {
        let addr = format!("0.0.0.0:{}", self.port);

        slog_info!("rpc", "grpc_server_listening", addr => &addr, protocol => "binary length-prefixed", max_message_size => MAX_MESSAGE_SIZE);

        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                slog_error!("rpc", "grpc_bind_failed", error => e);
                return;
            }
        };

        // Only set running to true AFTER successful bind
        self.running.store(true, Ordering::Relaxed);

        // Store bound address so stop() can send a dummy connection to unblock accept()
        if let Ok(local_addr) = listener.local_addr() {
            if let Ok(mut bound) = self.bound_addr.lock() {
                *bound = Some(local_addr);
            }
        }

        // Explicitly set blocking mode — listener.incoming() blocks on accept().
        // stop() breaks the accept loop by connecting briefly to the listener
        // (dummy connection), which unblocks accept() so it can re-check the
        // running flag. This is the standard workaround for std TcpListener
        // lacking a shutdown API.
        let _ = listener.set_nonblocking(false);
        let _ = listener.set_ttl(30);

        for stream in listener.incoming() {
            if !self.running.load(Ordering::Relaxed) { break; }

            if self.stats.active_conns.load(Ordering::Relaxed) >= MAX_CONNECTIONS as u64 {
                continue;
            }

            match stream {
                Ok(mut stream) => {
                    self.stats.active_conns.fetch_add(1, Ordering::Relaxed);
                    let handlers = Arc::clone(&self.handlers);
                    let stats = Arc::clone(&self.stats);
                    let running = Arc::clone(&self.running);
                    std::thread::spawn(move || {
                        let _ = running; // keep reference so we can check if needed
                        Self::handle_connection(&mut stream, &handlers, &stats);
                        stats.active_conns.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => slog_error!("rpc", "grpc_accept_error", error => e),
            }
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);

        // Unblock the accept loop: connect briefly to the listener so it
        // wakes up, checks `running`, and exits. This is the standard
        // workaround for std TcpListener lacking a shutdown API.
        if let Ok(bound) = self.bound_addr.lock() {
            if let Some(addr) = *bound {
                // Use 127.0.0.1 with the bound port to reach the listener
                let loopback = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    addr.port(),
                );
                let _ = TcpStream::connect_timeout(
                    &loopback,
                    std::time::Duration::from_millis(100),
                );
            }
        }

        slog_info!("rpc", "grpc_server_stopped", stats => &self.stats.summary());
    }

    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }
    pub fn stats(&self) -> &GrpcStats { &self.stats }
    pub fn port(&self) -> u16 { self.port }
}

/// Parse a raw binary request from wire format
pub fn parse_request(data: &[u8]) -> Option<GrpcRequest> {
    if data.len() < 13 { return None; } // 4B len + 1B method + 8B req_id

    let msg_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if msg_len > MAX_MESSAGE_SIZE { return None; }
    if data.len() < 4 + msg_len { return None; }

    let method = GrpcMethod::from_byte(data[4]);
    let req_id = u64::from_be_bytes([
        data[5], data[6], data[7], data[8],
        data[9], data[10], data[11], data[12],
    ]);
    let payload = data[13..4+msg_len].to_vec();

    Some(GrpcRequest { method, payload, req_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_from_byte() {
        assert_eq!(GrpcMethod::from_byte(0x01), GrpcMethod::GetBlock);
        assert_eq!(GrpcMethod::from_byte(0x0D), GrpcMethod::GetBpsInfo);
        assert_eq!(GrpcMethod::from_byte(0x10), GrpcMethod::GetPrivacyStats);
        assert_eq!(GrpcMethod::from_byte(0xAA), GrpcMethod::Unknown);
    }

    #[test]
    fn response_serialization() {
        let resp = GrpcResponse::ok(42, b"hello".to_vec());
        let bytes = resp.to_bytes();
        assert!(bytes.len() > 13);
        assert_eq!(bytes[4], 1); // success
    }

    #[test]
    fn handle_with_registered_handler() {
        let server = GrpcServer::new(17777);
        server.register_handler(GrpcMethod::GetBlockCount, |_| {
            100u64.to_be_bytes().to_vec()
        });

        let resp = server.handle_raw(0x03, &[], 1);
        assert!(resp.success);
        assert_eq!(resp.payload.len(), 8);
    }

    #[test]
    fn handle_unknown_method() {
        let server = GrpcServer::new(17777);
        let resp = server.handle_raw(0xAA, &[], 1);
        assert!(!resp.success);
    }

    #[test]
    fn handle_no_handler() {
        let server = GrpcServer::new(17777);
        let resp = server.handle_raw(0x01, &[], 1);
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("is not yet implemented"));
    }

    #[test]
    fn stats_track_requests() {
        let server = GrpcServer::new(17777);
        server.register_defaults();
        server.handle_raw(0x04, &[], 1); // GetInfo
        server.handle_raw(0x04, &[], 2);
        assert_eq!(server.stats().total_requests.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn parse_valid_request() {
        let mut data = Vec::new();
        let payload = b"test";
        let msg_len = (1 + 8 + payload.len()) as u32;
        data.extend_from_slice(&msg_len.to_be_bytes()); // len
        data.push(0x01); // method
        data.extend_from_slice(&42u64.to_be_bytes()); // req_id
        data.extend_from_slice(payload);

        let req = parse_request(&data).unwrap();
        assert_eq!(req.method, GrpcMethod::GetBlock);
        assert_eq!(req.req_id, 42);
        assert_eq!(req.payload, b"test");
    }

    #[test]
    fn parse_too_short() {
        assert!(parse_request(&[0, 0, 0]).is_none());
    }

    #[test]
    fn default_handlers_work() {
        let server = GrpcServer::new(17777);
        server.register_defaults();

        let resp = server.handle_raw(0x04, &[], 1); // GetInfo
        assert!(resp.success);
        let info = String::from_utf8(resp.payload).unwrap();
        assert!(info.contains("ShadowDAG"));
        assert!(info.contains("smart_contracts"));
    }

    #[test]
    fn grpc_method_names() {
        assert_eq!(GrpcMethod::GetBlock.name(), "GetBlock");
        assert_eq!(GrpcMethod::GetPrivacyStats.name(), "GetPrivacyStats");
        assert_eq!(GrpcMethod::GetVmGas.name(), "GetVmGas");
    }
}
