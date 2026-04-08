// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// shadowdag-loadtest — Transaction load testing tool (like Kaspa Rothschild)
//
// Generates high-volume transactions to stress-test the network.
//
// Usage:
//   shadowdag-loadtest --tps=1000            # Target 1000 TPS
//   shadowdag-loadtest --duration=60         # Run for 60 seconds
//   shadowdag-loadtest --wallets=100         # Use 100 wallets
//   shadowdag-loadtest --rpc=127.0.0.1:9332  # Connect to node
// ═══════════════════════════════════════════════════════════════════════════

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
use shadowdag::domain::transaction::transaction::{Transaction, TxInput, TxOutput};
use shadowdag::domain::transaction::tx_builder::generate_keypair;
use shadowdag::errors::NetworkError;
use shadowdag::{slog_info, slog_warn, slog_fatal};
use sha2::{Sha256, Digest};

fn main() {
    shadowdag::telemetry::logging::structured::init();
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_help();
        return;
    }

    let target_tps: u64 = parse_flag(&args, "--tps", "100").parse().unwrap_or(100);
    let duration_sec: u64 = parse_flag(&args, "--duration", "30").parse().unwrap_or(30);
    let num_wallets: usize = parse_flag(&args, "--wallets", "10").parse().unwrap_or(10).max(1);
    let rpc_addr = parse_flag(&args, "--rpc", "127.0.0.1:9332");
    let rpc_token = parse_flag(&args, "--rpc-token", "");

    println!("╔══════════════════════════════════════════════╗");
    println!("║  S H A D O W D A G  —  Load Tester            ║");
    println!("║  Transaction Stress Testing Tool               ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    slog_info!("loadtest", "config",
        target_tps => target_tps,
        duration_sec => duration_sec,
        wallets => num_wallets,
        rpc => &rpc_addr);

    // Generate test wallets
    slog_info!("loadtest", "generating_wallets", count => num_wallets);
    let wallets: Vec<_> = (0..num_wallets).map(|_| generate_keypair()).collect();
    slog_info!("loadtest", "wallets_ready");

    // Run load test
    slog_info!("loadtest", "starting_load_test");

    let total_sent = AtomicU64::new(0);
    let total_errors = AtomicU64::new(0);

    // Verify RPC endpoint is reachable
    slog_info!("loadtest", "connecting_to_rpc", addr => &rpc_addr);
    match TcpStream::connect(&rpc_addr) {
        Ok(_) => {
            slog_info!("loadtest", "rpc_connected");
        }
        Err(e) => {
            slog_fatal!("loadtest", "rpc_connect_failed", addr => &rpc_addr, error => e);
            std::process::exit(1);
        }
    };

    let start = Instant::now();
    let interval = Duration::from_micros(1_000_000 / target_tps.max(1));

    let mut tx_count: u64 = 0;
    let mut last_report = Instant::now();

    while start.elapsed() < Duration::from_secs(duration_sec) {
        // Generate a random transaction
        let from_idx = tx_count as usize % wallets.len();
        let to_idx = (tx_count as usize + 1) % wallets.len();

        let tx = generate_test_tx_invalid(
            &wallets[from_idx].address,
            &wallets[to_idx].address,
            tx_count,
        );

        // Submit transaction to node via RPC
        match rpc_submit_tx(&rpc_addr, &tx, tx_count, &rpc_token) {
            Ok(_) => {
                total_sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                total_errors.fetch_add(1, Ordering::Relaxed);
                let e_msg = e.to_string();
                if e_msg.contains("Broken pipe") || e_msg.contains("connection") {
                    slog_warn!("loadtest", "connection_error", error => &e_msg);
                }
            }
        }
        tx_count += 1;

        // Print progress every second
        if last_report.elapsed() >= Duration::from_secs(1) {
            let elapsed = start.elapsed().as_secs_f64();
            let sent = total_sent.load(Ordering::Relaxed);
            let errors = total_errors.load(Ordering::Relaxed);
            let actual_tps = sent as f64 / elapsed;
            slog_info!("loadtest", "progress",
                tx_sent => sent, errors => errors,
                tps => format!("{:.1}", actual_tps),
                elapsed_sec => format!("{:.0}", elapsed));
            last_report = Instant::now();
        }

        // Rate limiting
        if interval > Duration::from_micros(1) {
            std::thread::sleep(interval);
        }
    }

    let elapsed = start.elapsed();
    let sent = total_sent.load(Ordering::Relaxed);
    let errors = total_errors.load(Ordering::Relaxed);
    let actual_tps = sent as f64 / elapsed.as_secs_f64();

    println!();
    println!("═══ Load Test Results ═══");
    println!("Total TX Sent    : {}", sent);
    println!("Total TX Attempted: {}", tx_count);
    println!("Errors           : {}", errors);
    println!("Duration         : {:.2}s", elapsed.as_secs_f64());
    println!("Actual TPS       : {:.2}", actual_tps);
    println!("Target TPS       : {}", target_tps);
    println!("Achievement      : {:.1}%", (actual_tps / target_tps as f64) * 100.0);
    println!("Error Rate       : {:.1}%", if tx_count > 0 { errors as f64 / tx_count as f64 * 100.0 } else { 0.0 });
}

/// Submit a transaction to the node via JSON-RPC over HTTP.
fn rpc_submit_tx(addr: &str, tx: &Transaction, id: u64, token: &str) -> Result<String, NetworkError> {
    let tx_json = serde_json::to_string(tx).map_err(|e| NetworkError::Other(format!("serialize: {}", e)))?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "sendrawtransaction",
        "params": [tx_json]
    });

    let body_str = serde_json::to_string(&body).map_err(|e| NetworkError::Other(format!("serialize: {}", e)))?;

    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        addr, body_str.len()
    );
    if !token.is_empty() {
        request.push_str(&format!("Authorization: Bearer {}\r\n", token));
    }
    request.push_str(&format!("\r\n{}", body_str));

    let mut stream = TcpStream::connect(addr).map_err(|e| NetworkError::Other(format!("connect: {}", e)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    stream.write_all(request.as_bytes()).map_err(|e| NetworkError::Other(format!("write: {}", e)))?;
    stream.flush().map_err(|e| NetworkError::Other(format!("flush: {}", e)))?;

    // Read HTTP response: skip headers until empty line, then read body by Content-Length
    let mut reader = BufReader::new(&stream);
    let mut content_length: usize = 0;

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() { break; }
                if trimmed.len() > 15 && trimmed[..15].eq_ignore_ascii_case("content-length:") {
                    let cl_str = trimmed[15..].trim();
                    content_length = match cl_str.parse() {
                        Ok(n) => n,
                        Err(_) => {
                            eprintln!("[loadtest] Warning: invalid Content-Length '{}', reading up to 65536", cl_str);
                            65536
                        }
                    };
                }
            }
            Err(e) => return Err(NetworkError::Other(format!("read header: {}", e))),
        }
    }

    let response = if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        std::io::Read::read_exact(&mut reader, &mut buf)
            .map_err(|e| NetworkError::Other(format!("read body: {}", e)))?;
        String::from_utf8(buf).map_err(|e| NetworkError::Other(format!("utf8: {}", e)))?
    } else {
        let mut buf = vec![0u8; 65536];
        let n = match std::io::Read::read(&mut reader, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                slog_warn!("loadtest", "response_read_failed", error => e);
                return Err(NetworkError::Other(format!("read failed: {}", e)));
            }
        };
        String::from_utf8(buf[..n].to_vec()).map_err(|e| NetworkError::Other(format!("utf8: {}", e)))?
    };

    if response.contains("\"error\"") && !response.contains("\"error\":null") {
        return Err(NetworkError::Other(format!("rpc error: {}", response.trim())));
    }

    Ok(response)
}

/// Generate a deliberately INVALID test transaction for load testing.
/// These transactions will be REJECTED by validators — this measures
/// the rejection throughput path, not acceptance throughput.
/// Fields like "loadtest_sig" and "loadtest_pk" are fake placeholders
/// that will fail signature verification.
/// TODO: generate cryptographically valid transactions for acceptance testing.
fn generate_test_tx_invalid(from: &str, to: &str, seq: u64) -> Transaction {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut h = Sha256::new();
    h.update(b"loadtest_tx");
    h.update(from.as_bytes());
    h.update(to.as_bytes());
    h.update(seq.to_le_bytes());
    h.update(ts.to_le_bytes());
    let hash = hex::encode(h.finalize());

    Transaction {
        hash,
        inputs: vec![TxInput {
            txid:      format!("prev_tx_{}", seq),
            index:     0,
            owner:     from.to_string(),
            signature: "loadtest_sig".to_string(),
            pub_key:   "loadtest_pk".to_string(),
            key_image: None,
            ring_members: None,
        }],
        outputs: vec![TxOutput {
            address: to.to_string(),
            amount:  1_000, // 0.00001 SDAG,
            commitment: None,
            range_proof: None,
            ephemeral_pubkey: None,
        }],
        fee: 1,
        timestamp: ts,
        is_coinbase: false,
        tx_type: shadowdag::domain::transaction::transaction::TxType::Transfer,
        payload_hash: None,
        ..Default::default()
    }
}

fn parse_flag(args: &[String], name: &str, default: &str) -> String {
    parse_flag_opt(args, name).unwrap_or_else(|| default.to_string())
}

fn parse_flag_opt(args: &[String], name: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return match args.get(i + 1) {
                Some(val) if !val.starts_with("--") => Some(val.clone()),
                _ => {
                    eprintln!("[loadtest] Error: {} requires a value (e.g. {}=VALUE)", name, name);
                    std::process::exit(1);
                }
            };
        }
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) {
            if val.is_empty() {
                eprintln!("[loadtest] Error: {} requires a non-empty value", name);
                std::process::exit(1);
            }
            return Some(val.to_string());
        }
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn print_help() {
    println!("ShadowDAG Load Tester v1.0.0");
    println!();
    println!("USAGE:");
    println!("  shadowdag-loadtest [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --tps=<n>          Target transactions per second (default: 100)");
    println!("  --duration=<sec>   Test duration in seconds (default: 30)");
    println!("  --wallets=<n>      Number of test wallets (default: 10)");
    println!("  --rpc=<addr:port>  Node RPC endpoint (default: 127.0.0.1:9332)");
    println!("  --rpc-token=<tok>  Optional RPC bearer token for authentication");
    println!("  --help, -h         Show this help");
}
