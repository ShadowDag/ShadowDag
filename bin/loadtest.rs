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
//   shadowdag-loadtest --rpc=127.0.0.1:7778  # Connect to node
// ═══════════════════════════════════════════════════════════════════════════

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use shadowdag::domain::transaction::transaction::{Transaction, TxInput, TxOutput};
use shadowdag::domain::transaction::tx_builder::generate_keypair;
use sha2::{Sha256, Digest};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_help();
        return;
    }

    let target_tps: u64 = parse_flag(&args, "--tps", "100").parse().unwrap_or(100);
    let duration_sec: u64 = parse_flag(&args, "--duration", "30").parse().unwrap_or(30);
    let num_wallets: usize = parse_flag(&args, "--wallets", "10").parse().unwrap_or(10);
    let rpc_addr = parse_flag(&args, "--rpc", "127.0.0.1:7778");

    println!("╔══════════════════════════════════════════════╗");
    println!("║  S H A D O W D A G  —  Load Tester            ║");
    println!("║  Transaction Stress Testing Tool               ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("[loadtest] Target TPS    : {}", target_tps);
    println!("[loadtest] Duration      : {} seconds", duration_sec);
    println!("[loadtest] Wallets       : {}", num_wallets);
    println!("[loadtest] RPC Endpoint  : {}", rpc_addr);
    println!();

    // Generate test wallets
    println!("[loadtest] Generating {} test wallets...", num_wallets);
    let wallets: Vec<_> = (0..num_wallets).map(|_| generate_keypair()).collect();
    println!("[loadtest] Wallets ready.");

    // Run load test
    println!("[loadtest] Starting load test...");
    println!();

    let total_sent = AtomicU64::new(0);
    let total_errors = AtomicU64::new(0);

    // Connect to the node's RPC endpoint
    println!("[loadtest] Connecting to RPC at {}...", rpc_addr);
    let mut stream = match TcpStream::connect(&rpc_addr) {
        Ok(s) => {
            println!("[loadtest] Connected to RPC.");
            s
        }
        Err(e) => {
            eprintln!("[loadtest] FATAL: cannot connect to RPC at {}: {}", rpc_addr, e);
            eprintln!("[loadtest] Is the node running? Check --rpc flag.");
            std::process::exit(1);
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("Failed to set read timeout");
    stream.set_write_timeout(Some(Duration::from_secs(10)))
        .expect("Failed to set write timeout");

    let start = Instant::now();
    let interval = Duration::from_micros(1_000_000 / target_tps.max(1));

    let mut tx_count: u64 = 0;
    let mut last_report = Instant::now();

    // Backpressure: limit the number of unanswered/pending requests to avoid
    // overwhelming the node's RPC server when it cannot keep up.
    const MAX_PENDING: usize = 100;
    // Accurate response tracking: `sent_count` is incremented on each
    // successful send and `ack_count` is incremented for each RPC response
    // (success or error) we read back. `pending = sent_count - ack_count`
    // gives the exact number of in-flight requests at any point in time.
    let mut sent_count: u64 = 0;
    let mut ack_count: u64 = 0;

    while start.elapsed() < Duration::from_secs(duration_sec) {
        // Drain any responses that arrived since the last iteration so that
        // ack_count stays up-to-date and we release backpressure promptly.
        // The socket has a read timeout so `read_line` won't block forever;
        // we attempt non-blocking reads until there is nothing left.
        {
            let reader = BufReader::new(stream.try_clone().expect("clone tcp stream"));
            for _line in reader.lines() {
                match _line {
                    Ok(_) => ack_count += 1,
                    Err(_) => break, // no more data / timeout
                }
            }
        }

        let pending = (sent_count - ack_count) as usize;

        // Backpressure: wait if too many requests are pending
        if pending >= MAX_PENDING {
            eprintln!("[loadtest] Backpressure: {} pending requests (sent={}, ack={}), waiting...",
                      pending, sent_count, ack_count);
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        // Generate a random transaction
        let from_idx = tx_count as usize % wallets.len();
        let to_idx = (tx_count as usize + 1) % wallets.len();

        let tx = generate_test_tx(
            &wallets[from_idx].address,
            &wallets[to_idx].address,
            tx_count,
        );

        // Submit transaction to node via RPC
        match rpc_submit_tx(&mut stream, &tx, tx_count) {
            Ok(_) => {
                sent_count += 1;
                total_sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                total_errors.fetch_add(1, Ordering::Relaxed);
                // Reconnect on connection errors
                if e.contains("Broken pipe") || e.contains("connection") {
                    eprintln!("[loadtest] Connection lost, reconnecting...");
                    match TcpStream::connect(&rpc_addr) {
                        Ok(s) => {
                            if s.set_read_timeout(Some(Duration::from_secs(10))).is_err()
                                || s.set_write_timeout(Some(Duration::from_secs(10))).is_err()
                            {
                                eprintln!("[loadtest] Failed to set timeouts on reconnected socket");
                                break;
                            }
                            stream = s;
                        }
                        Err(re) => {
                            eprintln!("[loadtest] Reconnect failed: {}", re);
                            break;
                        }
                    }
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
            println!(
                "[loadtest] {} tx sent | {} errors | {:.1} TPS | {:.0}s elapsed",
                sent, errors, actual_tps, elapsed
            );
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

/// Submit a transaction to the node via JSON-RPC over TCP.
fn rpc_submit_tx(stream: &mut TcpStream, tx: &Transaction, id: u64) -> Result<String, String> {
    let tx_json = serde_json::to_string(tx).map_err(|e| format!("serialize: {}", e))?;

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "sendrawtransaction",
        "params": [tx_json]
    });

    let mut payload = serde_json::to_string(&request).map_err(|e| format!("serialize: {}", e))?;
    payload.push('\n');

    stream.write_all(payload.as_bytes()).map_err(|e| format!("write: {}", e))?;
    stream.flush().map_err(|e| format!("flush: {}", e))?;

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| format!("clone: {}", e))?);
    let mut response = String::new();
    reader.read_line(&mut response).map_err(|e| format!("read: {}", e))?;

    if response.contains("\"error\"") && !response.contains("\"error\":null") {
        return Err(format!("rpc error: {}", response.trim()));
    }

    Ok(response)
}

fn generate_test_tx(from: &str, to: &str, seq: u64) -> Transaction {
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
    }
}

fn parse_flag(args: &[String], name: &str, default: &str) -> String {
    for (i, arg) in args.iter().enumerate() {
        if arg == name { return args.get(i + 1).cloned().unwrap_or(default.to_string()); }
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) { return val.to_string(); }
    }
    default.to_string()
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
    println!("  --rpc=<addr:port>  Node RPC endpoint (default: 127.0.0.1:7778)");
    println!("  --help, -h         Show this help");
}
