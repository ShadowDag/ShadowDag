// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// shadowdag-node — Full node binary with CLI commands
//
// Usage:
//   shadowdag-node                          # Start mainnet node
//   shadowdag-node --network=testnet        # Start testnet node
//   shadowdag-node --network=regtest        # Start regtest node
//   shadowdag-node --rpc-port=8888          # Custom RPC port
//   shadowdag-node --data-dir=/path/to/data # Custom data directory
//   shadowdag-node info                     # Show node info
//   shadowdag-node genesis                  # Show genesis block info
// ═══════════════════════════════════════════════════════════════════════════

use shadowdag::daemon::DaemonNode;
use shadowdag::config::node::node_config::{NodeConfig, NetworkMode};
use shadowdag::config::genesis::genesis::{genesis_info, verify_genesis_detailed, create_genesis_block_for};
use shadowdag::config::consensus::emission_schedule::EmissionSchedule;
use shadowdag::{slog_info, slog_error};

// ── Boot error type ─────────────────────────────────────────────────────
// Lightweight enum for CLI-level errors that don't belong in the library.
// Library errors (NodeError, StorageError, etc.) are wrapped via Display.

#[derive(Debug)]
enum BootError {
    /// Invalid CLI arguments (--network, --rpc-port, etc.)
    InvalidArg(String),
    /// Genesis block verification failed
    GenesisFailed(String),
    /// Node initialization failed (DB, DAG, UTXO, etc.)
    InitFailed(String),
    /// Node start failed (P2P, RPC, etc.)
    StartFailed(String),
}

impl BootError {
    /// Error category for structured logging
    fn category(&self) -> &'static str {
        match self {
            BootError::InvalidArg(_)   => "config",
            BootError::GenesisFailed(_) => "genesis",
            BootError::InitFailed(_)    => "init",
            BootError::StartFailed(_)   => "start",
        }
    }
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::InvalidArg(msg)   => write!(f, "invalid argument: {}", msg),
            BootError::GenesisFailed(msg) => write!(f, "genesis verification failed: {}", msg),
            BootError::InitFailed(msg)    => write!(f, "initialization failed: {}", msg),
            BootError::StartFailed(msg)   => write!(f, "start failed: {}", msg),
        }
    }
}

fn main() {
    shadowdag::telemetry::logging::structured::init();
    let args: Vec<String> = std::env::args().collect();

    // Handle subcommands (these never fail -- no Result needed)
    if args.len() > 1 {
        match args[1].as_str() {
            "info" | "--info" => { print_info(); return; }
            "genesis" | "--genesis" => { print_genesis(&args); return; }
            "version" | "--version" | "-v" => { print_version(); return; }
            "help" | "--help" | "-h" => { print_help(); return; }
            _ => {} // Fall through to node startup
        }
    }

    // DevNet mode: lightweight local development environment
    if args.iter().any(|a| a == "--devnet") {
        println!("=== ShadowDAG DevNet Mode ===");
        println!("  Chain ID:     0xDA0C0003 (regtest)");
        println!("  Mining:       auto (instant blocks)");
        println!("  RPC:          http://localhost:29332");
        println!("  Faucet:       enabled");
        println!("  Network:      regtest");
        println!("  State:        ephemeral (reset on restart)");
        println!();
        // Force regtest network -- continue with normal startup using regtest settings
    }

    // run() returns all errors cleanly — main() just formats and exits.
    if let Err(e) = run(&args) {
        // Structured error logging (goes to slog if initialized, otherwise stderr)
        slog_error!("node", "fatal_startup_error",
            error => e.to_string(),
            category => e.category(),
            phase => "startup"
        );

        eprintln!();
        eprintln!("╔══════════════════════════════════════════════╗");
        eprintln!("║   ShadowDAG node failed to start             ║");
        eprintln!("╚══════════════════════════════════════════════╝");
        eprintln!();
        eprintln!("  Error: {}", e);
        eprintln!();
        match &e {
            BootError::InvalidArg(_) => {
                eprintln!("  Run 'shadowdag-node --help' for usage information.");
            }
            BootError::GenesisFailed(_) => {
                eprintln!("  This usually means chain constants were modified.");
                eprintln!("  Check config/genesis/genesis.rs for changes.");
            }
            BootError::InitFailed(_) => {
                eprintln!("  Possible causes:");
                eprintln!("    - Data directory not writable");
                eprintln!("    - RocksDB lock held by another process");
                eprintln!("    - Corrupted database (try --data-dir with a fresh path)");
            }
            BootError::StartFailed(_) => {
                eprintln!("  Possible causes:");
                eprintln!("    - Port already in use (P2P or RPC)");
                eprintln!("    - Crash recovery failed (corrupted chain state)");
                eprintln!("    - Insufficient permissions");
            }
        }
        eprintln!();

        // Cleanup hint: Rust drops all owned values when run() returns Err,
        // including DaemonNode (flushes RocksDB), TcpListeners (closes ports),
        // and any Arc<DB> handles. No explicit cleanup hook needed.
        std::process::exit(1);
    }
}

/// The actual boot sequence. Returns `Err` on any failure instead of panicking.
///
/// Phases (executed in strict order):
///   1. parse_config  — CLI flags → NodeConfig
///   2. verify_genesis — integrity check on genesis block
///   3. init_storage  — create data directories
///   4. init_daemon   — open DB, DAG, UTXO, mempool
///   5. start_services — bind P2P/RPC, bootstrap network
///   6. run_loop      — main event loop (blocks until shutdown)
fn run(args: &[String]) -> Result<(), BootError> {
    // ── Phase 1: Parse configuration ─────────────────────────────────
    let cfg = parse_config(args)?;

    // ── Phase 2: Verify genesis block integrity ──────────────────────
    let genesis = create_genesis_block_for(&cfg.network);
    if let Err(reason) = verify_genesis_detailed(&genesis, &cfg.network) {
        return Err(BootError::GenesisFailed(format!(
            "{} (network: {})", reason, cfg.network.name()
        )));
    }

    // ── Phase 3: Banner + initialize storage ─────────────────────────
    println!("╔══════════════════════════════════════════════╗");
    println!("║     S H A D O W D A G  —  Full Node          ║");
    println!("║     Privacy • Speed • Decentralization        ║");
    println!("╚══════════════════════════════════════════════╝");
    slog_info!("node", "config",
        version => env!("CARGO_PKG_VERSION"),
        network => cfg.network.name(),
        p2p_port => cfg.p2p_port,
        rpc_port => cfg.rpc_port,
        data_dir => cfg.data_dir.display(),
        genesis => &genesis.header.hash[..16],
        emission => EmissionSchedule::info(0));
    println!();

    if let Err(e) = cfg.init_dirs() {
        return Err(BootError::InitFailed(format!(
            "failed to initialize data directories at '{}': {}",
            cfg.data_dir.display(), e
        )));
    }

    // ── Phase 4: Initialize daemon (DB, DAG, consensus) ──────────────
    let mut daemon = DaemonNode::new(cfg)
        .map_err(|e| BootError::InitFailed(e.to_string()))?;

    // ── Phase 5: Start network services (P2P, RPC) ───────────────────
    daemon.start()
        .map_err(|e| BootError::StartFailed(e.to_string()))?;

    slog_info!("node", "all_services_started");

    // ── Phase 6: Main event loop (blocks until shutdown signal) ───────
    daemon.run_event_loop();
    Ok(())
}

/// Phase 1: Parse CLI flags into NodeConfig.
fn parse_config(args: &[String]) -> Result<NodeConfig, BootError> {
    let network_mode = parse_flag(args, "--network", "mainnet")?;
    let network: NetworkMode = network_mode.parse().map_err(|_| {
        BootError::InvalidArg(format!(
            "--network '{}' is not valid. Use: mainnet, testnet, or regtest", network_mode
        ))
    })?;

    let rpc_port: Option<u16> = match parse_flag_opt(args, "--rpc-port")? {
        Some(s) => Some(parse_port(&s, "--rpc-port")?),
        None => None,
    };
    let p2p_port: Option<u16> = match parse_flag_opt(args, "--p2p-port")? {
        Some(s) => Some(parse_port(&s, "--p2p-port")?),
        None => None,
    };
    let data_dir: Option<String> = parse_flag_opt(args, "--data-dir")?;

    let mut cfg = NodeConfig::for_network(network);
    if let Some(port) = rpc_port { cfg.rpc_port = port; }
    if let Some(port) = p2p_port { cfg.p2p_port = port; }
    if let Some(dir)  = data_dir { cfg.data_dir = std::path::PathBuf::from(dir); }

    Ok(cfg)
}

fn print_version() {
    println!("ShadowDAG Node v1.0.0");
    println!("  BlockDAG + Mining (GPU/ASIC-resistant)");
    println!("  Build: release");
}

fn print_info() {
    println!("ShadowDAG Node Info");
    println!("─────────────────────");
    println!("Max Supply       : 21,000,000,000 SDAG");
    println!("Block Time       : 1 second");
    println!("Block Reward     : 10 SDAG (smooth decay: 0.38%/month, ~5.5yr half-life)");
    println!("Miner Share      : 95%");
    println!("Developer Share  : 5%");
    println!("GHOSTDAG K       : 180");
    println!("Max Parents      : 80");
    println!("Max Block Size   : 2 MB");
    println!("Mining Algorithm : ShadowHash (ASIC-resistant)");
    println!("Privacy          : CLSAG + Pedersen + Dandelion++ (native)");
    println!("Smart Contracts  : ShadowVM (U256 stack, 90+ opcodes, gas metering)");
}

fn print_genesis(args: &[String]) {
    let network = parse_flag(args, "--network", "mainnet").unwrap_or_else(|_| "mainnet".into());
    let mode: NetworkMode = match network.parse() {
        Ok(m)  => m,
        Err(_) => {
            slog_error!("node", "invalid_network", value => &network);
            return;
        }
    };
    println!("{}", genesis_info(&mode));
}

fn print_help() {
    println!("ShadowDAG Node v1.0.0");
    println!();
    println!("USAGE:");
    println!("  shadowdag-node [COMMAND] [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("  info      Show network parameters");
    println!("  genesis   Show genesis block details");
    println!("  version   Show version");
    println!("  help      Show this help");
    println!();
    println!("OPTIONS:");
    println!("  --network=<mainnet|testnet|regtest>  Network to join (default: mainnet)");
    println!("  --rpc-port=<port>                    RPC server port (default: 9332)");
    println!("  --p2p-port=<port>                    P2P listen port (default: 9333)");
    println!("  --data-dir=<path>                    Data directory path");
    println!("  --devnet                             Start in DevNet mode (regtest + instant mining + faucet)");
}

fn parse_flag(args: &[String], name: &str, default: &str) -> Result<String, BootError> {
    match parse_flag_opt(args, name) {
        Ok(Some(val)) => Ok(val),
        Ok(None) => Ok(default.to_string()), // flag not present — use default
        Err(_) => Err(BootError::InvalidArg(format!("{} requires a value", name))),
    }
}

/// Parse a port string into u16, returning a proper BootError on failure.
fn parse_port(s: &str, flag_name: &str) -> Result<u16, BootError> {
    let port = s.parse::<u16>().map_err(|_| {
        BootError::InvalidArg(format!(
            "{} value '{}' is not valid (must be 1-65535)", flag_name, s
        ))
    })?;
    if port == 0 {
        return Err(BootError::InvalidArg(format!(
            "{} value '0' is not valid (must be 1-65535)", flag_name
        )));
    }
    Ok(port)
}

/// Parse an optional CLI flag. Returns:
/// - Ok(Some(value)) if flag is present with a value
/// - Ok(None) if flag is not present at all
/// - Err if flag is present but missing its value
fn parse_flag_opt(args: &[String], name: &str) -> Result<Option<String>, BootError> {
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return match args.get(i + 1) {
                Some(val) if !val.starts_with("--") => Ok(Some(val.clone())),
                _ => Err(BootError::InvalidArg(format!(
                    "{} requires a value (e.g. {}=VALUE)", name, name
                ))),
            };
        }
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) {
            if val.is_empty() {
                return Err(BootError::InvalidArg(format!(
                    "{} requires a non-empty value", name
                )));
            }
            return Ok(Some(val.to_string()));
        }
    }
    Ok(None)
}
