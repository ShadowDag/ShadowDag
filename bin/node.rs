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

    // Handle subcommands (these never fail — no Result needed)
    if args.len() > 1 {
        match args[1].as_str() {
            "info" | "--info" => { print_info(); return; }
            "genesis" | "--genesis" => { print_genesis(&args); return; }
            "version" | "--version" | "-v" => { print_version(); return; }
            "help" | "--help" | "-h" => { print_help(); return; }
            _ => {} // Fall through to node startup
        }
    }

    // run() returns all errors cleanly — main() just formats and exits.
    if let Err(e) = run(&args) {
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
        std::process::exit(1);
    }
}

/// The actual boot sequence. Returns `Err` on any failure instead of panicking.
fn run(args: &[String]) -> Result<(), BootError> {
    // ── Parse CLI flags ──────────────────────────────────────────────
    let network_mode = parse_flag(args, "--network", "mainnet");
    let network: NetworkMode = network_mode.parse().map_err(|_| {
        BootError::InvalidArg(format!(
            "--network '{}' is not valid. Use: mainnet, testnet, or regtest", network_mode
        ))
    })?;
    let rpc_port: Option<u16> = match parse_flag_opt(args, "--rpc-port") {
        Some(s) => Some(parse_port(&s, "--rpc-port")?),
        None => None,
    };
    let p2p_port: Option<u16> = match parse_flag_opt(args, "--p2p-port") {
        Some(s) => Some(parse_port(&s, "--p2p-port")?),
        None => None,
    };
    let data_dir: Option<String> = parse_flag_opt(args, "--data-dir");

    let mut cfg = NodeConfig::for_network(network);
    if let Some(port) = rpc_port { cfg.rpc_port = port; }
    if let Some(port) = p2p_port { cfg.p2p_port = port; }
    if let Some(dir)  = data_dir { cfg.data_dir = std::path::PathBuf::from(dir); }

    // ── Verify genesis block integrity ───────────────────────────────
    let genesis = create_genesis_block_for(&cfg.network);
    if let Err(reason) = verify_genesis_detailed(&genesis, &cfg.network) {
        return Err(BootError::GenesisFailed(format!(
            "{} (network: {})", reason, cfg.network.name()
        )));
    }

    // ── Banner ───────────────────────────────────────────────────────
    println!("╔══════════════════════════════════════════════╗");
    println!("║     S H A D O W D A G  —  Full Node          ║");
    println!("║     Privacy • Speed • Decentralization        ║");
    println!("╚══════════════════════════════════════════════╝");
    slog_info!("node", "config", version => "1.0.0",
        network => cfg.network.name(),
        p2p_port => cfg.p2p_port,
        rpc_port => cfg.rpc_port,
        data_dir => cfg.data_dir.display(),
        genesis => &genesis.header.hash[..16],
        emission => EmissionSchedule::info(0));
    println!();

    // ── Initialize data directories ──────────────────────────────────
    if let Err(e) = cfg.init_dirs() {
        return Err(BootError::InitFailed(format!(
            "failed to initialize data directories at '{}': {}",
            cfg.data_dir.display(), e
        )));
    }

    // ── Create and start daemon ──────────────────────────────────────
    let mut daemon = DaemonNode::new(cfg)
        .map_err(|e| BootError::InitFailed(e.to_string()))?;

    daemon.start()
        .map_err(|e| BootError::StartFailed(e.to_string()))?;

    slog_info!("node", "all_services_started");

    // Main event loop — drains P2P pending queues (blocks + transactions)
    // and processes them through the full consensus pipeline.
    // Without this, P2P data piles up in queues and is never processed.
    daemon.run_event_loop();
    Ok(())
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
    println!("Block Reward     : 10 SDAG (halves every 210M blocks)");
    println!("Miner Share      : 95%");
    println!("Developer Share  : 5%");
    println!("GHOSTDAG K       : 18");
    println!("Max Parents      : 8");
    println!("Max Block Size   : 2 MB");
    println!("Mining Algorithm : ShadowHash (ASIC-resistant)");
    println!("Privacy          : CLSAG + Pedersen + Dandelion++ (native)");
    println!("Smart Contracts  : ShadowVM (U256 stack, 90+ opcodes, gas metering)");
}

fn print_genesis(args: &[String]) {
    let network = parse_flag(args, "--network", "mainnet");
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
}

fn parse_flag(args: &[String], name: &str, default: &str) -> String {
    parse_flag_opt(args, name).unwrap_or_else(|| default.to_string())
}

/// Parse a port string into u16, returning a proper BootError on failure.
fn parse_port(s: &str, flag_name: &str) -> Result<u16, BootError> {
    s.parse::<u16>().map_err(|_| {
        BootError::InvalidArg(format!(
            "{} value '{}' is not valid (must be 1-65535)", flag_name, s
        ))
    })
}

fn parse_flag_opt(args: &[String], name: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return args.get(i + 1).cloned();
        }
        if let Some(val) = arg.strip_prefix(&format!("{}=", name)) {
            return Some(val.to_string());
        }
    }
    None
}
