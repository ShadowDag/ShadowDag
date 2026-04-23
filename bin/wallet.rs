// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// shadowdag-wallet -- Unified wallet (CLI + Desktop GUI)
//
// When launched with no arguments (or double-clicked) → opens GUI window
// When launched with a subcommand → runs CLI (like bitcoin-qt / litecoin-qt)
//
// CLI Usage:
//   shadowdag-wallet new                  # Create new wallet
//   shadowdag-wallet balance <address>    # Check balance
//   shadowdag-wallet send <to> <amount>   # Send SDAG
//   shadowdag-wallet info                 # Show wallet info
//   shadowdag-wallet export               # Export keys
//   shadowdag-wallet deploy <hex> [gas]   # Deploy contract
//   shadowdag-wallet deploy-package <pkg> # Deploy from package
//   shadowdag-wallet call <addr> <hex>    # Call contract
//   shadowdag-wallet verify <addr> <pkg>  # Verify contract
//   shadowdag-wallet receipt <tx_hash>    # Get receipt
//   shadowdag-wallet logs [address]       # Get contract logs
//
// GUI Usage (requires --features desktop at build):
//   shadowdag-wallet                       # Opens GUI (mainnet)
//   shadowdag-wallet --gui                 # Force GUI mode
//   shadowdag-wallet --rpc=127.0.0.1:19332 # GUI connected to testnet
// =============================================================================

// On Windows + desktop feature: use GUI subsystem (hides console on double-click).
// CLI output still works via AttachConsole(ATTACH_PARENT_PROCESS).
#![cfg_attr(
    all(not(debug_assertions), feature = "desktop", windows),
    windows_subsystem = "windows"
)]

use std::io::{self, Write};
use std::path::PathBuf;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

static UNLOCK_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

use shadowdag::config::node::node_config::NetworkMode;
use shadowdag::domain::address::invisible_wallet::InvisibleWallet;
use shadowdag::errors::WalletError;
use shadowdag::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
use shadowdag::runtime::vm::contracts::contract_package::ContractPackage;
use shadowdag::service::wallet::core::wallet::{EncryptedSeed, Wallet};
use shadowdag::service::wallet::storage::wallet_db::WalletDB;
use shadowdag::slog_error;

const MAX_SDAG_SATS: u64 = 21_000_000_000 * 100_000_000; // 21B SDAG in satoshis

/// Parse a SDAG amount string to satoshis using integer-only arithmetic.
/// Avoids f64 rounding errors in monetary calculations.
///
/// Accepts: "1.5", "0.00000001", "100", "1234.56789012" (truncates to 8 decimals)
fn safe_sdag_to_sats(input: &str) -> Option<u64> {
    let input = input.trim();
    if input.is_empty() || input.starts_with('-') {
        return None;
    }

    let (whole_str, frac_str) = match input.split_once('.') {
        Some((w, f)) => (w, f),
        None => (input, ""),
    };

    let whole: u64 = if whole_str.is_empty() {
        0
    } else {
        whole_str.parse().ok()?
    };

    // Pad or truncate fractional part to exactly 8 digits
    let mut frac_padded = String::with_capacity(8);
    for (i, ch) in frac_str.chars().enumerate() {
        if i >= 8 {
            break;
        }
        if !ch.is_ascii_digit() {
            return None;
        }
        frac_padded.push(ch);
    }
    while frac_padded.len() < 8 {
        frac_padded.push('0');
    }

    let frac: u64 = frac_padded.parse().ok()?;
    let sats = whole.checked_mul(100_000_000)?.checked_add(frac)?;

    if sats == 0 || sats > MAX_SDAG_SATS {
        return None;
    }
    Some(sats)
}

// ---------------------------------------------------------------------------
// Wallet file persistence helpers
// ---------------------------------------------------------------------------

/// Default directory for wallet data: ~/.shadowdag/
fn default_wallet_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".shadowdag")
}

/// Path to the wallet database (RocksDB-backed via WalletDB).
/// Network-aware: stores data under ~/.shadowdag/<network>/wallet_db
fn wallet_db_path() -> String {
    if let Ok(custom) = std::env::var("SHADOWDAG_WALLET_DB") {
        return custom;
    }
    let base = default_wallet_dir();
    let net = wallet_network();
    format!("{}/{}/wallet_db", base.display(), net)
}

/// Path to the encrypted seed file.
/// Network-aware: stores seed under ~/.shadowdag/<network>/seed.dat
fn seed_path() -> PathBuf {
    if let Ok(custom) = std::env::var("SHADOWDAG_WALLET_DIR") {
        return PathBuf::from(custom).join("seed.dat");
    }
    let base = default_wallet_dir();
    let net = wallet_network();
    base.join(net).join("seed.dat")
}

/// Determine the active network from the SHADOWDAG_NETWORK environment variable.
/// Falls back to "mainnet" if unset.
fn wallet_network() -> String {
    std::env::var("SHADOWDAG_NETWORK").unwrap_or_else(|_| "mainnet".to_string())
}

/// Path to the UTXO database used by the node (read-only for balance queries).
/// Uses the same network-aware directory structure as the node:
///   ~/.shadowdag/<network>/utxo
fn utxo_db_path() -> String {
    if let Ok(custom) = std::env::var("SHADOWDAG_DB") {
        return custom;
    }
    let net: NetworkMode = wallet_network().parse().unwrap_or(NetworkMode::Mainnet);
    net.utxo_path().to_string_lossy().into_owned()
}

fn save_encrypted_seed(enc: &EncryptedSeed) -> Result<(), WalletError> {
    let dir = seed_path()
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    std::fs::create_dir_all(&dir)
        .map_err(|e| WalletError::Other(format!("Cannot create dir: {}", e)))?;
    let data = bincode::serialize(enc)
        .map_err(|e| WalletError::Other(format!("Serialize error: {}", e)))?;
    std::fs::write(seed_path(), &data)
        .map_err(|e| WalletError::Other(format!("Write error: {}", e)))?;
    Ok(())
}

fn load_encrypted_seed() -> Result<EncryptedSeed, WalletError> {
    let data = std::fs::read(seed_path())
        .map_err(|e| WalletError::Other(format!("Cannot read seed file: {}", e)))?;
    bincode::deserialize(&data).map_err(|e| WalletError::Other(format!("Deserialize error: {}", e)))
}

fn prompt_password(prompt_msg: &str) -> String {
    eprint!("{}", prompt_msg);
    io::stderr().flush().ok();
    let mut password = String::new();
    match io::stdin().read_line(&mut password) {
        Ok(0) => {
            slog_error!("wallet", "stdin_closed_eof", hint => "pipe password via stdin for non-interactive use");
            std::process::exit(1);
        }
        Err(e) => {
            slog_error!("wallet", "password_read_failed", error => &e.to_string());
            std::process::exit(1);
        }
        Ok(_) => {}
    }
    let trimmed = password.trim().to_string();
    // Zeroize the original buffer before dropping it
    password.replace_range(.., &"\0".repeat(password.len()));
    password.clear();

    if trimmed.is_empty() {
        slog_error!("wallet", "empty_password_rejected");
        std::process::exit(1);
    }
    if trimmed.len() < 8 {
        slog_error!("wallet", "password_too_short", min_length => "8");
        std::process::exit(1);
    }
    trimmed
}

/// Zeroize a password string in memory after use.
fn zeroize_password(mut password: String) {
    password.replace_range(.., &"\0".repeat(password.len()));
    password.clear();
    drop(password);
}

/// Load an existing wallet from the DB and unlock it with a password.
fn load_and_unlock_wallet() -> Result<Wallet, WalletError> {
    // Collect password and encrypted seed BEFORE acquiring the mutex so that
    // blocking I/O (the password prompt) never holds the lock. This eliminates
    // the deadlock risk when another thread also needs UNLOCK_MUTEX.
    let password = prompt_password("Enter wallet password: ");
    let enc_seed = match load_encrypted_seed() {
        Ok(s) => s,
        Err(e) => {
            zeroize_password(password);
            return Err(e);
        }
    };

    // Now acquire the mutex only for the DB-touching critical section.
    let _guard = UNLOCK_MUTEX.lock();

    let db = WalletDB::new(&wallet_db_path())
        .map_err(|e| WalletError::Other(format!("cannot open wallet DB: {}", e)))?;

    // We need the address to look up the wallet. We can try to load it by
    // creating a fresh wallet, unlocking, and checking if we have a persisted
    // copy. Since WalletDB keys by address we need the address first.
    // Strategy: unlock a temp wallet to derive the address, then load from DB.
    let mut temp = Wallet::new(&wallet_network());
    if let Err(e) = temp.unlock(&enc_seed, &password) {
        // Rate limit after failed password attempt
        std::thread::sleep(std::time::Duration::from_secs(1));
        zeroize_password(password);
        return Err(e);
    }
    // After unlocking, derive account 0 to get the address
    if let Err(e) = temp.add_account(0, "Default Account") {
        zeroize_password(password);
        return Err(e);
    }
    let addr = temp.address();

    // Try to load persisted wallet state (UTXOs, history, etc.)
    let result = match db.get_wallet(&addr) {
        Ok(Some(mut persisted)) => {
            if let Err(e) = persisted.unlock(&enc_seed, &password) {
                // Rate limit after failed password attempt
                std::thread::sleep(std::time::Duration::from_secs(1));
                zeroize_password(password);
                return Err(e);
            }
            Ok(persisted)
        }
        Ok(None) => {
            // Don't silently create a new wallet — warn the user
            eprintln!(
                "Warning: no wallet found for address {} (network: {})",
                addr,
                wallet_network()
            );
            eprintln!("If you created this wallet on a different network, set SHADOWDAG_NETWORK accordingly.");
            Err(WalletError::Other(
                "wallet not found for current network".into(),
            ))
        }
        Err(e) => Err(e),
    };

    // Zeroize password from memory after use
    zeroize_password(password);
    result
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/// Known CLI subcommands — if the first arg matches one of these, run CLI mode.
/// Anything else (no args, --gui, --rpc=, etc.) → GUI mode (if feature enabled).
const CLI_COMMANDS: &[&str] = &[
    "new", "create", "balance", "bal", "send", "transfer",
    "info", "stealth", "invisible", "export",
    "deploy", "deploy-package", "call", "receipt", "logs", "verify",
    "help", "--help", "-h", "version", "--version", "-v",
    "--cli",
];

/// Windows: attach to parent console so println!/eprintln! appear in the
/// terminal that launched us (when built as GUI subsystem).
#[cfg(all(windows, feature = "desktop"))]
fn attach_parent_console() {
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    extern "system" {
        fn AttachConsole(dw_process_id: u32) -> i32;
    }
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(all(windows, feature = "desktop")))]
fn attach_parent_console() {}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let first = args.get(1).map(|s| s.as_str()).unwrap_or("");

    // Decide: CLI or GUI?
    let is_cli = CLI_COMMANDS.contains(&first);
    let force_gui = args.iter().any(|a| a == "--gui");

    if is_cli && !force_gui {
        // CLI mode — attach parent console on Windows so stdio works
        attach_parent_console();
        run_cli(&args, first);
    } else {
        run_gui(&args);
    }
}

fn run_cli(args: &[String], command: &str) {
    match command {
        "new" | "create" => cmd_new(args),
        "balance" | "bal" => cmd_balance(args),
        "send" | "transfer" => cmd_send(args),
        "info" => cmd_info(),
        "stealth" => cmd_stealth(args),
        "invisible" => cmd_invisible(args),
        "export" => cmd_export(),
        "deploy" => cmd_deploy(args),
        "deploy-package" => cmd_deploy_package(args),
        "call" => cmd_call(args),
        "receipt" => cmd_receipt(args),
        "logs" => cmd_logs(args),
        "verify" => cmd_verify(args),
        "version" | "--version" | "-v" => println!("ShadowDAG Wallet v1.0.0"),
        "help" | "--help" | "-h" => print_help(),
        _ => print_help(),
    }
}

// ---------------------------------------------------------------------------
// GUI mode dispatcher (conditionally compiled)
// ---------------------------------------------------------------------------

#[cfg(feature = "desktop")]
fn run_gui(args: &[String]) {
    gui::run(args);
}

#[cfg(not(feature = "desktop"))]
fn run_gui(_args: &[String]) {
    // Built without GUI support — fall back to help
    attach_parent_console();
    eprintln!("GUI mode requires building with --features desktop");
    eprintln!();
    print_help();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_new(args: &[String]) {
    let network = args.get(2).map(|s| s.as_str()).unwrap_or("mainnet");

    // Warn if the specified network doesn't match the SHADOWDAG_NETWORK env var
    let env_network = wallet_network();
    if network != env_network {
        eprintln!(
            "NOTE: Creating wallet for '{}' but SHADOWDAG_NETWORK='{}'",
            network, env_network
        );
    }

    println!("======================================================");
    println!("     S H A D O W D A G  --  New Wallet");
    println!("======================================================");

    let password = prompt_password("Choose a password to encrypt the wallet: ");
    if password.is_empty() {
        eprintln!("Error: password cannot be empty.");
        return;
    }
    let confirm = prompt_password("Confirm password: ");
    if password != confirm {
        zeroize_password(password);
        zeroize_password(confirm);
        eprintln!("Error: passwords do not match.");
        return;
    }
    zeroize_password(confirm);

    let mut wallet = Wallet::new(network);
    let (mnemonic, enc_seed) = match wallet.create(&password) {
        Ok(r) => {
            zeroize_password(password);
            r
        }
        Err(e) => {
            zeroize_password(password);
            eprintln!("Error creating wallet: {}", e);
            return;
        }
    };

    // Persist the encrypted seed to disk
    if let Err(e) = save_encrypted_seed(&enc_seed) {
        slog_error!("wallet", "seed_save_failed", error => &e.to_string());
        eprintln!("FATAL: Could not save encrypted seed. Wallet NOT created.");
        return;
    }

    // Persist wallet state via WalletDB
    let db = match WalletDB::new(&wallet_db_path()) {
        Ok(db) => db,
        Err(e) => {
            slog_error!("wallet", "wallet_db_open_failed", error => &e.to_string());
            slog_error!("wallet", "wallet_not_persisted", recovery => "mnemonic below is the ONLY way to recover");
            // Print mnemonic BEFORE returning so user can still recover
            println!();
            println!("  Mnemonic (WRITE THIS DOWN — wallet NOT saved):");
            println!("  {}", mnemonic.join(" "));
            println!();
            return;
        }
    };
    if let Err(e) = db.save_wallet(&wallet) {
        slog_error!("wallet", "wallet_save_failed", error => &e.to_string());
        println!();
        println!("  WARNING: Failed to persist wallet: {}", e);
        println!("  Mnemonic (WRITE THIS DOWN — wallet NOT saved):");
        println!("  {}", mnemonic.join(" "));
        println!();
        return;
    }

    let address = wallet.address();
    let acc = wallet.accounts().first();
    let pub_key = acc
        .and_then(|a| a.addresses.first())
        .map(|a| a.public_key.as_str())
        .unwrap_or("(none)");

    println!();
    println!("  Network     : {}", network);
    println!("  Address     : {}", address);
    println!("  Public Key  : {}", pub_key);
    println!();
    println!("  Mnemonic (WRITE THIS DOWN):");
    println!("  {}", mnemonic.join(" "));
    println!();
    println!("  WARNING: Save your mnemonic! It cannot be recovered.");
    println!("  WARNING: Never share your mnemonic with anyone.");
    println!("  Wallet saved to: {}", seed_path().display());
}

fn cmd_balance(args: &[String]) {
    // Accept an explicit address, or use the wallet's primary address
    let address: String = match args.get(2) {
        Some(addr) => addr.clone(),
        None => {
            // Try to load wallet and use its address
            match load_and_unlock_wallet() {
                Ok(w) => {
                    let a = w.address();
                    if a.is_empty() {
                        eprintln!("Usage: shadowdag-wallet balance <address>");
                        eprintln!("       (or create a wallet first with 'new')");
                        return;
                    }
                    a
                }
                Err(_) => {
                    eprintln!("Usage: shadowdag-wallet balance <address>");
                    return;
                }
            }
        }
    };

    let db_path = utxo_db_path();
    match UtxoStore::new(db_path.as_str()) {
        Ok(store) => match store.get_balance(&address) {
            Ok(balance) => {
                let sdag = balance as f64 / 100_000_000.0;
                println!("Address : {}", address);
                println!("Balance : {:.8} SDAG ({} sats)", sdag, balance);
            }
            Err(e) => {
                eprintln!("Error querying balance: {}", e);
            }
        },
        Err(e) => {
            slog_error!("wallet", "utxo_db_open_failed", path => &db_path, error => &e.to_string());
            eprintln!("Make sure a ShadowDAG node has been run at least once,");
            eprintln!("or set SHADOWDAG_DB to the correct path.");
        }
    }
}

/// Validate a ShadowDAG address format.
///
/// Address formats produced by `make_address()` (in wallet core):
///   Standard:  prefix(2: "SD"/"ST"/"SR") + hex(version(1) + hash(32) + checksum(4))
///              = 2-char prefix + 74 hex chars = 76 total
///   Stealth:   4-char prefix ("SD1s"/"ST1s"/"SR1s") + 40 hex chars = 44 total
///   Contract:  4-char prefix ("SD1c"/"ST1c"/"SR1c") + 40 hex chars = 44 total
///   Multisig:  4-char prefix ("SD1m"/"ST1m"/"SR1m") + 40 hex chars = 44 total
///
/// Both standard and typed address formats are accepted.
fn validate_address(addr: &str) -> Result<(), String> {
    // Check network prefix (2 chars)
    let valid_net = addr.starts_with("SD") || addr.starts_with("ST") || addr.starts_with("SR");
    if !valid_net {
        return Err("Invalid address prefix (expected SD/ST/SR)".to_string());
    }

    let after_net = &addr[2..];

    // Typed addresses: "1s", "1c", "1m" after network prefix => 4-char prefix + 40 hex
    if after_net.starts_with("1s") || after_net.starts_with("1c") || after_net.starts_with("1m") {
        let hex_part = &after_net[2..];
        if hex_part.len() != 40 {
            return Err(format!(
                "Typed address hex part must be 40 characters, got {}",
                hex_part.len()
            ));
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Address contains invalid hex characters".into());
        }
        return Ok(());
    }

    // Standard addresses: 2-char prefix + 74 hex (version + hash + checksum)
    if after_net.len() != 74 {
        return Err(format!(
            "Standard address hex part must be 74 characters, got {}",
            after_net.len()
        ));
    }
    if !after_net.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Address contains invalid hex characters".into());
    }
    Ok(())
}

fn cmd_send(args: &[String]) {
    let to = match args.get(2) {
        Some(addr) => {
            if let Err(e) = validate_address(addr) {
                eprintln!("Error: Invalid destination address: {}", e);
                return;
            }
            addr.clone()
        }
        None => {
            eprintln!("Usage: shadowdag-wallet send <to_address> <amount> [fee]");
            return;
        }
    };
    let amount_str = match args.get(3) {
        Some(s) => s.as_str(),
        None => {
            eprintln!("Usage: shadowdag-wallet send <to_address> <amount> [fee]");
            return;
        }
    };
    let amount = match safe_sdag_to_sats(amount_str) {
        Some(a) => a,
        None => {
            eprintln!("Error: invalid amount (must be 0 < amount <= 21,000,000,000)");
            return;
        }
    };
    let fee: u64 = args.get(4).and_then(|s| safe_sdag_to_sats(s)).unwrap_or(1); // default 1 sat fee

    // Load and unlock wallet — signing keys are derived from the encrypted
    // seed after password authentication. Private keys never leave the wallet.
    let mut wallet = match load_and_unlock_wallet() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Cannot load wallet: {}", e);
            return;
        }
    };

    let from_address = wallet.address();
    if from_address.is_empty() {
        eprintln!("Error: wallet has no accounts. Create a wallet first.");
        return;
    }

    // Build and sign transaction using the wallet's internal key derivation.
    // The wallet selects UTXOs, derives signing keys from the encrypted seed,
    // signs each input, and zeroizes key material — no raw keys exposed.
    match wallet.build_tx(0, &to, amount, fee, "") {
        Ok(built_tx) => {
            println!("Transaction built and signed!");
            println!("  TxID   : {}", built_tx.txid);
            println!("  From   : {}", from_address);
            println!("  To     : {}", to);
            println!("  Amount : {} SDAG", amount_str);
            println!("  Fee    : {:.8} SDAG", fee as f64 / 100_000_000.0);
            println!("  Raw    : {}", built_tx.raw_hex);
            println!();
            println!("Broadcast this raw transaction to a running node to send it.");
        }
        Err(e) => {
            eprintln!("Error building transaction: {}", e);
        }
    }
}

fn cmd_info() {
    // Try to load the wallet and show real info
    match load_and_unlock_wallet() {
        Ok(wallet) => {
            println!("ShadowDAG Wallet Info");
            println!("-----------------------------");
            println!(
                "  Network    : {}",
                if wallet.address().starts_with("ST") {
                    "testnet"
                } else if wallet.address().starts_with("SR") {
                    "regtest"
                } else {
                    "mainnet"
                }
            );
            println!("  Address    : {}", wallet.address());
            println!("  Accounts   : {}", wallet.accounts().len());
            for acc in wallet.accounts() {
                println!(
                    "    Account #{}: {} ({} addresses)",
                    acc.index,
                    acc.label,
                    acc.addresses.len()
                );
                for addr in &acc.addresses {
                    println!(
                        "      {} {}{}",
                        addr.address,
                        addr.label,
                        if addr.is_change { " (change)" } else { "" }
                    );
                }
            }
            println!("  Locked     : {}", wallet.is_locked());
        }
        Err(_) => {
            println!("ShadowDAG Wallet Info");
            println!("-----------------------------");
            println!("No wallet found. Create one with: shadowdag-wallet new");
            println!();
            println!("Supported features:");
            println!("  - Standard addresses (SD1...)");
            println!("  - Stealth addresses (SD1s...)");
            println!("  - Invisible wallets (auto-rotating addresses)");
            println!("  - Ring signature privacy");
            println!("  - Confidential transactions (hidden amounts)");
            println!("  - HD wallet derivation (BIP44-like)");
        }
    }
}

fn cmd_stealth(args: &[String]) {
    let base = args.get(2).map(|s| s.as_str()).unwrap_or("SD1default");
    use shadowdag::domain::address::stealth_address::StealthAddress;

    println!("Generating stealth address...");
    let stealth = StealthAddress::generate(base);
    println!("  Base Address    : {}", base);
    println!("  Stealth Address : {}", stealth);
    println!("  (One-time address -- never reused)");
}

fn cmd_invisible(args: &[String]) {
    let network = args.get(2).map(|s| s.as_str()).unwrap_or("mainnet");
    let mut wallet = match InvisibleWallet::new(network) {
        Ok(w) => w,
        Err(e) => {
            slog_error!("wallet", "invisible_wallet_creation_failed", error => &e.to_string());
            return;
        }
    };

    println!("======================================================");
    println!("     Invisible Wallet -- Ghost Mode");
    println!("======================================================");
    println!();
    println!("  View Key  : {}", wallet.view_key_hex());
    println!("  Address 1 : {}", wallet.next_address());
    println!("  Address 2 : {}", wallet.next_address());
    println!("  Address 3 : {}", wallet.next_address());
    println!();
    println!("  Each address is unique and auto-rotates.");
    println!("  Share the View Key for watch-only access.");
}

fn cmd_export() {
    // Security warning — export reveals wallet structure
    eprintln!("╔══════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: This exports wallet data to stdout.   ║");
    eprintln!("║  Do NOT share this output with anyone.          ║");
    eprintln!("║  It contains public keys and address mappings.  ║");
    eprintln!("╚══════════════════════════════════════════════════╝");
    eprintln!();

    // Require explicit --yes flag to prevent accidental export
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|a| a == "--yes" || a == "-y") {
        eprintln!("Add --yes flag to confirm: shadowdag-wallet export --yes");
        return;
    }

    match load_and_unlock_wallet() {
        Ok(wallet) => {
            let address = wallet.address();
            let pub_key = wallet
                .accounts()
                .first()
                .and_then(|a| a.addresses.first())
                .map(|a| a.public_key.as_str())
                .unwrap_or("");

            println!("{{");
            println!("  \"address\": \"{}\",", address);
            println!("  \"public_key\": \"{}\",", pub_key);
            println!("  \"accounts\": [");
            for (i, acc) in wallet.accounts().iter().enumerate() {
                println!("    {{");
                println!("      \"index\": {},", acc.index);
                println!("      \"label\": \"{}\",", acc.label);
                println!("      \"addresses\": [");
                for (j, addr) in acc.addresses.iter().enumerate() {
                    let comma = if j + 1 < acc.addresses.len() { "," } else { "" };
                    println!("        {{ \"address\": \"{}\", \"public_key\": \"{}\", \"is_change\": {} }}{}",
                             addr.address, addr.public_key, addr.is_change, comma);
                }
                println!("      ]");
                let comma = if i + 1 < wallet.accounts().len() {
                    ","
                } else {
                    ""
                };
                println!("    }}{}", comma);
            }
            println!("  ]");
            println!("}}");
        }
        Err(e) => {
            eprintln!("Cannot load wallet: {}", e);
            eprintln!("Create a wallet first with: shadowdag-wallet new");
        }
    }
}

fn cmd_deploy(args: &[String]) {
    let bytecode_hex = match args.get(2) {
        Some(v) => v,
        None => {
            eprintln!("Usage: wallet deploy <bytecode_hex> [gas_limit] [value]");
            return;
        }
    };
    let gas_limit: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000_000);
    let value: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);

    let bytecode = match hex::decode(bytecode_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Invalid bytecode hex: {}", e);
            return;
        }
    };

    println!("Deploying contract...");
    println!("  Bytecode size: {} bytes", bytecode.len());
    println!("  Gas limit:     {}", gas_limit);
    println!("  Value:         {} sats", value);

    // Build TX
    let mut wallet = match load_and_unlock_wallet() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Wallet error: {}", e);
            return;
        }
    };

    match wallet.build_deploy_tx(0, bytecode, value, gas_limit, 1000) {
        Ok(tx) => {
            println!("  TX hash:       {}", tx.hash);
            println!("  TX type:       ContractCreate");
            println!("  VM version:    1");
            println!("\nTransaction built. Submit via RPC: deploy_contract");
        }
        Err(e) => eprintln!("Failed to build deploy TX: {}", e),
    }
}

fn cmd_call(args: &[String]) {
    let contract_addr = match args.get(2) {
        Some(v) => v,
        None => {
            eprintln!("Usage: wallet call <contract_address> <calldata_hex> [gas_limit] [value]");
            return;
        }
    };
    let calldata_hex = match args.get(3) {
        Some(v) => v,
        None => {
            eprintln!("Usage: wallet call <contract_address> <calldata_hex> [gas_limit] [value]");
            return;
        }
    };
    let gas_limit: u64 = args
        .get(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000_000);
    let value: u64 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

    let calldata = match hex::decode(calldata_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Invalid calldata hex: {}", e);
            return;
        }
    };

    println!("Calling contract {}...", contract_addr);
    println!("  Calldata:   {} bytes", calldata.len());
    println!("  Gas limit:  {}", gas_limit);
    println!("  Value:      {} sats", value);

    let mut wallet = match load_and_unlock_wallet() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Wallet error: {}", e);
            return;
        }
    };

    match wallet.build_call_tx(0, contract_addr, calldata, value, gas_limit, 1000) {
        Ok(tx) => {
            println!("  TX hash:    {}", tx.hash);
            println!("  TX type:    ContractCall");
            println!("\nTransaction built. Submit via RPC: call_contract");
        }
        Err(e) => eprintln!("Failed to build call TX: {}", e),
    }
}

fn cmd_receipt(args: &[String]) {
    let tx_hash = match args.get(2) {
        Some(v) => v,
        None => {
            eprintln!("Usage: wallet receipt <tx_hash>");
            return;
        }
    };
    println!("Fetching receipt for {}...", tx_hash);
    println!("  Use RPC: get_transaction_receipt {}", tx_hash);
    // In a full implementation, this would connect to the local RPC
    // and fetch the receipt. For now, print instructions.
    println!("\n  curl -X POST http://localhost:9332 \\");
    println!("    -d '{{\"jsonrpc\":\"2.0\",\"method\":\"get_transaction_receipt\",\"params\":[\"{}\"],\"id\":1}}'", tx_hash);
}

fn cmd_logs(args: &[String]) {
    let address = args.get(2).unwrap_or(&String::new()).clone();
    println!("Fetching logs...");
    if !address.is_empty() {
        println!("  Address filter: {}", address);
    }
    println!("\n  Use RPC: get_logs with filter parameters");
    println!("  curl -X POST http://localhost:9332 \\");
    println!(
        "    -d '{{\"jsonrpc\":\"2.0\",\"method\":\"get_logs\",\"params\":[\"{}\"],\"id\":1}}'",
        address
    );
}

fn cmd_deploy_package(args: &[String]) {
    let package_path = match args.get(2) {
        Some(v) => v,
        None => {
            eprintln!("Usage: wallet deploy-package <package.json> [gas_limit]");
            return;
        }
    };
    let gas_limit: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);

    let json = match std::fs::read_to_string(package_path) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to read {}: {}", package_path, e);
            return;
        }
    };

    let package = match ContractPackage::from_json(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Invalid package: {}", e);
            return;
        }
    };

    if !package.verify() {
        eprintln!("ERROR: package bytecode hash mismatch -- artifact may be tampered");
        return;
    }

    let effective_gas = if gas_limit > 0 {
        gas_limit
    } else {
        package.estimated_deploy_gas()
    };

    println!("Deploying contract from package: {}", package.name);
    println!(
        "  Bytecode:    {} bytes (hash: {}...)",
        package.code_size(),
        &package.bytecode_hash[..16]
    );
    println!("  VM version:  {}", package.vm_version);
    println!(
        "  Gas limit:   {} ({})",
        effective_gas,
        if gas_limit > 0 { "custom" } else { "estimated" }
    );
    println!("  Verified:    bytecode integrity OK");

    let mut wallet = match load_and_unlock_wallet() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Wallet error: {}", e);
            return;
        }
    };

    match wallet.build_deploy_tx(0, package.bytecode.clone(), 0, effective_gas, 1000) {
        Ok(_tx) => {
            println!("\n  TX type:     ContractCreate");
            println!("  TX built successfully");
            println!("\n  After deployment, verify with:");
            println!("    wallet verify <contract_address> {}", package_path);
        }
        Err(e) => eprintln!("Failed: {}", e),
    }
}

fn cmd_verify(args: &[String]) {
    let address = match args.get(2) {
        Some(v) => v,
        None => {
            eprintln!("Usage: wallet verify <contract_address> <package.json>");
            return;
        }
    };
    let package_path = match args.get(3) {
        Some(v) => v,
        None => {
            eprintln!("Usage: wallet verify <contract_address> <package.json>");
            return;
        }
    };

    let json = match std::fs::read_to_string(package_path) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to read {}: {}", package_path, e);
            return;
        }
    };

    let package = match ContractPackage::from_json(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Invalid package: {}", e);
            return;
        }
    };

    println!("Verifying contract {} against {}...", address, package_path);
    println!("  Package name:     {}", package.name);
    println!("  Package hash:     {}...", &package.bytecode_hash[..16]);
    println!("  VM version:       {}", package.vm_version);
    println!(
        "\n  Use RPC: verify_contract {} '{}'",
        address,
        json.replace('\n', "")
    );
    println!("\n  curl -X POST http://localhost:9332 \\");
    println!("    -d '{{\"jsonrpc\":\"2.0\",\"method\":\"verify_contract\",\"params\":[\"{}\",<package_json>],\"id\":1}}'", address);
}

fn print_help() {
    println!("ShadowDAG Wallet v1.0.0");
    println!();
    println!("USAGE:");
    println!("  shadowdag-wallet <COMMAND> [ARGS]");
    println!();
    println!("COMMANDS:");
    println!("  new [network]           Create a new wallet (mainnet/testnet/regtest)");
    println!("  balance [address]       Check address balance (uses wallet address if omitted)");
    println!("  send <to> <amount>      Send SDAG to address");
    println!("  stealth [base_addr]     Generate stealth address");
    println!("  invisible [network]     Create invisible wallet (ghost mode)");
    println!("  export                  Export wallet keys as JSON");
    println!("  info                    Show wallet info");
    println!();
    println!("CONTRACT COMMANDS:");
    println!("  deploy <bytecode_hex> [gas_limit] [value]");
    println!("                          Deploy a smart contract");
    println!("  deploy-package <package.json> [gas_limit]");
    println!("                          Deploy from a ContractPackage artifact");
    println!("  call <contract_addr> <calldata_hex> [gas_limit] [value]");
    println!("                          Call a smart contract function");
    println!("  verify <contract_addr> <package.json>");
    println!("                          Verify deployed contract against a package");
    println!("  receipt <tx_hash>       Fetch a transaction receipt");
    println!("  logs [address]          Fetch contract logs");
    println!();
    println!("  help                    Show this help");
    println!();
    println!("ENVIRONMENT:");
    println!(
        "  SHADOWDAG_NETWORK       Network to use: mainnet, testnet, regtest (default: mainnet)"
    );
    println!("  SHADOWDAG_WALLET_DB     Path to wallet database (default: ~/.shadowdag/wallet_db)");
    println!("  SHADOWDAG_WALLET_DIR    Path to wallet directory (default: ~/.shadowdag/)");
    println!("  SHADOWDAG_DB            Path to UTXO database (default: ~/.shadowdag/data/utxo)");
}

// ===========================================================================
// GUI Mode — native desktop window with embedded webview
// ===========================================================================
//
// Built only when `--features desktop` is set. Starts a local HTTP server
// that serves both the wallet HTML and JSON API (same origin), then opens a
// native window pointing to that server.
// ===========================================================================

#[cfg(feature = "desktop")]
mod gui {
    use std::io::{BufRead, BufReader, Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::dpi::{LogicalPosition, LogicalSize as WryLogicalSize};
    use wry::{Rect, WebViewBuilder};

    const WALLET_HTML: &str =
        include_str!("../service/network/wallet_ui/html_standalone.html");

    const MAX_CONNECTIONS: usize = 16;
    const READ_TIMEOUT_SECS: u64 = 5;
    const MAX_REQUEST_LINE: usize = 4096;
    const MAX_HEADER_LINES: usize = 64;
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    const MAX_BODY_BYTES: usize = 64 * 1024;
    const RPC_TIMEOUT_SECS: u64 = 5;

    pub fn run(args: &[String]) {
        let rpc_addr =
            parse_flag(args, "--rpc").unwrap_or_else(|| "127.0.0.1:9332".to_string());
        let network = parse_flag(args, "--network").unwrap_or_else(|| {
            if rpc_addr.contains("19332") {
                "testnet".to_string()
            } else if rpc_addr.contains("29332") {
                "regtest".to_string()
            } else {
                "mainnet".to_string()
            }
        });

        // Start local server (HTML + API on same origin)
        let server_port = start_server(rpc_addr, network.clone());
        let url = format!("http://127.0.0.1:{}", server_port);

        // Create native window
        let event_loop = EventLoop::new();
        let window = WindowBuilder::new()
            .with_title(format!("ShadowDAG Wallet — {}", network))
            .with_inner_size(LogicalSize::new(1280.0, 860.0))
            .with_min_inner_size(LogicalSize::new(800.0, 600.0))
            .build(&event_loop)
            .expect("Failed to create window");

        // Create webview with explicit bounds
        let size = window.inner_size();
        let builder = WebViewBuilder::new_as_child(&window)
            .with_bounds(Rect {
                position: LogicalPosition::new(0, 0).into(),
                size: WryLogicalSize::new(size.width, size.height).into(),
            })
            .with_url(&url);

        #[cfg(debug_assertions)]
        let builder = builder.with_devtools(true);

        let webview = builder.build().expect("Failed to create webview");

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            match event {
                Event::WindowEvent {
                    event: WindowEvent::Resized(new_size),
                    ..
                } => {
                    let _ = webview.set_bounds(Rect {
                        position: LogicalPosition::new(0, 0).into(),
                        size: WryLogicalSize::new(new_size.width, new_size.height).into(),
                    });
                }
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

    // ── RPC Client ──
    fn rpc_call(
        rpc_addr: &str,
        method: &str,
        params: &[serde_json::Value],
    ) -> serde_json::Value {
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
                return serde_json::json!({"error": format!("Cannot connect to node: {}", e)})
            }
        };
        let _ = stream
            .set_read_timeout(Some(std::time::Duration::from_secs(RPC_TIMEOUT_SECS)));
        let _ = stream
            .set_write_timeout(Some(std::time::Duration::from_secs(RPC_TIMEOUT_SECS)));

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

    // ── HTTP Server ──
    fn start_server(rpc_addr: String, network: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind server");
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
                            handle_request(stream, &rpc, &net);
                            active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(_) => continue,
                }
            }
        });

        port
    }

    fn handle_request(mut stream: TcpStream, rpc_addr: &str, network: &str) {
        let _ = stream
            .set_read_timeout(Some(std::time::Duration::from_secs(READ_TIMEOUT_SECS)));

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
                    if header_lines > MAX_HEADER_LINES || header_bytes > MAX_HEADER_BYTES
                    {
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

        let body = if method == "POST"
            && content_length > 0
            && content_length <= MAX_BODY_BYTES
        {
            let mut buf = vec![0u8; content_length];
            if reader.read_exact(&mut buf).is_err() {
                return;
            }
            String::from_utf8_lossy(&buf).to_string()
        } else {
            String::new()
        };

        match (method, path) {
            ("GET", "/" | "/index.html") => {
                send_response(&mut stream, 200, "text/html; charset=utf-8", WALLET_HTML.as_bytes());
            }
            ("GET", "/api/wallet/overview") => {
                send_json(&mut stream, &api_overview(rpc_addr, network));
            }
            ("GET", "/api/wallet/network") => {
                send_json(&mut stream, &api_network(rpc_addr));
            }
            ("GET", p) if p.starts_with("/api/wallet/balance/") => {
                let addr = &p["/api/wallet/balance/".len()..];
                send_json(&mut stream, &api_balance(rpc_addr, addr));
            }
            ("POST", "/api/wallet/send") => {
                send_json(&mut stream, &api_send(rpc_addr, &body));
            }
            ("GET", "/favicon.ico") => {
                send_response(&mut stream, 204, "text/plain", b"");
            }
            _ => {
                send_response(&mut stream, 404, "text/plain", b"Not Found");
            }
        }
    }

    // ── API Handlers ──
    fn api_overview(rpc_addr: &str, network: &str) -> serde_json::Value {
        let info = rpc_call(rpc_addr, "getnetworkinfo", &[]);
        let height_val = rpc_call(rpc_addr, "getblockcount", &[]);
        let mempool = rpc_call(rpc_addr, "getmempoolinfo", &[]);

        let height = if height_val.is_number() {
            height_val.as_u64().unwrap_or(0)
        } else {
            height_val
                .get("best_height")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        };
        let peer_count = info
            .get("peer_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let version = info
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("1.0.0");
        let mempool_size = mempool.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let net_name = info
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or(network);

        serde_json::json!({
            "node_version": version,
            "network": net_name,
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
        let height = info
            .get("best_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        serde_json::json!({
            "network": info.get("network").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "p2p_port": info.get("p2p_port").and_then(|v| v.as_u64()).unwrap_or(0),
            "rpc_port": info.get("rpc_port").and_then(|v| v.as_u64()).unwrap_or(0),
            "peer_count": info.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0),
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
            result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0)
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

    // ── HTTP helpers ──
    fn send_json(stream: &mut TcpStream, data: &serde_json::Value) {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        send_response(stream, 200, "application/json", body.as_bytes());
    }

    fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let status_text = match status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "OK",
        };
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            status_text,
            content_type,
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }
}
