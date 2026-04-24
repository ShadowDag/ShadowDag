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
use zeroize::Zeroizing;

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
    wallet_db_path_for(&wallet_network())
}

/// Network-parameterised variant — used by the GUI so it never has to
/// mutate the process-wide SHADOWDAG_NETWORK env var (which is UB in
/// multithreaded Rust).
fn wallet_db_path_for(network: &str) -> String {
    if let Ok(custom) = std::env::var("SHADOWDAG_WALLET_DB") {
        return custom;
    }
    let base = default_wallet_dir();
    format!("{}/{}/wallet_db", base.display(), network)
}

/// Path to the encrypted seed file.
/// Network-aware: stores seed under ~/.shadowdag/<network>/seed.dat
fn seed_path() -> PathBuf {
    seed_path_for(&wallet_network())
}

fn seed_path_for(network: &str) -> PathBuf {
    if let Ok(custom) = std::env::var("SHADOWDAG_WALLET_DIR") {
        return PathBuf::from(custom).join("seed.dat");
    }
    let base = default_wallet_dir();
    base.join(network).join("seed.dat")
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

/// Write the encrypted seed with owner-only permissions (0o600 on Unix,
/// ACL hardened on Windows via default user-only ACL). Uses `create_new`
/// so two concurrent writers can never silently overwrite each other —
/// the second caller gets `AlreadyExists`.
fn save_encrypted_seed(enc: &EncryptedSeed) -> Result<(), WalletError> {
    save_encrypted_seed_at(&seed_path(), enc)
}

fn save_encrypted_seed_at(path: &std::path::Path, enc: &EncryptedSeed) -> Result<(), WalletError> {
    let dir = path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    std::fs::create_dir_all(&dir)
        .map_err(|e| WalletError::Other(format!("Cannot create dir: {}", e)))?;
    let data = bincode::serialize(enc)
        .map_err(|e| WalletError::Other(format!("Serialize error: {}", e)))?;

    // Write atomically to a tmp file with owner-only perms, then rename.
    // On Unix: mode 0o600 via OpenOptionsExt.
    // On Windows: files created by a user inherit that user's ACL by
    // default when the parent dir is %USERPROFILE%\.shadowdag — good enough.
    let tmp_path = path.with_extension("dat.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .map_err(|e| WalletError::Other(format!("Open tmp failed: {}", e)))?;
        use std::io::Write as _;
        f.write_all(&data)
            .map_err(|e| WalletError::Other(format!("Write tmp failed: {}", e)))?;
        f.sync_all()
            .map_err(|e| WalletError::Other(format!("Sync tmp failed: {}", e)))?;
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|e| WalletError::Other(format!("Rename failed: {}", e)))?;
    Ok(())
}

fn load_encrypted_seed() -> Result<EncryptedSeed, WalletError> {
    let data = std::fs::read(seed_path())
        .map_err(|e| WalletError::Other(format!("Cannot read seed file: {}", e)))?;
    bincode::deserialize(&data).map_err(|e| WalletError::Other(format!("Deserialize error: {}", e)))
}

/// Read a password from the terminal with echo disabled (hidden input).
///
/// Uses rpassword which disables terminal echo via platform-specific APIs
/// (termios on Unix, GetConsoleMode on Windows). Falls back to plain read
/// when stdin is not a TTY (e.g. pipes, CI) — this is required for
/// non-interactive use but does NOT hide input in that case.
///
/// Returns a Zeroizing<String> so the buffer is wiped on drop.
fn prompt_password(prompt_msg: &str) -> Zeroizing<String> {
    eprint!("{}", prompt_msg);
    io::stderr().flush().ok();

    // rpassword::read_password reads without echoing when stdin is a TTY.
    // When stdin is redirected (pipe, file), it falls back to a line read.
    let input = match rpassword::read_password() {
        Ok(s) => s,
        Err(e) => {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                slog_error!("wallet", "stdin_closed_eof", hint => "pipe password via stdin for non-interactive use");
            } else {
                slog_error!("wallet", "password_read_failed", error => &e.to_string());
            }
            std::process::exit(1);
        }
    };

    // Wrap in Zeroizing so the allocation is wiped on drop.
    let mut wrapped = Zeroizing::new(input);

    // Normalise by trimming trailing CR/LF/whitespace. Since trim() returns a
    // borrowed slice, we copy into a new Zeroizing and drop the original.
    let trimmed = Zeroizing::new(wrapped.trim().to_string());
    // Explicitly clear the original before it drops (defence in depth —
    // Zeroizing will also do this, but being explicit documents intent).
    wrapped.clear();
    drop(wrapped);

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

/// Load an existing wallet from the DB and unlock it with a password.
///
/// The password is held in `Zeroizing<String>`, so its backing allocation is
/// wiped automatically on drop regardless of which code path exits the fn.
fn load_and_unlock_wallet() -> Result<Wallet, WalletError> {
    // Collect password and encrypted seed BEFORE acquiring the mutex so that
    // blocking I/O (the password prompt) never holds the lock. This eliminates
    // the deadlock risk when another thread also needs UNLOCK_MUTEX.
    let password = prompt_password("Enter wallet password: ");
    let enc_seed = load_encrypted_seed()?;

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
        return Err(e);
    }
    // After unlocking, derive account 0 to get the address
    temp.add_account(0, "Default Account")?;
    let addr = temp.address();

    // Try to load persisted wallet state (UTXOs, history, etc.)
    match db.get_wallet(&addr) {
        Ok(Some(mut persisted)) => {
            if let Err(e) = persisted.unlock(&enc_seed, &password) {
                // Rate limit after failed password attempt
                std::thread::sleep(std::time::Duration::from_secs(1));
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
    }
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
    if *password != *confirm {
        // Both are Zeroizing<String> — auto-wiped on drop at fn exit
        eprintln!("Error: passwords do not match.");
        return;
    }
    drop(confirm); // release the duplicate early

    let mut wallet = Wallet::new(network);
    let (mnemonic, enc_seed) = match wallet.create(&password) {
        Ok(r) => r,
        Err(e) => {
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
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};

    use once_cell::sync::Lazy;
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::dpi::{LogicalPosition, LogicalSize as WryLogicalSize};
    use wry::{Rect, WebViewBuilder};
    use zeroize::Zeroizing;

    use shadowdag::domain::address::stealth_address::StealthAddress;
    use shadowdag::service::wallet::core::wallet::Wallet;
    use shadowdag::service::wallet::storage::wallet_db::WalletDB;

    const WALLET_HTML: &str =
        include_str!("../service/network/wallet_ui/html_standalone.html");

    /// In-memory unlocked wallet. Held under a Mutex so handlers can
    /// mutate it (add accounts, etc.). Seed material is zeroized when the
    /// Wallet is dropped (via its internal `lock()` in Drop).
    static WALLET: Lazy<Arc<StdMutex<Option<Wallet>>>> =
        Lazy::new(|| Arc::new(StdMutex::new(None)));

    /// Global create lock — serialises `/api/wallet/create` to close the
    /// check-then-act TOCTOU race on the seed file existence check.
    static CREATE_LOCK: Lazy<Arc<StdMutex<()>>> =
        Lazy::new(|| Arc::new(StdMutex::new(())));

    /// Exponential-backoff counter for failed unlock attempts (process-wide).
    /// Not per-IP because this server is localhost-only; a single counter
    /// is sufficient to slow down a wrong-password loop.
    static UNLOCK_FAILURES: Lazy<Arc<StdMutex<u32>>> =
        Lazy::new(|| Arc::new(StdMutex::new(0)));

    /// One-time mnemonic slot. After `api_create` the mnemonic is parked
    /// here and a single-use token is returned. The UI fetches the mnemonic
    /// via `GET /api/wallet/mnemonic?token=...` which drains the slot
    /// immediately — so the mnemonic never lives in the create response
    /// and is wiped from server memory after the first read.
    static MNEMONIC_SLOT: Lazy<Arc<StdMutex<Option<(String, Zeroizing<Vec<Zeroizing<String>>>)>>>> =
        Lazy::new(|| Arc::new(StdMutex::new(None)));

    /// Acquire a lock on an std Mutex, recovering from poison. Handlers
    /// never panic just because another thread crashed while holding the
    /// lock — the locked data is simply treated as still valid.
    fn lock_recover<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
        match m.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Cryptographically random 32-byte hex token.
    fn new_token() -> String {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        hex::encode(b)
    }

    const MAX_CONNECTIONS: usize = 16;
    const READ_TIMEOUT_SECS: u64 = 5;
    const REQUEST_DEADLINE_SECS: u64 = 15; // overall deadline per request
    const MAX_REQUEST_LINE: usize = 4096;
    const MAX_HEADER_LINES: usize = 64;
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    const MAX_BODY_BYTES: usize = 64 * 1024;
    const MAX_HOST_HEADER_BYTES: usize = 256;
    const MAX_PATH_BYTES: usize = 512;
    const MAX_ADDR_BYTES: usize = 128; // longest plausible SDAG address
    const RPC_TIMEOUT_SECS: u64 = 5;
    const SEED_PROBE_TIMEOUT_SECS: u64 = 3;

    /// Official ShadowDAG seed RPC endpoints. The wallet picks the first one
    /// that responds on startup, so users don't need to configure anything.
    ///
    /// Override with `--rpc=HOST:PORT` to use a custom node (e.g. a local
    /// one for full trustlessness).
    const DEFAULT_SEED_ENDPOINTS: &[&str] = &[
        "144.172.105.147:9332",
        "45.61.151.206:9332",
        "172.86.90.70:9332",
    ];

    /// Parsed + validated RPC target. Using the SocketAddr's own
    /// fmt avoids any user-controlled characters (CRLF etc.) in the
    /// outbound HTTP Host header.
    #[derive(Clone)]
    struct RpcTarget {
        socket: SocketAddr,
        display: String, // canonical "ip:port" form from the parsed addr
    }

    pub fn run(args: &[String]) {
        // Explicit --rpc=HOST:PORT overrides the seed list.
        let user_rpc = parse_flag(args, "--rpc");

        let rpc_target = match user_rpc {
            Some(raw) => match parse_rpc_target(&raw) {
                Some(t) => t,
                None => {
                    eprintln!("[wallet] invalid --rpc address: {}", raw);
                    return;
                }
            },
            None => match pick_first_live_seed() {
                Some(t) => {
                    eprintln!("[wallet] connected to seed node {}", t.display);
                    t
                }
                None => {
                    eprintln!(
                        "[wallet] no seed nodes reachable — falling back to 127.0.0.1:9332"
                    );
                    eprintln!("         (check internet; or run a local node)");
                    parse_rpc_target("127.0.0.1:9332")
                        .expect("hardcoded loopback should always parse")
                }
            },
        };

        // Info banner (not a warning) when using a remote seed node.
        if !is_loopback_ip(&rpc_target.socket) {
            eprintln!("[wallet] using remote RPC: {}", rpc_target.display);
            eprintln!("         - Balance / height data comes from this server.");
            eprintln!("         - To send transactions, use the CLI wallet (signing is local).");
        }

        let network = parse_flag(args, "--network").unwrap_or_else(|| {
            // Auto-detect from the RPC port (no substring matching on raw input).
            match rpc_target.socket.port() {
                19332 => "testnet".to_string(),
                29332 => "regtest".to_string(),
                _ => "mainnet".to_string(),
            }
        });

        // Start local server (HTML + API on same origin, localhost-only).
        let server_port = match start_server(rpc_target, network.clone()) {
            Some(p) => p,
            None => {
                eprintln!("[wallet] failed to start local HTTP server");
                return;
            }
        };
        let url = format!("http://127.0.0.1:{}", server_port);

        // Create native window (no panics on failure).
        let event_loop = EventLoop::new();
        let window = match WindowBuilder::new()
            .with_title(format!("ShadowDAG Wallet — {}", network))
            .with_inner_size(LogicalSize::new(1280.0, 860.0))
            .with_min_inner_size(LogicalSize::new(800.0, 600.0))
            .build(&event_loop)
        {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[wallet] failed to create window: {}", e);
                return;
            }
        };

        let size = window.inner_size();
        let builder = WebViewBuilder::new_as_child(&window)
            .with_bounds(Rect {
                position: LogicalPosition::new(0, 0).into(),
                size: WryLogicalSize::new(size.width, size.height).into(),
            })
            .with_url(&url);

        #[cfg(debug_assertions)]
        let builder = builder.with_devtools(true);

        let webview = match builder.build() {
            Ok(wv) => wv,
            Err(e) => {
                eprintln!("[wallet] failed to create webview: {}", e);
                eprintln!("        On Windows, ensure WebView2 Runtime is installed:");
                eprintln!("        https://developer.microsoft.com/microsoft-edge/webview2/");
                return;
            }
        };

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

    fn parse_rpc_target(raw: &str) -> Option<RpcTarget> {
        // Reject obvious control characters up-front (defence in depth —
        // SocketAddr's own parser also rejects these, but being explicit
        // makes the guarantee visible at the call site).
        if raw.chars().any(|c| c.is_control()) {
            return None;
        }
        let socket: SocketAddr = raw.parse().ok()?;
        // Use the SocketAddr's own Display impl — canonical, no CRLF.
        let display = socket.to_string();
        Some(RpcTarget { socket, display })
    }

    fn is_loopback_ip(addr: &SocketAddr) -> bool {
        addr.ip().is_loopback()
    }

    /// Probe each seed endpoint and return the first one that accepts a TCP
    /// connection within SEED_PROBE_TIMEOUT_SECS. Preserves the order from
    /// DEFAULT_SEED_ENDPOINTS so users get deterministic failover behaviour.
    ///
    /// Probes run serially (not in parallel) to keep the wallet startup
    /// predictable and avoid a burst of connections when all seeds are up.
    fn pick_first_live_seed() -> Option<RpcTarget> {
        for ep in DEFAULT_SEED_ENDPOINTS {
            let target = match parse_rpc_target(ep) {
                Some(t) => t,
                None => {
                    eprintln!("[wallet] skipping invalid seed: {}", ep);
                    continue;
                }
            };
            match TcpStream::connect_timeout(
                &target.socket,
                Duration::from_secs(SEED_PROBE_TIMEOUT_SECS),
            ) {
                Ok(s) => {
                    // Close immediately — we only wanted to know it's up.
                    drop(s);
                    return Some(target);
                }
                Err(_) => continue,
            }
        }
        None
    }

    /// Strip characters that could break out of a JSON string into HTML when
    /// the result is rendered by `innerHTML`. JSON escaping alone is not
    /// enough because `innerHTML` parses HTML, not JSON. We replace the
    /// dangerous chars entirely rather than HTML-encoding them, because the
    /// RPC strings that reach the UI (version, network name, block hash) are
    /// not expected to contain them in honest operation.
    fn sanitize_display(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                '<' | '>' | '&' | '\'' | '"' | '`' | '\u{0000}'..='\u{001F}' => '?',
                other => other,
            })
            .take(256)
            .collect()
    }

    /// Host / Origin validation — mitigate DNS rebinding and browser CSRF
    /// against the localhost wallet UI. Accept ONLY loopback hostnames.
    fn is_safe_local_request(host: Option<&str>, origin: Option<&str>) -> bool {
        if let Some(h) = host {
            let h = h.to_ascii_lowercase();
            let host_only = h.split(':').next().unwrap_or("").trim();
            if host_only != "127.0.0.1" && host_only != "localhost" && host_only != "[::1]"
            {
                return false;
            }
        }
        if let Some(o) = origin {
            let o = o.to_ascii_lowercase();
            if !(o.starts_with("http://127.0.0.1")
                || o.starts_with("http://localhost")
                || o.starts_with("http://[::1]"))
            {
                return false;
            }
        }
        true
    }

    // ── RPC Client ──
    fn rpc_call(
        target: &RpcTarget,
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

        let stream = match TcpStream::connect_timeout(
            &target.socket,
            Duration::from_secs(RPC_TIMEOUT_SECS),
        ) {
            Ok(s) => s,
            // Generic error — don't leak OS error details to the webview.
            Err(_) => return serde_json::json!({"error": "rpc unreachable"}),
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)));

        let mut stream = stream;
        // Use the PARSED address's Display for the Host header, not the raw
        // user input — guarantees no CRLF injection into request headers.
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            target.display,
            body_str.len(),
            body_str
        );

        if stream.write_all(request.as_bytes()).is_err() {
            return serde_json::json!({"error": "rpc write failed"});
        }
        let _ = stream.flush();

        let mut response = String::new();
        if stream.read_to_string(&mut response).is_err() {
            return serde_json::json!({"error": "rpc read failed"});
        }

        if let Some(idx) = response.find("\r\n\r\n") {
            let json_str = &response[idx + 4..];
            match serde_json::from_str::<serde_json::Value>(json_str) {
                Ok(val) => {
                    if let Some(result) = val.get("result") {
                        return result.clone();
                    }
                    if val.get("error").is_some() {
                        // Don't echo node error back — just say it failed.
                        return serde_json::json!({"error": "rpc returned error"});
                    }
                    val
                }
                Err(_) => serde_json::json!({"error": "invalid rpc response"}),
            }
        } else {
            serde_json::json!({"error": "malformed rpc response"})
        }
    }

    // ── HTTP Server ──
    fn start_server(target: RpcTarget, network: String) -> Option<u16> {
        // Bind to loopback ONLY. Never listen on 0.0.0.0.
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        let active = Arc::new(AtomicUsize::new(0));

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        // CAS-based admission: reject before spawning thread
                        // if at capacity. Eliminates the fetch_add race.
                        let mut current = active.load(Ordering::Acquire);
                        loop {
                            if current >= MAX_CONNECTIONS {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                break;
                            }
                            match active.compare_exchange_weak(
                                current,
                                current + 1,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            ) {
                                Ok(_) => {
                                    let rpc = target.clone();
                                    let net = network.clone();
                                    let active = Arc::clone(&active);
                                    std::thread::spawn(move || {
                                        handle_request(stream, &rpc, &net);
                                        active.fetch_sub(1, Ordering::Release);
                                    });
                                    break;
                                }
                                Err(actual) => {
                                    current = actual;
                                    // retry
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        Some(port)
    }

    fn handle_request(mut stream: TcpStream, target: &RpcTarget, network: &str) {
        let deadline = Instant::now() + Duration::from_secs(REQUEST_DEADLINE_SECS);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));

        let clone = match stream.try_clone() {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut reader = BufReader::new(clone);

        // ── Request line ──
        let mut request_line = String::new();
        {
            let mut limited = (&mut reader).take(MAX_REQUEST_LINE as u64);
            if limited.read_line(&mut request_line).is_err() {
                return;
            }
        }
        if Instant::now() > deadline {
            return;
        }
        if request_line.len() >= MAX_REQUEST_LINE && !request_line.ends_with('\n') {
            send_response(&mut stream, 414, "text/plain", b"URI Too Long");
            return;
        }

        // ── Headers (with Host/Origin extraction for DNS-rebinding guard) ──
        let mut content_length: usize = 0;
        let mut host_header: Option<String> = None;
        let mut origin_header: Option<String> = None;
        let mut header_line = String::new();
        let mut header_lines = 0usize;
        let mut header_bytes = 0usize;
        loop {
            if Instant::now() > deadline {
                return;
            }
            header_line.clear();
            match reader.read_line(&mut header_line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    header_lines += 1;
                    header_bytes += header_line.len();
                    if header_lines > MAX_HEADER_LINES || header_bytes > MAX_HEADER_BYTES {
                        send_response(&mut stream, 431, "text/plain", b"Headers Too Large");
                        return;
                    }
                    let trimmed = header_line.trim();
                    let lower = trimmed.to_ascii_lowercase();
                    if lower.starts_with("content-length:") {
                        if let Some((_, val)) = trimmed.split_once(':') {
                            content_length = val.trim().parse().unwrap_or(0);
                        }
                    } else if lower.starts_with("host:") {
                        if let Some((_, val)) = trimmed.split_once(':') {
                            let h = val.trim();
                            if h.len() <= MAX_HOST_HEADER_BYTES {
                                host_header = Some(h.to_string());
                            }
                        }
                    } else if lower.starts_with("origin:") {
                        if let Some((_, val)) = trimmed.split_once(':') {
                            let o = val.trim();
                            if o.len() <= MAX_HOST_HEADER_BYTES {
                                origin_header = Some(o.to_string());
                            }
                        }
                    }
                    if trimmed.is_empty() {
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

        if path.len() > MAX_PATH_BYTES {
            send_response(&mut stream, 414, "text/plain", b"URI Too Long");
            return;
        }

        if method != "GET" && method != "POST" {
            send_response(&mut stream, 405, "text/plain", b"Method Not Allowed");
            return;
        }

        // DNS-rebinding / CSRF guard.
        if !is_safe_local_request(host_header.as_deref(), origin_header.as_deref()) {
            send_response(&mut stream, 403, "text/plain", b"Forbidden");
            return;
        }

        // ── Body (POST) — strict UTF-8, no lossy conversion ──
        let body = if method == "POST"
            && content_length > 0
            && content_length <= MAX_BODY_BYTES
        {
            if Instant::now() > deadline {
                return;
            }
            let mut buf = vec![0u8; content_length];
            if reader.read_exact(&mut buf).is_err() {
                return;
            }
            match String::from_utf8(buf) {
                Ok(s) => s,
                Err(_) => {
                    send_response(&mut stream, 400, "text/plain", b"Invalid UTF-8 body");
                    return;
                }
            }
        } else {
            String::new()
        };

        match (method, path) {
            ("GET", "/" | "/index.html") => {
                send_response(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    WALLET_HTML.as_bytes(),
                );
            }
            ("GET", "/api/wallet/overview") => {
                send_json(&mut stream, &api_overview(target, network));
            }
            ("GET", "/api/wallet/network") => {
                send_json(&mut stream, &api_network(target));
            }
            ("GET", p) if p.starts_with("/api/wallet/balance/") => {
                let addr = &p["/api/wallet/balance/".len()..];
                if addr.is_empty() || addr.len() > MAX_ADDR_BYTES {
                    send_response(&mut stream, 400, "text/plain", b"Invalid address");
                    return;
                }
                // Only ASCII alphanumerics + a few separators allowed in
                // SDAG addresses — reject anything that could be a path or
                // payload injection vector.
                if !addr
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    send_response(&mut stream, 400, "text/plain", b"Invalid address");
                    return;
                }
                send_json(&mut stream, &api_balance(target, addr));
            }
            ("POST", "/api/wallet/send") => {
                send_json(&mut stream, &api_send(target, &body));
            }
            // ── Wallet management (create / unlock / lock / accounts) ──
            ("GET", "/api/wallet/state") => {
                send_json(&mut stream, &api_state());
            }
            ("POST", "/api/wallet/create") => {
                send_json_nostore(&mut stream, &api_create(&body));
            }
            ("POST", "/api/wallet/unlock") => {
                send_json_nostore(&mut stream, &api_unlock(&body));
            }
            ("POST", "/api/wallet/lock") => {
                send_json(&mut stream, &api_lock());
            }
            ("GET", p) if p.starts_with("/api/wallet/mnemonic") => {
                // Extract query string (everything after the first '?')
                let query = p.split_once('?').map(|x| x.1).unwrap_or("");
                send_json_nostore(&mut stream, &api_mnemonic(&format!("?{}", query)));
            }
            ("GET", "/api/wallet/accounts") => {
                send_json(&mut stream, &api_accounts());
            }
            ("POST", "/api/wallet/new-account") => {
                send_json(&mut stream, &api_new_account(&body));
            }
            ("POST", "/api/wallet/new-stealth") => {
                send_json(&mut stream, &api_new_stealth(&body));
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
    fn api_overview(target: &RpcTarget, network: &str) -> serde_json::Value {
        let info = rpc_call(target, "getnetworkinfo", &[]);
        let height_val = rpc_call(target, "getblockcount", &[]);
        let mempool = rpc_call(target, "getmempoolinfo", &[]);

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
        // Sanitize any display strings coming from RPC — a malicious or
        // compromised RPC could otherwise inject HTML into innerHTML.
        let version = sanitize_display(
            info.get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("1.0.0"),
        );
        let mempool_size = mempool.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let net_name = sanitize_display(
            info.get("network")
                .and_then(|v| v.as_str())
                .unwrap_or(network),
        );
        let best_hash = sanitize_display(
            info.get("best_hash").and_then(|v| v.as_str()).unwrap_or(""),
        );

        serde_json::json!({
            "node_version": version,
            "network": net_name,
            "best_height": height,
            "best_hash": best_hash,
            "peer_count": peer_count,
            "mempool_size": mempool_size,
            "chain_name": "ShadowDAG",
            "max_supply": 2_100_000_000_000_000_000u64,
        })
    }

    fn api_network(target: &RpcTarget) -> serde_json::Value {
        let info = rpc_call(target, "getnetworkinfo", &[]);
        let height = info
            .get("best_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let network = sanitize_display(
            info.get("network")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
        );

        serde_json::json!({
            "network": network,
            "p2p_port": info.get("p2p_port").and_then(|v| v.as_u64()).unwrap_or(0),
            "rpc_port": info.get("rpc_port").and_then(|v| v.as_u64()).unwrap_or(0),
            "peer_count": info.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0),
            "best_height": height,
            "rpc_endpoint": target.display,
        })
    }

    fn api_balance(target: &RpcTarget, addr: &str) -> serde_json::Value {
        let result = rpc_call(
            target,
            "getbalancebyaddress",
            &[serde_json::Value::String(addr.to_string())],
        );
        let balance = if result.is_number() {
            result.as_u64().unwrap_or(0)
        } else {
            result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0)
        };
        serde_json::json!({
            // `addr` is already validated against [A-Za-z0-9_-] in the router.
            "address": addr,
            "balance": balance,
            "balance_sdag": balance as f64 / 100_000_000.0,
        })
    }

    fn api_send(target: &RpcTarget, body: &str) -> serde_json::Value {
        let req: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return serde_json::json!({"error": "invalid json"}),
        };
        let to_raw = req.get("to").and_then(|v| v.as_str()).unwrap_or("");
        let amount_raw = req.get("amount").and_then(|v| v.as_str()).unwrap_or("0");

        // Validate both fields — the UI should already do this but never
        // trust the client. Sanitize before echoing back.
        if to_raw.is_empty() || to_raw.len() > MAX_ADDR_BYTES {
            return serde_json::json!({"error": "invalid 'to' address"});
        }
        if !to_raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return serde_json::json!({"error": "invalid 'to' address"});
        }
        if amount_raw.is_empty() || amount_raw.len() > 32 {
            return serde_json::json!({"error": "invalid 'amount'"});
        }
        if !amount_raw
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ',')
        {
            return serde_json::json!({"error": "invalid 'amount'"});
        }

        // Echo back — these are sanitized.
        serde_json::json!({
            "status": "prepared",
            "to": to_raw,
            "amount": amount_raw,
            "message": format!("Sign via CLI:\n  shadowdag-wallet send {} {}", to_raw, amount_raw),
            "rpc_endpoint": target.display,
        })
    }

    // ── Wallet Management Handlers ────────────────────────────────────

    /// Status of the wallet: whether a seed file exists on disk, and whether
    /// it is currently unlocked in memory. Used by the HTML to decide
    /// whether to show the welcome screen, the unlock screen, or the
    /// main UI.
    fn api_state() -> serde_json::Value {
        // We can't know the user-chosen network without an unlocked wallet,
        // so scan all three known networks for a seed file.
        let has_seed_main = super::seed_path_for("mainnet").exists();
        let has_seed_test = super::seed_path_for("testnet").exists();
        let has_seed_reg = super::seed_path_for("regtest").exists();
        let has_seed = has_seed_main || has_seed_test || has_seed_reg;
        let detected_network = if has_seed_main {
            "mainnet"
        } else if has_seed_test {
            "testnet"
        } else if has_seed_reg {
            "regtest"
        } else {
            ""
        };

        let guard = lock_recover(&WALLET);
        let unlocked = guard.is_some();
        let (primary_addr, network, account_count) = match guard.as_ref() {
            Some(w) => (
                w.address(),
                detect_network_from_address(&w.address()),
                w.accounts().len(),
            ),
            None => (String::new(), detected_network.to_string(), 0),
        };
        drop(guard);
        serde_json::json!({
            "has_seed": has_seed,
            "unlocked": unlocked,
            "primary_address": primary_addr,
            "account_count": account_count,
            "network": network,
        })
    }

    /// Extract a password field from a JSON body, zeroizing the intermediate
    /// `serde_json::Value` so the plaintext doesn't linger in serde's
    /// allocation after we take our copy. Returns Zeroizing<String>.
    fn extract_password(body: &str) -> Option<Zeroizing<String>> {
        let mut v: serde_json::Value = serde_json::from_str(body).ok()?;
        let p = v.get("password")?.as_str()?.to_string();
        // Best-effort wipe of the password string inside the Value before
        // the Value drops. serde_json::Value owns the string, so we take
        // ownership and drop our zeroising copy, then let the Value drop
        // (its internal copy is unreachable).
        if let Some(pwd_val) = v.as_object_mut().and_then(|o| o.get_mut("password")) {
            *pwd_val = serde_json::Value::Null;
        }
        drop(v);
        Some(Zeroizing::new(p))
    }

    fn extract_str<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        v.get(key)?.as_str()
    }

    /// Classify an address by prefix to pick the right network label.
    fn detect_network_from_address(addr: &str) -> String {
        if addr.starts_with("ST") {
            "testnet".to_string()
        } else if addr.starts_with("SR") {
            "regtest".to_string()
        } else {
            "mainnet".to_string()
        }
    }

    fn api_create(body: &str) -> serde_json::Value {
        // Serialise the entire create operation — closes the TOCTOU gap
        // between seed_path().exists() and save_encrypted_seed().
        let _guard = lock_recover(&CREATE_LOCK);

        let mut v: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return serde_json::json!({"error": "invalid json"}),
        };
        let password = match v.get("password").and_then(|p| p.as_str()) {
            Some(p) => Zeroizing::new(p.to_string()),
            None => return serde_json::json!({"error": "missing password"}),
        };
        let confirm = match v.get("confirm").and_then(|p| p.as_str()) {
            Some(p) => Zeroizing::new(p.to_string()),
            None => return serde_json::json!({"error": "missing confirm"}),
        };
        // Null out the plaintext fields inside the Value (#7) so they don't
        // stay in serde's allocation after we've copied them into Zeroizing.
        if let Some(o) = v.as_object_mut() {
            o.insert("password".into(), serde_json::Value::Null);
            o.insert("confirm".into(), serde_json::Value::Null);
        }

        if *password != *confirm {
            return serde_json::json!({"error": "passwords do not match"});
        }
        if password.len() < 8 {
            return serde_json::json!({"error": "password too short (min 8)"});
        }
        let network = v
            .get("network")
            .and_then(|n| n.as_str())
            .unwrap_or("mainnet")
            .to_string();
        if !matches!(network.as_str(), "mainnet" | "testnet" | "regtest") {
            return serde_json::json!({"error": "invalid network"});
        }
        drop(v); // release serde Value (with plaintext fields nulled)

        let seed_path = super::seed_path_for(&network);
        let wallet_db = super::wallet_db_path_for(&network);

        // Refuse to overwrite an existing seed file — safety belt.
        // save_encrypted_seed_at uses create_new so it also fails atomically
        // on its own, but checking here gives a clearer error message.
        if seed_path.exists() {
            return serde_json::json!({
                "error": "a wallet already exists on disk; unlock it instead"
            });
        }

        let mut wallet = Wallet::new(&network);
        let (mnemonic_vec, enc_seed) = match wallet.create(&password) {
            Ok(v) => v,
            Err(e) => return serde_json::json!({"error": format!("create failed: {}", e)}),
        };

        // Wrap the mnemonic in Zeroizing<Vec<Zeroizing<String>>> so it wipes
        // on drop. Note: the raw `mnemonic_vec` copy from Wallet::create is
        // still un-zeroised by Wallet itself (a lib-level gap), but at least
        // from here on we keep it protected.
        let mnemonic: Zeroizing<Vec<Zeroizing<String>>> = Zeroizing::new(
            mnemonic_vec.into_iter().map(Zeroizing::new).collect(),
        );

        // Persist the seed file atomically with owner-only permissions.
        if let Err(e) = super::save_encrypted_seed_at(&seed_path, &enc_seed) {
            return serde_json::json!({"error": format!("could not save seed: {}", e)});
        }

        // Persist wallet DB (UTXO cache etc.)
        match WalletDB::new(&wallet_db) {
            Ok(db) => {
                if let Err(e) = db.save_wallet(&wallet) {
                    eprintln!("[wallet] warning: save_wallet failed: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[wallet] warning: wallet_db open failed: {}", e);
            }
        }

        let address = wallet.address();

        // Stash unlocked wallet for this session.
        *lock_recover(&WALLET) = Some(wallet);

        // Park the mnemonic in the one-time slot; return only a token.
        // The UI must GET /api/wallet/mnemonic?token=... exactly once to
        // see it. This shrinks the window during which the mnemonic is in
        // buffers / responses to a single handler invocation on demand.
        let token = new_token();
        *lock_recover(&MNEMONIC_SLOT) = Some((token.clone(), mnemonic));

        serde_json::json!({
            "status": "created",
            "address": address,
            "mnemonic_token": token,
            "network": network,
            "warning": "Call GET /api/wallet/mnemonic?token=<token> ONCE to read the mnemonic. It will not be shown again.",
        })
    }

    /// Drain the one-time mnemonic slot. The token is single-use: after
    /// this call, the slot is cleared and subsequent GETs with the same
    /// token return 410 Gone / "expired".
    fn api_mnemonic(query: &str) -> serde_json::Value {
        // Parse ?token=HEX (hex chars only).
        let token = query
            .strip_prefix("?token=")
            .or_else(|| query.strip_prefix("token="))
            .unwrap_or("");
        if token.is_empty() || token.len() != 64
            || !token.chars().all(|c| c.is_ascii_hexdigit())
        {
            return serde_json::json!({"error": "invalid token"});
        }

        let mut slot = lock_recover(&MNEMONIC_SLOT);
        let taken = match slot.take() {
            Some(t) => t,
            None => return serde_json::json!({"error": "no pending mnemonic"}),
        };
        let (stored_token, mnemonic) = taken;

        // Constant-time comparison to avoid leaking token validity via timing.
        if !constant_eq(stored_token.as_bytes(), token.as_bytes()) {
            // Put it back — do NOT drain on wrong token (so the legit UI
            // can still fetch it). We could also lock-out after N wrong
            // tries, but this endpoint is localhost + origin-checked.
            *slot = Some((stored_token, mnemonic));
            return serde_json::json!({"error": "invalid token"});
        }

        // Serialise the mnemonic words out of their Zeroizing wrappers into
        // a JSON array. The Vec clone here is the minimum unavoidable copy
        // for serialisation — the slot itself is dropped on return so the
        // canonical copy is wiped.
        let words: Vec<String> = mnemonic.iter().map(|z| (**z).clone()).collect();
        drop(mnemonic); // explicit: zeroise the slot's copy now
        drop(slot);

        serde_json::json!({
            "mnemonic": words,
            "warning": "Write it down NOW. You cannot fetch this again.",
        })
    }

    /// Constant-time byte comparison — prevents timing side-channels on
    /// short secret comparisons (the token here).
    fn constant_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    fn api_unlock(body: &str) -> serde_json::Value {
        // Exponential backoff on sequential unlock failures.
        // Current delay = min(30s, 2^failures) seconds.
        let failures = *lock_recover(&UNLOCK_FAILURES);
        let delay_secs: u64 = 1u64 << failures.min(5); // 1,2,4,8,16,32s cap
        let delay = Duration::from_secs(delay_secs.min(30));

        let password = match extract_password(body) {
            Some(p) => p,
            None => return serde_json::json!({"error": "missing password"}),
        };
        // Scan all three networks for an on-disk seed. This also fixes the
        // old behaviour where wallet_network() (via env) could pick the
        // "wrong" network if the user created a testnet wallet first.
        let (seed, network) = {
            let mut found = None;
            for net in ["mainnet", "testnet", "regtest"] {
                let p = super::seed_path_for(net);
                if p.exists() {
                    match std::fs::read(&p)
                        .ok()
                        .and_then(|b| bincode::deserialize::<super::EncryptedSeed>(&b).ok())
                    {
                        Some(s) => {
                            found = Some((s, net));
                            break;
                        }
                        None => continue,
                    }
                }
            }
            match found {
                Some((s, n)) => (s, n.to_string()),
                None => {
                    return serde_json::json!({
                        "error": "no wallet on disk — create one first"
                    })
                }
            }
        };

        let mut wallet = Wallet::new(&network);
        if let Err(_) = wallet.unlock(&seed, &password) {
            // Bump failure counter and sleep before responding.
            {
                let mut f = lock_recover(&UNLOCK_FAILURES);
                *f = f.saturating_add(1);
            }
            std::thread::sleep(delay);
            return serde_json::json!({"error": "unlock failed: bad password"});
        }
        // Reset failure counter on success.
        *lock_recover(&UNLOCK_FAILURES) = 0;

        if let Err(e) = wallet.add_account(0, "Default Account") {
            return serde_json::json!({"error": format!("derive account: {}", e)});
        }

        // Load any persisted state (extra accounts, labels) from WalletDB.
        let addr = wallet.address();
        if let Ok(db) = WalletDB::new(&super::wallet_db_path_for(&network)) {
            if let Ok(Some(mut persisted)) = db.get_wallet(&addr) {
                if persisted.unlock(&seed, &password).is_ok() {
                    wallet = persisted;
                }
            }
        }

        let address = wallet.address();
        let account_count = wallet.accounts().len();
        *lock_recover(&WALLET) = Some(wallet);

        serde_json::json!({
            "status": "unlocked",
            "address": address,
            "account_count": account_count,
            "network": network,
        })
    }

    fn api_lock() -> serde_json::Value {
        let mut g = lock_recover(&WALLET);
        if let Some(mut w) = g.take() {
            // Explicit lock() to zeroise session keys before drop.
            w.lock();
        }
        // Also drop any pending mnemonic slot on lock (defence in depth).
        *lock_recover(&MNEMONIC_SLOT) = None;
        serde_json::json!({"status": "locked"})
    }

    fn api_accounts() -> serde_json::Value {
        let g = lock_recover(&WALLET);
        let w = match g.as_ref() {
            Some(w) => w,
            None => return serde_json::json!({"error": "wallet locked"}),
        };
        let accounts: Vec<serde_json::Value> = w
            .accounts()
            .iter()
            .map(|a| {
                serde_json::json!({
                    "index": a.index,
                    "label": a.label,
                    "balance": a.balance,
                    "tx_count": a.tx_count,
                    "addresses": a.addresses.iter().map(|ad| serde_json::json!({
                        "address": ad.address,
                        "public_key": ad.public_key,
                        "is_change": ad.is_change,
                        "label": ad.label,
                        "index": ad.index,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::json!({
            "primary_address": w.address(),
            "accounts": accounts,
        })
    }

    fn api_new_account(body: &str) -> serde_json::Value {
        let v: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return serde_json::json!({"error": "invalid json"}),
        };
        let label = extract_str(&v, "label").unwrap_or("Account").to_string();
        if label.len() > 64 {
            return serde_json::json!({"error": "label too long"});
        }

        let mut g = lock_recover(&WALLET);
        let w = match g.as_mut() {
            Some(w) => w,
            None => return serde_json::json!({"error": "wallet locked"}),
        };

        // Pick the next unused account index.
        let next_idx = w
            .accounts()
            .iter()
            .map(|a| a.index)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        let account = match w.add_account(next_idx, &label) {
            Ok(a) => a,
            Err(e) => return serde_json::json!({"error": format!("add_account: {}", e)}),
        };

        // Persist wallet state (best effort). Use the network inferred
        // from the unlocked wallet's address to avoid env-var races.
        let network = detect_network_from_address(&w.address());
        if let Ok(db) = WalletDB::new(&super::wallet_db_path_for(&network)) {
            let _ = db.save_wallet(w);
        }

        let address = account
            .addresses
            .first()
            .map(|a| a.address.clone())
            .unwrap_or_default();
        serde_json::json!({
            "status": "created",
            "index": account.index,
            "label": account.label,
            "address": address,
        })
    }

    fn api_new_stealth(body: &str) -> serde_json::Value {
        // Stealth addresses are derived from a base address (the user's
        // primary). They're one-time, never stored — each call produces a
        // fresh one.
        let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        let explicit_base = extract_str(&v, "base_address");

        let base = if let Some(b) = explicit_base {
            b.to_string()
        } else {
            let g = lock_recover(&WALLET);
            match g.as_ref() {
                Some(w) => w.address(),
                None => {
                    return serde_json::json!({
                        "error": "wallet locked and no base_address provided"
                    })
                }
            }
        };

        if base.is_empty() || base.len() > MAX_ADDR_BYTES {
            return serde_json::json!({"error": "invalid base address"});
        }

        let network = detect_network_from_address(&base);
        let stealth = StealthAddress::generate_for_network(&base, &network);

        serde_json::json!({
            "status": "generated",
            "base_address": base,
            "stealth_address": stealth,
            "note": "Each call produces a new one-time address; share this instead of your real one.",
        })
    }

    // ── HTTP helpers ──
    fn send_json(stream: &mut TcpStream, data: &serde_json::Value) {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        send_response(stream, 200, "application/json", body.as_bytes());
    }

    /// Like send_json, but adds aggressive cache / privacy headers —
    /// used for sensitive responses (mnemonic, unlock, create) so the
    /// webview / any intermediary never caches them.
    fn send_json_nostore(stream: &mut TcpStream, data: &serde_json::Value) {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        send_response_with_headers(
            stream,
            200,
            "application/json",
            body.as_bytes(),
            "Cache-Control: no-store, no-cache, must-revalidate, private\r\nPragma: no-cache\r\nExpires: 0\r\n",
        );
    }

    fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        send_response_with_headers(stream, status, content_type, body, "");
    }

    fn send_response_with_headers(
        stream: &mut TcpStream,
        status: u16,
        content_type: &str,
        body: &[u8],
        extra_headers: &str,
    ) {
        let status_text = match status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            410 => "Gone",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            431 => "Request Header Fields Too Large",
            _ => "OK",
        };
        // Security response headers: deny framing, no sniffing, no referrer.
        // CSP restricts scripts/forms to the same origin, mitigating XSS if
        // anything slips past sanitize_display.
        let response = format!(
            "HTTP/1.1 {status} {status_text}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {len}\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Frame-Options: DENY\r\n\
             Referrer-Policy: no-referrer\r\n\
             Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'\r\n\
             {extra}\
             Connection: close\r\n\
             \r\n",
            status = status,
            status_text = status_text,
            content_type = content_type,
            len = body.len(),
            extra = extra_headers,
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }
}
