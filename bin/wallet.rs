// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// shadowdag-wallet -- Wallet management CLI
//
// Usage:
//   shadowdag-wallet new                  # Create new wallet
//   shadowdag-wallet balance <address>    # Check balance
//   shadowdag-wallet send <to> <amount>   # Send SDAG
//   shadowdag-wallet info                 # Show wallet info
//   shadowdag-wallet export               # Export keys
// =============================================================================

use std::io::{self, Write};
use std::path::PathBuf;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

static UNLOCK_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

use shadowdag::service::wallet::core::wallet::{Wallet, EncryptedSeed};
use shadowdag::service::wallet::storage::wallet_db::WalletDB;
use shadowdag::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
use shadowdag::config::node::node_config::NetworkMode;
use shadowdag::domain::address::invisible_wallet::InvisibleWallet;
use shadowdag::errors::WalletError;
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

    let whole: u64 = if whole_str.is_empty() { 0 } else {
        whole_str.parse().ok()?
    };

    // Pad or truncate fractional part to exactly 8 digits
    let mut frac_padded = String::with_capacity(8);
    for (i, ch) in frac_str.chars().enumerate() {
        if i >= 8 { break; }
        if !ch.is_ascii_digit() { return None; }
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
fn wallet_db_path() -> String {
    std::env::var("SHADOWDAG_WALLET_DB")
        .unwrap_or_else(|_| default_wallet_dir().join("wallet_db").to_string_lossy().to_string())
}

/// Path to the encrypted seed file.
fn seed_path() -> PathBuf {
    let dir = std::env::var("SHADOWDAG_WALLET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_wallet_dir());
    dir.join("seed.dat")
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
    let dir = seed_path().parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    std::fs::create_dir_all(&dir).map_err(|e| WalletError::Other(format!("Cannot create dir: {}", e)))?;
    let data = bincode::serialize(enc).map_err(|e| WalletError::Other(format!("Serialize error: {}", e)))?;
    std::fs::write(seed_path(), &data).map_err(|e| WalletError::Other(format!("Write error: {}", e)))?;
    Ok(())
}

fn load_encrypted_seed() -> Result<EncryptedSeed, WalletError> {
    let data = std::fs::read(seed_path()).map_err(|e| WalletError::Other(format!("Cannot read seed file: {}", e)))?;
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

    let db = WalletDB::new(&wallet_db_path()).map_err(|e| {
        WalletError::Other(format!("cannot open wallet DB: {}", e))
    })?;

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
            // First time loading -- just save and return
            db.save_wallet(&temp)?;
            Ok(temp)
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match command {
        "new" | "create"  => cmd_new(&args),
        "balance" | "bal" => cmd_balance(&args),
        "send" | "transfer" => cmd_send(&args),
        "info"            => cmd_info(),
        "stealth"         => cmd_stealth(&args),
        "invisible"       => cmd_invisible(&args),
        "export"          => cmd_export(),
        "version" | "--version" | "-v" => println!("ShadowDAG Wallet v1.0.0"),
        "help" | "--help" | "-h" => print_help(),
        _ => print_help(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_new(args: &[String]) {
    let network = args.get(2).map(|s| s.as_str()).unwrap_or("mainnet");

    // Warn if the specified network doesn't match the SHADOWDAG_NETWORK env var
    let env_network = wallet_network();
    if network != env_network {
        eprintln!("NOTE: Creating wallet for '{}' but SHADOWDAG_NETWORK='{}'",
                  network, env_network);
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
        Ok(store) => {
            match store.get_balance(&address) {
                Ok(balance) => {
                    let sdag = balance as f64 / 100_000_000.0;
                    println!("Address : {}", address);
                    println!("Balance : {:.8} SDAG ({} sats)", sdag, balance);
                }
                Err(e) => {
                    eprintln!("Error querying balance: {}", e);
                }
            }
        }
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
            return Err(format!("Typed address hex part must be 40 characters, got {}", hex_part.len()));
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Address contains invalid hex characters".into());
        }
        return Ok(());
    }

    // Standard addresses: 2-char prefix + 74 hex (version + hash + checksum)
    if after_net.len() != 74 {
        return Err(format!("Standard address hex part must be 74 characters, got {}", after_net.len()));
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
        None => { eprintln!("Usage: shadowdag-wallet send <to_address> <amount> [fee]"); return; }
    };
    let amount_str = match args.get(3) {
        Some(s) => s.as_str(),
        None => { eprintln!("Usage: shadowdag-wallet send <to_address> <amount> [fee]"); return; }
    };
    let amount = match safe_sdag_to_sats(amount_str) {
        Some(a) => a,
        None => { eprintln!("Error: invalid amount (must be 0 < amount <= 21,000,000,000)"); return; }
    };
    let fee: u64 = args.get(4)
        .and_then(|s| safe_sdag_to_sats(s))
        .unwrap_or(1); // default 1 sat fee

    // Load and unlock wallet — signing keys are derived from the encrypted
    // seed after password authentication. Private keys never leave the wallet.
    let mut wallet = match load_and_unlock_wallet() {
        Ok(w) => w,
        Err(e) => { eprintln!("Cannot load wallet: {}", e); return; }
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
            println!("  Network    : {}", if wallet.address().starts_with("ST") { "testnet" }
                     else if wallet.address().starts_with("SR") { "regtest" } else { "mainnet" });
            println!("  Address    : {}", wallet.address());
            println!("  Accounts   : {}", wallet.accounts().len());
            for acc in wallet.accounts() {
                println!("    Account #{}: {} ({} addresses)",
                         acc.index, acc.label, acc.addresses.len());
                for addr in &acc.addresses {
                    println!("      {} {}{}", addr.address, addr.label,
                             if addr.is_change { " (change)" } else { "" });
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
    // Export the EXISTING wallet's keypair, not a freshly generated one
    match load_and_unlock_wallet() {
        Ok(wallet) => {
            let address = wallet.address();
            let pub_key = wallet.accounts().first()
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
                let comma = if i + 1 < wallet.accounts().len() { "," } else { "" };
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
    println!("  help                    Show this help");
    println!();
    println!("ENVIRONMENT:");
    println!("  SHADOWDAG_NETWORK       Network to use: mainnet, testnet, regtest (default: mainnet)");
    println!("  SHADOWDAG_WALLET_DB     Path to wallet database (default: ~/.shadowdag/wallet_db)");
    println!("  SHADOWDAG_WALLET_DIR    Path to wallet directory (default: ~/.shadowdag/)");
    println!("  SHADOWDAG_DB            Path to UTXO database (default: ~/.shadowdag/data/utxo)");
}
