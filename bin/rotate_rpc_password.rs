// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// shadowdag-rotate-rpc-password
//
// One-shot operational tool: open the node's RocksDB, delete the
// `rpc:admin_password` key, exit. The next boot of `shadowdag-node`
// will trigger `load_or_create_admin_password` to generate a fresh
// credential and write it to the gitignored `rpc_password` file in
// the data directory.
//
// Why this exists:
// ----------------
//   The repository's history previously contained a committed
//   `rpc_password` file with a real RPC admin credential. Even
//   after the file was untracked and the history scrubbed, any
//   node booted from a snapshot of the old history kept the leaked
//   password persisted in its RocksDB at key `rpc:admin_password`,
//   and `load_or_create_admin_password` would keep returning that
//   value across restarts.
//
//   This binary lets an operator rotate the credential WITHOUT
//   wiping the entire database — i.e. without losing block state
//   and forcing a re-sync from genesis.
//
// Usage:
// ------
//   1. STOP the node first (RocksDB takes an exclusive lock):
//        sudo systemctl stop shadowdag-node
//        # or: pkill -f shadowdag-node
//
//   2. Run the rotation tool against the SAME path the daemon
//      opens. The daemon opens `<data_dir>/db`, so if the node is
//      started with `--data-dir /root/.shadowdag-mainnet`, the
//      RocksDB lives at `/root/.shadowdag-mainnet/db`:
//
//        cargo run --release --bin shadowdag-rotate-rpc-password -- \
//            --db-path /root/.shadowdag-mainnet/db
//
//      Or if you've already built the binary:
//
//        ./target/release/shadowdag-rotate-rpc-password \
//            --db-path /root/.shadowdag-mainnet/db
//
//   3. Restart the node:
//        sudo systemctl start shadowdag-node
//
//   4. The new password is at `<data_dir>/rpc_password` (the
//      gitignored file). Update any script / dashboard that
//      hard-coded the old password.
//
// Safety notes:
// -------------
//   * The tool refuses to create a DB if the path doesn't exist
//     (uses `create_if_missing(false)`), so a typo'd path can't
//     accidentally produce an empty new DB next to the real one.
//   * The tool refuses to run if the daemon still has the lock,
//     because RocksDB is exclusive — you'll get a clear error
//     telling you to stop the node first.
//   * The tool is idempotent: running it on a DB that has no
//     rpc:admin_password key (e.g. fresh install or already
//     rotated) is a no-op with a clean exit.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{Options, DB};
use std::path::PathBuf;
use std::process::ExitCode;

const KEY: &[u8] = b"rpc:admin_password";

fn print_usage() {
    eprintln!("usage: shadowdag-rotate-rpc-password --db-path <PATH>");
    eprintln!();
    eprintln!("Rotate the RPC admin password by deleting the `rpc:admin_password`");
    eprintln!("key from the node's RocksDB. The next boot of shadowdag-node will");
    eprintln!("regenerate a fresh credential and write it to <data_dir>/rpc_password.");
    eprintln!();
    eprintln!("Required:");
    eprintln!("  --db-path <PATH>    Full path to the RocksDB directory the daemon");
    eprintln!("                      opens (the parent of CURRENT / MANIFEST-* /");
    eprintln!("                      *.sst files). For a node started with");
    eprintln!("                      `--data-dir /root/.shadowdag-mainnet`, this is");
    eprintln!("                      `/root/.shadowdag-mainnet/db`.");
    eprintln!();
    eprintln!("Before running: STOP the node — RocksDB takes an exclusive lock.");
}

fn parse_args() -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut db_path: Option<PathBuf> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--db-path" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --db-path requires a value");
                    return None;
                }
                db_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-h" | "--help" => return None,
            other => {
                eprintln!("error: unknown argument '{}'", other);
                return None;
            }
        }
    }
    db_path
}

fn main() -> ExitCode {
    let db_path = match parse_args() {
        Some(p) => p,
        None => {
            print_usage();
            return ExitCode::from(2);
        }
    };

    if !db_path.exists() {
        eprintln!("error: {} does not exist", db_path.display());
        eprintln!();
        eprintln!("hint: pass the FULL path to the RocksDB directory the daemon opens.");
        eprintln!("      The daemon opens `<data_dir>/db`, so for a node started with");
        eprintln!("      --data-dir /root/.shadowdag-mainnet, the path you want is");
        eprintln!("      /root/.shadowdag-mainnet/db (with the `/db` suffix).");
        return ExitCode::from(1);
    }

    if !db_path.join("CURRENT").exists() {
        eprintln!(
            "error: {} does not look like a RocksDB directory",
            db_path.display()
        );
        eprintln!("       (no CURRENT file found inside it)");
        return ExitCode::from(1);
    }

    // Use create_if_missing(false) so a wrong --db-path can't
    // accidentally create an empty DB next to the real one.
    let mut opts = Options::default();
    opts.create_if_missing(false);

    let db = match DB::open(&opts, &db_path) {
        Ok(db) => db,
        Err(e) => {
            let msg = e.to_string();
            eprintln!(
                "error: failed to open RocksDB at {}: {}",
                db_path.display(),
                msg
            );
            if msg.to_lowercase().contains("lock") {
                eprintln!();
                eprintln!("hint: the node is still running and holds the exclusive RocksDB lock.");
                eprintln!("      Stop it first:");
                eprintln!("        sudo systemctl stop shadowdag-node");
                eprintln!("      or:");
                eprintln!("        pkill -f shadowdag-node && sleep 2");
            }
            return ExitCode::from(1);
        }
    };

    match db.get(KEY) {
        Ok(Some(existing)) => {
            // Show a masked hint of the value being deleted so the
            // operator can correlate it with their leaked password.
            // Print only the first 4 hex chars and the length —
            // never the full secret.
            let hint = match std::str::from_utf8(&existing) {
                Ok(s) if s.len() >= 4 => format!("{}... ({} bytes)", &s[..4], s.len()),
                Ok(s) => format!("({} bytes, ascii)", s.len()),
                Err(_) => format!("({} bytes, non-ascii)", existing.len()),
            };
            println!("found existing rpc:admin_password = {}", hint);
            println!("deleting...");
            if let Err(e) = db.delete(KEY) {
                eprintln!("error: failed to delete key: {}", e);
                return ExitCode::from(1);
            }
            // Force-flush so the delete lands on disk before we exit
            // — otherwise a crash between here and the daemon's next
            // boot could leave the old key in the WAL.
            if let Err(e) = db.flush() {
                eprintln!("warning: flush after delete failed: {}", e);
                eprintln!("         the delete is in the WAL but may not be in an SST yet;");
                eprintln!(
                    "         this is still safe — RocksDB will replay the WAL on next open."
                );
            }
            println!("✓ rpc:admin_password deleted from {}", db_path.display());
            println!();
            println!("next steps:");
            println!("  1. start shadowdag-node again — load_or_create_admin_password will");
            println!("     generate a fresh password and write it to:");
            if let Some(parent) = db_path.parent() {
                println!("       {}/rpc_password", parent.display());
            } else {
                println!("       <data_dir>/rpc_password");
            }
            println!("  2. update any script, dashboard, or .env that hard-coded the old password");
            println!("  3. (optional) check the security log for unauthorized RPC admin calls");
            println!("     made between when the password leaked and now");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("no rpc:admin_password key in {}", db_path.display());
            println!("(this is normal on a fresh install or after a previous rotation)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to read key: {}", e);
            ExitCode::from(1)
        }
    }
}
