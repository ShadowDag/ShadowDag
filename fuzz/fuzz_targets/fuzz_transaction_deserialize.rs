// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Fuzz target: Transaction deserialization
// Run: cargo +nightly fuzz run fuzz_transaction_deserialize

#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowdag::domain::transaction::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize arbitrary bytes as a Transaction.
    // Must never panic — only Ok or Err.
    let _ = bincode::deserialize::<Transaction>(data);

    // Also test JSON deserialization path (used in RPC)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Transaction>(s);
    }
});
