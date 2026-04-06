// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Fuzz target: canonical_bytes() round-trip consistency
// Run: cargo +nightly fuzz run fuzz_canonical_bytes

#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowdag::domain::transaction::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    // If we can deserialize a transaction, its canonical_bytes() must:
    // 1. Never panic
    // 2. Be deterministic (same tx → same bytes every time)
    if let Ok(tx) = bincode::deserialize::<Transaction>(data) {
        let bytes1 = tx.canonical_bytes();
        let bytes2 = tx.canonical_bytes();
        assert_eq!(bytes1, bytes2, "canonical_bytes() must be deterministic");
    }
});
