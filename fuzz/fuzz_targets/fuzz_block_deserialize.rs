// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Fuzz target: Block deserialization from untrusted P2P data
// Run: cargo +nightly fuzz run fuzz_block_deserialize

#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowdag::domain::block::block::Block;
use shadowdag::domain::block::block_header::BlockHeader;

fuzz_target!(|data: &[u8]| {
    // Blocks arrive over P2P as raw bytes — deserialization must be safe.
    let _ = bincode::deserialize::<Block>(data);
    let _ = bincode::deserialize::<BlockHeader>(data);
});
