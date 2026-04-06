// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Domain traits — abstract interfaces that domain/ depends on.
// Implementations live in engine/, infrastructure/, or service/.
//
// This enforces the dependency rule:
//   service/ → engine/ → domain/ → (nothing)
//                 ↓
//          infrastructure/
//
// domain/ NEVER imports from engine/, service/, or infrastructure/.
// Instead, it defines traits here and receives implementations via generics.
// ═══════════════════════════════════════════════════════════════════════════

pub mod utxo_backend;
pub mod pow_checker;
pub mod content_hasher;
pub mod tx_pool;
pub mod peer_info;
pub mod fee_store;
