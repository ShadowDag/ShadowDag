// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Precompiled contracts — built-in operations callable by address.
// These run native code instead of bytecode, enabling efficient crypto
// operations that would be too expensive in the VM.
//
// Address range: 0x01 – 0x0F (reserved for precompiles)
// ═══════════════════════════════════════════════════════════════════════════

pub mod precompile_registry;
pub mod crypto_precompiles;
pub mod hash_precompiles;
pub mod math_precompiles;
