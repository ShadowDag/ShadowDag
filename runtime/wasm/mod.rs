// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// WASM SDK Abstraction Layer — Core types and functions that can be
// compiled to WebAssembly for use in browsers and Node.js.
//
// This module provides a clean boundary between the WASM-compatible
// code (pure computation, no I/O) and the native code (RocksDB, TCP, etc).
//
// When compiled with `--target wasm32-unknown-unknown`:
//   - All functions in this module work
//   - No filesystem, no network, no RocksDB
//   - Used for: wallet operations, tx signing, address generation, VM
//
// Usage from JavaScript:
//   import { generate_address, sign_transaction, verify_signature } from 'shadowdag-wasm';
// ═══════════════════════════════════════════════════════════════════════════

pub mod sdk;
