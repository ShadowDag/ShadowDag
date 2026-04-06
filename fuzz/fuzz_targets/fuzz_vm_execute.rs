// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Fuzz target: ShadowVM bytecode execution
// Run: cargo +nightly fuzz run fuzz_vm_execute

#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowdag::runtime::vm::core::vm::ShadowVM;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytecode to the VM — it must never panic or corrupt state.
    // Valid behavior: Ok(result), Err(VmError) — both acceptable.
    // Invalid behavior: panic, infinite loop, memory corruption.
    let mut vm = ShadowVM::new(1_000_000); // 1M gas limit to prevent infinite loops
    let _ = vm.execute(data);
});
