// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Precompile Registry — maps addresses to native implementations.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;

/// Result of a precompile execution
#[derive(Debug, Clone)]
pub struct PrecompileResult {
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub success: bool,
    pub error: Option<String>,
}

impl PrecompileResult {
    pub fn ok(output: Vec<u8>, gas_used: u64) -> Self {
        Self { output, gas_used, success: true, error: None }
    }

    pub fn err(msg: &str, gas_used: u64) -> Self {
        Self { output: vec![], gas_used, success: false, error: Some(msg.to_string()) }
    }
}

/// A precompiled contract function signature
pub type PrecompileFn = fn(input: &[u8], gas_limit: u64) -> PrecompileResult;

/// Registry of all precompiled contracts
pub struct PrecompileRegistry {
    contracts: BTreeMap<u64, PrecompileEntry>,
}

#[derive(Clone)]
pub struct PrecompileEntry {
    pub name: &'static str,
    pub address: u64,
    pub base_gas: u64,
    pub per_word_gas: u64,
    pub func: PrecompileFn,
}

impl Default for PrecompileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileRegistry {
    /// Create registry with all built-in precompiles
    pub fn new() -> Self {
        let mut contracts = BTreeMap::new();

        // 0x01: Ed25519 signature verification with address derivation.
        // WARNING: NOT standard secp256k1 ecrecover -- requires pubkey as input.
        contracts.insert(0x01, PrecompileEntry {
            name: "ed25519_verify_and_derive (not ecrecover)",
            address: 0x01,
            base_gas: 3000,
            per_word_gas: 0,
            func: super::crypto_precompiles::ecrecover,
        });

        // 0x02: SHA256 — SHA-256 hash
        contracts.insert(0x02, PrecompileEntry {
            name: "sha256",
            address: 0x02,
            base_gas: 60,
            per_word_gas: 12,
            func: super::hash_precompiles::sha256_precompile,
        });

        // 0x03: SHA-256-truncated-to-20-bytes (NOT real RIPEMD-160).
        // WARNING: Produces different output than actual RIPEMD-160.
        contracts.insert(0x03, PrecompileEntry {
            name: "ripemd160 (SHA-256 truncation, not real RIPEMD-160)",
            address: 0x03,
            base_gas: 600,
            per_word_gas: 120,
            func: super::hash_precompiles::ripemd160_precompile,
        });

        // 0x04: IDENTITY — data copy (cheapest precompile)
        contracts.insert(0x04, PrecompileEntry {
            name: "identity",
            address: 0x04,
            base_gas: 15,
            per_word_gas: 3,
            func: super::hash_precompiles::identity_precompile,
        });

        // 0x05: MODEXP -- modular exponentiation (128-bit inputs only).
        // WARNING: Limited to 16-byte (128-bit) base/exp/mod. Not suitable
        // for RSA or any big-integer operations requiring larger values.
        contracts.insert(0x05, PrecompileEntry {
            name: "modexp (128-bit limit)",
            address: 0x05,
            base_gas: 200,
            per_word_gas: 0, // Gas is computed dynamically
            func: super::math_precompiles::modexp_precompile,
        });

        // 0x06: BLAKE3 hash (ShadowDAG native).
        // WARNING: Address 0x06 was historically labeled "blake2b" but the
        // implementation has always used BLAKE3. The name is now corrected.
        contracts.insert(0x06, PrecompileEntry {
            name: "blake3",
            address: 0x06,
            base_gas: 40,
            per_word_gas: 8,
            func: super::hash_precompiles::blake3_precompile,
        });

        // 0x07: SHA3 — SHA3-256 (Keccak)
        contracts.insert(0x07, PrecompileEntry {
            name: "sha3",
            address: 0x07,
            base_gas: 50,
            per_word_gas: 10,
            func: super::hash_precompiles::sha3_precompile,
        });

        // 0x08: ED25519_VERIFY — Ed25519 signature verification (ShadowDAG native)
        contracts.insert(0x08, PrecompileEntry {
            name: "ed25519_verify",
            address: 0x08,
            base_gas: 2000,
            per_word_gas: 0,
            func: super::crypto_precompiles::ed25519_verify,
        });

        // 0x09: SHA-256 based commitment (NOT a real Pedersen commitment).
        // WARNING: No homomorphic properties. See crypto_precompiles.rs doc.
        contracts.insert(0x09, PrecompileEntry {
            name: "sha256_commitment (not Pedersen)",
            address: 0x09,
            base_gas: 5000,
            per_word_gas: 0,
            func: super::crypto_precompiles::pedersen_commit,
        });

        Self { contracts }
    }

    /// Check if an address is a precompile
    pub fn is_precompile(&self, address: u64) -> bool {
        self.contracts.contains_key(&address)
    }

    /// Execute a precompile by address.
    ///
    /// The registry enforces **both** ends of the precompile gas invariant:
    ///
    /// 1. **Floor (new):** `result.gas_used` is clamped UP to
    ///    `required_gas = base_gas + per_word_gas * words`. If a
    ///    precompile implementation under-reports gas usage — whether
    ///    by a bug or by forgetting to charge per-word — the registry
    ///    raises it to the declared schedule. This guarantees that the
    ///    published `base_gas` / `per_word_gas` figures in this
    ///    module are the ACTUAL minimum price paid per call, not just
    ///    a pre-flight check that the caller has enough gas.
    ///
    /// 2. **Ceiling (existing):** `result.gas_used` is clamped DOWN to
    ///    `gas_limit`. If a precompile over-reports gas, the caller is
    ///    never charged more than it allocated.
    ///
    /// Both clamps are applied regardless of whether the precompile
    /// reported success or failure, so that gas accounting cannot be
    /// bypassed by returning an error with zero `gas_used`.
    pub fn execute(&self, address: u64, input: &[u8], gas_limit: u64) -> PrecompileResult {
        match self.contracts.get(&address) {
            Some(entry) => {
                // Calculate gas cost from the declared schedule.
                let words = (input.len() as u64).div_ceil(32);
                let required_gas = entry
                    .base_gas
                    .saturating_add(words.saturating_mul(entry.per_word_gas));

                if gas_limit < required_gas {
                    return PrecompileResult::err("insufficient gas for precompile", gas_limit);
                }

                // Execute the precompile function.
                let mut result = (entry.func)(input, gas_limit);

                // (1) Floor: enforce that gas_used is at least the
                //     declared required_gas from the gas schedule. This
                //     catches precompile implementations that forget to
                //     charge per-word gas, or return `PrecompileResult::err`
                //     with `gas_used = 0` and thereby skip the base fee
                //     entirely. The published gas schedule in `base_gas`
                //     and `per_word_gas` is now the authoritative floor
                //     regardless of what the implementation reports.
                if result.gas_used < required_gas {
                    result.gas_used = required_gas;
                }

                // (2) Ceiling: enforce that the precompile does not
                //     report more gas than allocated. If a precompile
                //     implementation has a bug that over-reports
                //     gas_used, cap it to the gas_limit so the caller
                //     is never charged more than it allowed.
                if result.gas_used > gas_limit {
                    result.gas_used = gas_limit;
                }

                result
            }
            None => PrecompileResult::err("unknown precompile address", 0),
        }
    }

    /// Get precompile info by address
    pub fn get(&self, address: u64) -> Option<&PrecompileEntry> {
        self.contracts.get(&address)
    }

    /// List all registered precompiles
    pub fn list(&self) -> Vec<(u64, &'static str)> {
        self.contracts.iter().map(|(&addr, e)| (addr, e.name)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_all_precompiles() {
        let reg = PrecompileRegistry::new();
        assert!(reg.is_precompile(0x01)); // ecrecover
        assert!(reg.is_precompile(0x02)); // sha256
        assert!(reg.is_precompile(0x03)); // ripemd160
        assert!(reg.is_precompile(0x04)); // identity
        assert!(reg.is_precompile(0x05)); // modexp
        assert!(reg.is_precompile(0x06)); // blake3
        assert!(reg.is_precompile(0x07)); // sha3
        assert!(reg.is_precompile(0x08)); // ed25519_verify
        assert!(reg.is_precompile(0x09)); // pedersen_commit
        assert!(!reg.is_precompile(0x10)); // not a precompile
    }

    #[test]
    fn identity_precompile_works() {
        let reg = PrecompileRegistry::new();
        let input = b"hello world";
        let result = reg.execute(0x04, input, 1_000_000);
        assert!(result.success);
        assert_eq!(result.output, input.to_vec());
    }

    #[test]
    fn insufficient_gas_rejected() {
        let reg = PrecompileRegistry::new();
        let result = reg.execute(0x01, &[0u8; 128], 1); // ecrecover needs 3000
        assert!(!result.success);
    }

    // ── Gas floor enforcement (the new invariant) ────────────────────

    /// A fake precompile that deliberately UNDER-reports gas usage by
    /// returning `gas_used = 0`. Used to prove that the registry's new
    /// floor clamp catches buggy precompiles that would otherwise skip
    /// the base fee.
    fn underreporting_precompile(_input: &[u8], _gas_limit: u64) -> PrecompileResult {
        PrecompileResult::ok(vec![0xAA], 0) // ← lies about gas
    }

    /// A fake precompile that deliberately OVER-reports gas usage.
    fn overreporting_precompile(_input: &[u8], gas_limit: u64) -> PrecompileResult {
        PrecompileResult::ok(vec![0xBB], gas_limit * 10) // ← lies the other way
    }

    fn registry_with_fake(
        addr: u64,
        base_gas: u64,
        per_word_gas: u64,
        func: PrecompileFn,
    ) -> PrecompileRegistry {
        let mut reg = PrecompileRegistry::new();
        reg.contracts.insert(
            addr,
            PrecompileEntry {
                name: "fake",
                address: addr,
                base_gas,
                per_word_gas,
                func,
            },
        );
        reg
    }

    #[test]
    fn gas_floor_clamps_underreporting_precompile_to_required_gas() {
        // With a declared base_gas of 5000 and an input of 0 words, the
        // floor is exactly 5000. A precompile that returns gas_used = 0
        // must be clamped UP to 5000 so the declared gas schedule is
        // the authoritative price.
        let reg = registry_with_fake(0xFE, 5000, 100, underreporting_precompile);
        let result = reg.execute(0xFE, b"", 1_000_000);
        assert!(result.success);
        assert_eq!(
            result.gas_used, 5000,
            "under-reported gas must be clamped up to the declared base floor"
        );
    }

    #[test]
    fn gas_floor_includes_per_word_charge() {
        // Input is 65 bytes → ceil(65/32) = 3 words → required_gas
        // = base_gas(100) + per_word_gas(50)*3 = 100 + 150 = 250.
        // Fake precompile reports 0 → must be clamped to 250, not 100.
        let reg = registry_with_fake(0xFD, 100, 50, underreporting_precompile);
        let result = reg.execute(0xFD, &[0u8; 65], 10_000);
        assert!(result.success);
        assert_eq!(
            result.gas_used, 250,
            "floor must include base_gas + per_word_gas * words, not just base_gas"
        );
    }

    #[test]
    fn gas_ceiling_still_clamps_overreporting_precompile() {
        // And in the other direction, an over-reporting precompile is
        // capped at the gas_limit the caller allocated.
        let reg = registry_with_fake(0xFC, 100, 0, overreporting_precompile);
        let result = reg.execute(0xFC, b"", 5_000);
        assert!(result.success);
        assert_eq!(
            result.gas_used, 5_000,
            "over-reported gas must be clamped down to gas_limit"
        );
    }

    #[test]
    fn gas_floor_applies_even_when_limit_exactly_matches_required() {
        // Edge case: gas_limit == required_gas means the caller has
        // exactly enough gas. Under-reporting must still be floored.
        let reg = registry_with_fake(0xFB, 500, 0, underreporting_precompile);
        let result = reg.execute(0xFB, b"", 500);
        assert!(result.success);
        assert_eq!(result.gas_used, 500);
    }

    #[test]
    fn insufficient_gas_still_rejected_before_floor_applies() {
        // The floor is an accounting enforcement; the existing pre-flight
        // check still rejects calls where the CALLER didn't allocate
        // enough gas — i.e. we don't silently charge the floor if the
        // caller couldn't cover it.
        let reg = registry_with_fake(0xFA, 1000, 0, underreporting_precompile);
        let result = reg.execute(0xFA, b"", 500); // only 500, need 1000
        assert!(!result.success, "insufficient-gas path must still reject");
    }
}
