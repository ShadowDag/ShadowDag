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

        // 0x01: ECRECOVER — recover public key from signature
        contracts.insert(0x01, PrecompileEntry {
            name: "ecrecover",
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

        // 0x03: RIPEMD160 — RIPEMD-160 hash
        contracts.insert(0x03, PrecompileEntry {
            name: "ripemd160",
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

        // 0x05: MODEXP — modular exponentiation (for RSA, etc.)
        contracts.insert(0x05, PrecompileEntry {
            name: "modexp",
            address: 0x05,
            base_gas: 200,
            per_word_gas: 0, // Gas is computed dynamically
            func: super::math_precompiles::modexp_precompile,
        });

        // 0x06: BLAKE2B — Blake2b-256 hash (ShadowDAG specific)
        contracts.insert(0x06, PrecompileEntry {
            name: "blake2b",
            address: 0x06,
            base_gas: 40,
            per_word_gas: 8,
            func: super::hash_precompiles::blake2b_precompile,
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

        // 0x09: PEDERSEN_COMMIT — Pedersen commitment (for privacy contracts)
        contracts.insert(0x09, PrecompileEntry {
            name: "pedersen_commit",
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

    /// Execute a precompile by address
    pub fn execute(&self, address: u64, input: &[u8], gas_limit: u64) -> PrecompileResult {
        match self.contracts.get(&address) {
            Some(entry) => {
                // Calculate gas cost
                let words = (input.len() as u64).div_ceil(32);
                let required_gas = entry.base_gas.saturating_add(words.saturating_mul(entry.per_word_gas));

                if gas_limit < required_gas {
                    return PrecompileResult::err("insufficient gas for precompile", gas_limit);
                }

                // Execute the precompile function
                (entry.func)(input, gas_limit)
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
        assert!(reg.is_precompile(0x06)); // blake2b
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
}
