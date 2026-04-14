// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Math precompiles — modular exponentiation, big integer operations.
// ═══════════════════════════════════════════════════════════════════════════

use super::precompile_registry::PrecompileResult;

/// Maximum allowed input size for modexp (prevent DoS)
const MAX_MODEXP_INPUT: usize = 1024;

/// 0x05: MODEXP -- modular exponentiation: base^exp mod modulus.
///
/// **WARNING: Inputs are limited to 128-bit (16 bytes) each.** The internal
/// arithmetic uses Rust `u128`, so base, exponent, and modulus must each fit
/// in 16 bytes or fewer. Inputs larger than 16 bytes are rejected with an
/// error. This makes this precompile unsuitable for RSA signature verification
/// (which needs 2048+ bit moduli) or any big-integer modular arithmetic beyond
/// 128 bits.
///
/// # TODO
/// Replace `u128` arithmetic with a proper big-integer library (e.g. `num-bigint`
/// or `crypto-bigint`) to support arbitrary-precision modexp as required by
/// EIP-198.
///
/// Input format:
///   [0..8]    base_len (u64 LE)
///   [8..16]   exp_len  (u64 LE)
///   [16..24]  mod_len  (u64 LE)
///   [24..]    base || exp || modulus (big-endian bytes)
///
/// Output: result as big-endian bytes (same length as modulus)
pub fn modexp_precompile(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if input.len() < 24 {
        return PrecompileResult::err("modexp: input too short (need 24+ bytes)", 200);
    }

    // Parse lengths
    let base_len = u64::from_le_bytes(input[0..8].try_into().unwrap_or([0u8; 8])) as usize;
    let exp_len = u64::from_le_bytes(input[8..16].try_into().unwrap_or([0u8; 8])) as usize;
    let mod_len = u64::from_le_bytes(input[16..24].try_into().unwrap_or([0u8; 8])) as usize;

    // Safety: prevent absurdly large inputs
    if base_len > MAX_MODEXP_INPUT || exp_len > MAX_MODEXP_INPUT || mod_len > MAX_MODEXP_INPUT {
        return PrecompileResult::err("modexp: input too large (max 1024 bytes each)", 200);
    }

    let total_data_len = base_len + exp_len + mod_len;
    if input.len() < 24 + total_data_len {
        return PrecompileResult::err("modexp: input data shorter than declared lengths", 200);
    }

    // Extract big-endian byte arrays
    let base_bytes = &input[24..24 + base_len];
    let exp_bytes = &input[24 + base_len..24 + base_len + exp_len];
    let mod_bytes = &input[24 + base_len + exp_len..24 + total_data_len];

    // Gas calculation: proportional to the size of the inputs
    let max_len = base_len.max(mod_len) as u64;
    let exp_bits = count_significant_bits(exp_bytes);
    let gas_cost = modexp_gas(max_len, exp_bits);

    if gas_limit < gas_cost {
        return PrecompileResult::err("modexp: insufficient gas", gas_cost);
    }

    // Reject inputs that exceed 128-bit (16 bytes) — bytes_to_u128 silently
    // truncates larger values which would produce incorrect results.
    if base_len > 16 || exp_len > 16 || mod_len > 16 {
        return PrecompileResult {
            output: vec![],
            gas_used: gas_cost,
            success: false,
            error: Some(
                "modexp inputs limited to 128-bit (16 bytes); use U256 ops for larger values"
                    .into(),
            ),
        };
    }

    // Convert to u128 for basic modexp (handles up to 16-byte values)
    if mod_len == 0 {
        return PrecompileResult::ok(vec![0u8; mod_len.max(1)], gas_cost);
    }

    let modulus = bytes_to_u128(mod_bytes);
    if modulus == 0 {
        return PrecompileResult::ok(vec![0u8; mod_len], gas_cost);
    }

    let base = bytes_to_u128(base_bytes) % modulus;
    let exp = bytes_to_u128(exp_bytes);

    let result = mod_pow(base, exp, modulus);

    // Convert result back to big-endian bytes
    let result_bytes = u128_to_bytes(result, mod_len);

    PrecompileResult::ok(result_bytes, gas_cost)
}

/// Modular exponentiation: base^exp mod modulus
fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 {
        return 0;
    }

    let mut result: u128 = 1;
    base %= modulus;

    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        exp >>= 1;
        if exp > 0 {
            base = mul_mod(base, base, modulus);
        }
    }

    result
}

/// Modular multiplication avoiding overflow
fn mul_mod(a: u128, b: u128, modulus: u128) -> u128 {
    // For small enough values, direct multiplication works
    if a < (1u128 << 64) && b < (1u128 << 64) {
        (a * b) % modulus
    } else {
        // Use Russian peasant multiplication to avoid overflow
        let mut result: u128 = 0;
        let mut a = a % modulus;
        let mut b = b % modulus;

        while b > 0 {
            if b & 1 == 1 {
                result = (result + a) % modulus;
            }
            a = (a + a) % modulus;
            b >>= 1;
        }

        result
    }
}

/// Convert big-endian bytes to u128 (truncating if too large)
fn bytes_to_u128(bytes: &[u8]) -> u128 {
    let mut result: u128 = 0;
    for &b in bytes.iter().take(16) {
        result = (result << 8) | (b as u128);
    }
    result
}

/// Convert u128 to big-endian bytes of specified length
fn u128_to_bytes(value: u128, len: usize) -> Vec<u8> {
    let full = value.to_be_bytes();
    if len >= 16 {
        let mut result = vec![0u8; len - 16];
        result.extend_from_slice(&full);
        result
    } else {
        full[16 - len..].to_vec()
    }
}

/// Count significant bits in big-endian bytes
fn count_significant_bits(bytes: &[u8]) -> u64 {
    for (i, &b) in bytes.iter().enumerate() {
        if b != 0 {
            let remaining_bytes = (bytes.len() - i - 1) as u64;
            let bits_in_byte = 8 - b.leading_zeros() as u64;
            return remaining_bytes * 8 + bits_in_byte;
        }
    }
    0
}

/// Calculate gas cost for modexp
fn modexp_gas(max_len: u64, exp_bits: u64) -> u64 {
    let len_cost = if max_len <= 64 {
        max_len * max_len
    } else if max_len <= 1024 {
        max_len * max_len / 4 + 96 * max_len - 3072
    } else {
        max_len * max_len / 16 + 480 * max_len - 199_680
    };

    let exp_cost = exp_bits.max(1);
    let raw = len_cost.saturating_mul(exp_cost) / 3;
    raw.max(200) // Minimum 200 gas
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modexp_basic() {
        // 2^10 mod 1000 = 1024 mod 1000 = 24
        let mut input = vec![0u8; 24 + 1 + 1 + 2];
        input[0..8].copy_from_slice(&1u64.to_le_bytes()); // base_len = 1
        input[8..16].copy_from_slice(&1u64.to_le_bytes()); // exp_len = 1
        input[16..24].copy_from_slice(&2u64.to_le_bytes()); // mod_len = 2
        input[24] = 2; // base = 2
        input[25] = 10; // exp = 10
        input[26] = 0x03; // modulus = 1000 (0x03E8)
        input[27] = 0xE8;

        let result = modexp_precompile(&input, 1_000_000);
        assert!(result.success);
        let value = bytes_to_u128(&result.output);
        assert_eq!(value, 24);
    }

    #[test]
    fn modexp_zero_modulus() {
        let mut input = vec![0u8; 24 + 1 + 1 + 1];
        input[0..8].copy_from_slice(&1u64.to_le_bytes());
        input[8..16].copy_from_slice(&1u64.to_le_bytes());
        input[16..24].copy_from_slice(&1u64.to_le_bytes());
        input[24] = 5; // base
        input[25] = 3; // exp
        input[26] = 0; // modulus = 0

        let result = modexp_precompile(&input, 1_000_000);
        assert!(result.success);
        assert_eq!(result.output, vec![0]);
    }

    #[test]
    fn modexp_identity() {
        // x^1 mod m = x mod m
        let mut input = vec![0u8; 24 + 1 + 1 + 1];
        input[0..8].copy_from_slice(&1u64.to_le_bytes());
        input[8..16].copy_from_slice(&1u64.to_le_bytes());
        input[16..24].copy_from_slice(&1u64.to_le_bytes());
        input[24] = 7; // base
        input[25] = 1; // exp
        input[26] = 10; // modulus

        let result = modexp_precompile(&input, 1_000_000);
        assert!(result.success);
        assert_eq!(bytes_to_u128(&result.output), 7);
    }

    #[test]
    fn mod_pow_basic() {
        assert_eq!(mod_pow(2, 10, 1000), 24);
        assert_eq!(mod_pow(3, 4, 100), 81);
        assert_eq!(mod_pow(5, 0, 100), 1);
        assert_eq!(mod_pow(5, 1, 100), 5);
        assert_eq!(mod_pow(0, 5, 100), 0);
    }

    #[test]
    fn count_bits() {
        assert_eq!(count_significant_bits(&[0xFF]), 8);
        assert_eq!(count_significant_bits(&[0x01]), 1);
        assert_eq!(count_significant_bits(&[0x00, 0x01]), 1);
        assert_eq!(count_significant_bits(&[0x01, 0x00]), 9);
    }
}
