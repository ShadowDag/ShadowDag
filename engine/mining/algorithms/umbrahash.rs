// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// UmbraHash — ShadowDAG's memory-hard PoW ("umbra" = the darkest part of a
// shadow). Ethash-derived (the algorithm family used by Ethereum (Ethash) and
// Ergo (Autolykos)): GPU-first, strongly ASIC-resistant, and — the crucial part
// for a 10 BPS chain — cheaply verifiable.
//
// The asymmetry: MINING needs a large dataset (GiBs) resident in VRAM, accessed
// randomly and DEPENDENTLY (each read's address depends on the previous read's
// value → memory-bandwidth/latency bound → an ASIC can't beat a GPU on commodity
// DRAM). VERIFICATION regenerates only the ~64 dataset items a given (header,
// nonce) touches, from a small cache — so a node validates a block in ~ms
// without holding the dataset. `hashimoto_light` (cache) and `hashimoto_full`
// (dataset) MUST return identical results; that equality is the whole point.
//
// NOTE: uses SHA3-256/512 (NIST, the crate-wide convention) rather than
// Ethereum's legacy Keccak, so this is Ethash-STRUCTURED but NOT Ethereum
// consensus-compatible — intentional, and fine for a new chain.
// ═══════════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256, Sha3_512};

pub const HASH_BYTES: usize = 64; // one hash unit
pub const WORD_BYTES: usize = 4; // 32-bit word
pub const DATASET_PARENTS: usize = 256; // cache reads per dataset item
pub const CACHE_ROUNDS: usize = 3; // RandMemoHash rounds
pub const ACCESSES: usize = 64; // dataset reads per hash
pub const MIX_BYTES: usize = 128; // mix width
const FNV_PRIME: u32 = 0x0100_0193;

#[inline]
fn fnv(a: u32, b: u32) -> u32 {
    a.wrapping_mul(FNV_PRIME) ^ b
}

fn sha3_512_bytes(data: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(data);
    let o = h.finalize();
    let mut r = [0u8; 64];
    r.copy_from_slice(&o);
    r
}

fn sha3_256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    let o = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&o);
    r
}

#[inline]
fn u32le(b: &[u8], word: usize) -> u32 {
    u32::from_le_bytes([b[word * 4], b[word * 4 + 1], b[word * 4 + 2], b[word * 4 + 3]])
}

#[inline]
fn put_u32le(b: &mut [u8], word: usize, v: u32) {
    b[word * 4..word * 4 + 4].copy_from_slice(&v.to_le_bytes());
}

/// Per-epoch seed: SHA3-256 chained `epoch` times over 32 zero bytes.
pub fn epoch_seed(epoch: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    for _ in 0..epoch {
        s = sha3_256_bytes(&s);
    }
    s
}

/// Build the verification cache (the small structure every node keeps).
/// `cache_size` must be a multiple of `HASH_BYTES` (64).
pub fn mkcache(cache_size: usize, seed: &[u8; 32]) -> Vec<u8> {
    assert!(cache_size.is_multiple_of(HASH_BYTES) && cache_size > 0, "bad cache size");
    let n = cache_size / HASH_BYTES;
    let mut cache: Vec<[u8; 64]> = Vec::with_capacity(n);
    cache.push(sha3_512_bytes(seed));
    for i in 1..n {
        cache.push(sha3_512_bytes(&cache[i - 1]));
    }
    // RandMemoHash: makes the cache sequentially dependent (anti-shortcut).
    for _ in 0..CACHE_ROUNDS {
        for i in 0..n {
            let v = (u32le(&cache[i], 0) as usize) % n;
            let prev = cache[(i + n - 1) % n];
            let other = cache[v];
            let mut tmp = [0u8; 64];
            for k in 0..64 {
                tmp[k] = prev[k] ^ other[k];
            }
            cache[i] = sha3_512_bytes(&tmp);
        }
    }
    let mut out = Vec::with_capacity(cache_size);
    for c in &cache {
        out.extend_from_slice(c);
    }
    out
}

/// Compute one 64-byte dataset item from the cache (256 dependent cache reads).
pub fn calc_dataset_item(cache: &[u8], i: u32) -> [u8; 64] {
    let n = cache.len() / HASH_BYTES;
    let r = HASH_BYTES / WORD_BYTES; // 16 words
    let start = (i as usize % n) * HASH_BYTES;
    let mut mix = [0u8; 64];
    mix.copy_from_slice(&cache[start..start + 64]);
    let w0 = u32le(&mix, 0) ^ i;
    put_u32le(&mut mix, 0, w0);
    mix = sha3_512_bytes(&mix);
    for j in 0..DATASET_PARENTS as u32 {
        let cache_index = (fnv(i ^ j, u32le(&mix, (j as usize) % r)) as usize) % n;
        let coff = cache_index * HASH_BYTES;
        for word in 0..r {
            let f = fnv(u32le(&mix, word), u32le(&cache[coff..], word));
            put_u32le(&mut mix, word, f);
        }
    }
    sha3_512_bytes(&mix)
}

/// Generate the FULL dataset (miner-side, once per epoch). Never called by nodes.
pub fn generate_dataset(cache: &[u8], full_size: usize) -> Vec<u8> {
    let items = full_size / HASH_BYTES;
    let mut out = vec![0u8; full_size];
    for i in 0..items {
        let item = calc_dataset_item(cache, i as u32);
        out[i * HASH_BYTES..i * HASH_BYTES + HASH_BYTES].copy_from_slice(&item);
    }
    out
}

/// Core hashimoto: returns (mix_hash, result). `lookup(index)` fetches a 64-byte
/// dataset item — from VRAM when mining, regenerated from cache when verifying.
fn hashimoto<F: FnMut(u32) -> [u8; 64]>(
    header_hash: &[u8; 32],
    nonce: u64,
    full_size: usize,
    mut lookup: F,
) -> ([u8; 32], [u8; 32]) {
    let n = (full_size / HASH_BYTES) as u32;
    let w = MIX_BYTES / WORD_BYTES; // 32 words
    let mixhashes = (MIX_BYTES / HASH_BYTES) as u32; // 2

    let mut seed_in = [0u8; 40];
    seed_in[0..32].copy_from_slice(header_hash);
    seed_in[32..40].copy_from_slice(&nonce.to_le_bytes());
    let s = sha3_512_bytes(&seed_in);

    let mut mix = [0u8; MIX_BYTES];
    mix[0..64].copy_from_slice(&s);
    mix[64..128].copy_from_slice(&s);
    let s0 = u32le(&s, 0);

    for i in 0..ACCESSES as u32 {
        let p = (fnv(i ^ s0, u32le(&mix, (i as usize) % w)) % (n / mixhashes)) * mixhashes;
        let mut newdata = [0u8; MIX_BYTES];
        for j in 0..mixhashes {
            let item = lookup(p + j);
            newdata[(j as usize) * 64..(j as usize) * 64 + 64].copy_from_slice(&item);
        }
        for word in 0..w {
            let f = fnv(u32le(&mix, word), u32le(&newdata, word));
            put_u32le(&mut mix, word, f);
        }
    }

    // Compress 32 words → 8 words (mix_hash).
    let mut cmix = [0u8; 32];
    for i in 0..8 {
        let f = fnv(
            fnv(fnv(u32le(&mix, 4 * i), u32le(&mix, 4 * i + 1)), u32le(&mix, 4 * i + 2)),
            u32le(&mix, 4 * i + 3),
        );
        put_u32le(&mut cmix, i, f);
    }

    let mut res_in = [0u8; 96];
    res_in[0..64].copy_from_slice(&s);
    res_in[64..96].copy_from_slice(&cmix);
    let result = sha3_256_bytes(&res_in);
    (cmix, result)
}

/// Cheap verification path: regenerate touched dataset items from the cache.
pub fn hashimoto_light(
    cache: &[u8],
    full_size: usize,
    header_hash: &[u8; 32],
    nonce: u64,
) -> ([u8; 32], [u8; 32]) {
    hashimoto(header_hash, nonce, full_size, |idx| calc_dataset_item(cache, idx))
}

/// Mining path: read items from the resident full dataset.
pub fn hashimoto_full(dataset: &[u8], header_hash: &[u8; 32], nonce: u64) -> ([u8; 32], [u8; 32]) {
    hashimoto(header_hash, nonce, dataset.len(), |idx| {
        let off = idx as usize * HASH_BYTES;
        let mut item = [0u8; 64];
        item.copy_from_slice(&dataset[off..off + 64]);
        item
    })
}

// ─────────────────────────── Consensus parameters ───────────────────────────
// Blocks per epoch: at 10 BPS this is ~3.5 days of dataset freshness.
pub const EPOCH_BLOCKS: u64 = 3_000_000;
// Fixed dataset size (light on cards: fits any 2GB+ GPU) and its verification
// cache. Both are multiples of MIX_BYTES(128); dataset item-count is even so the
// hashimoto `mixhashes=2` fetch never runs off the end.
// TODO(external-review): Ethash uses the largest PRIME item-count below the byte
// target to avoid cache/dataset cycles; power-of-two is functionally correct but
// a prime count is the stronger, review-blessed choice before mainnet.
pub const DATASET_BYTES: usize = 1 << 30; // 1 GiB
pub const CACHE_BYTES: usize = 16 << 20; // 16 MiB

/// The epoch a block height belongs to.
pub fn epoch_of(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

/// The UmbraHash PoW pre-image: SHA3-256 over the header fields EXCLUDING `nonce`
/// and `mix_hash`. The miner varies `nonce` over this fixed pre-image to search
/// for a `(mix_hash, result)` that meets the target. Reuses the single-source
/// header serializer (with nonce zeroed, so the pre-image is nonce-independent).
#[allow(clippy::too_many_arguments)]
pub fn header_hash(
    version: u32,
    height: u64,
    timestamp: u64,
    extra_nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
) -> [u8; 32] {
    let bytes = crate::engine::mining::algorithms::shadowhash::serialize_header_template(
        version,
        height,
        timestamp,
        extra_nonce,
        difficulty,
        merkle_root,
        parents,
    );
    sha3_256_bytes(&bytes)
}

/// Big-endian `a <= b` over 32 bytes (hash-meets-target comparison).
fn le_or_eq_be(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    true // equal
}

/// Consensus light-verification of a PoW solution. Recomputes `(mix_hash,
/// result)` from the epoch cache (cheap — no dataset needed) and requires the
/// block's committed `mix_hash` to match AND `result <= target` (big-endian).
/// This is exactly what every node runs per block.
pub fn verify_light(
    cache: &[u8],
    full_size: usize,
    header_hash: &[u8; 32],
    nonce: u64,
    mix_hash: &[u8; 32],
    target: &[u8; 32],
) -> bool {
    let (mix, result) = hashimoto_light(cache, full_size, header_hash, nonce);
    &mix == mix_hash && le_or_eq_be(&result, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small params for fast tests. full_size must be a multiple of MIX_BYTES(128).
    const CACHE_SIZE: usize = 64 * 128; // 128 items
    const FULL_SIZE: usize = 64 * 512; // 512 items (even → mixhashes ok)

    fn hh(nonce: u64) -> [u8; 32] {
        sha3_256_bytes(&nonce.to_le_bytes())
    }

    #[test]
    fn light_equals_full() {
        // THE core property: verifying from the cache must equal mining from the
        // full dataset. This is what makes cheap node verification valid.
        let cache = mkcache(CACHE_SIZE, &epoch_seed(0));
        let dataset = generate_dataset(&cache, FULL_SIZE);
        for &nonce in &[1u64, 42, 12_345, 0xdead_beef, u64::MAX] {
            let h = hh(nonce);
            let light = hashimoto_light(&cache, FULL_SIZE, &h, nonce);
            let full = hashimoto_full(&dataset, &h, nonce);
            assert_eq!(light, full, "light != full for nonce {}", nonce);
        }
    }

    #[test]
    fn deterministic() {
        let c1 = mkcache(CACHE_SIZE, &epoch_seed(1));
        let c2 = mkcache(CACHE_SIZE, &epoch_seed(1));
        assert_eq!(c1, c2, "cache generation must be deterministic");
        let h = hh(7);
        assert_eq!(
            hashimoto_light(&c1, FULL_SIZE, &h, 7),
            hashimoto_light(&c2, FULL_SIZE, &h, 7)
        );
    }

    #[test]
    fn dataset_items_are_distinct() {
        // Guard against a degenerate bug that fills the dataset with repeats
        // (which would destroy memory-hardness).
        let cache = mkcache(CACHE_SIZE, &epoch_seed(0));
        let a = calc_dataset_item(&cache, 0);
        let b = calc_dataset_item(&cache, 1);
        let c = calc_dataset_item(&cache, 1000);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn nonce_avalanche() {
        let cache = mkcache(CACHE_SIZE, &epoch_seed(0));
        let r1 = hashimoto_light(&cache, FULL_SIZE, &hh(1), 1).1;
        let r2 = hashimoto_light(&cache, FULL_SIZE, &hh(1), 2).1;
        assert_ne!(r1, r2, "adjacent nonces must give different results");
    }

    #[test]
    fn epoch_seed_advances() {
        assert_eq!(epoch_seed(0), [0u8; 32]);
        assert_ne!(epoch_seed(0), epoch_seed(1));
        assert_ne!(epoch_seed(1), epoch_seed(2));
    }

    #[test]
    fn verify_light_accepts_valid_and_rejects_tampering() {
        let cache = mkcache(CACHE_SIZE, &epoch_seed(0));
        let dataset = generate_dataset(&cache, FULL_SIZE);
        let header = hh(5);
        let nonce = 9_999u64;
        let (mix, result) = hashimoto_full(&dataset, &header, nonce);

        // target == result → result <= target holds → accept (with the real mix).
        assert!(
            verify_light(&cache, FULL_SIZE, &header, nonce, &mix, &result),
            "a valid solution must verify"
        );
        // Wrong mix_hash → reject.
        let mut bad_mix = mix;
        bad_mix[0] ^= 0xff;
        assert!(!verify_light(&cache, FULL_SIZE, &header, nonce, &bad_mix, &result));
        // Target one below the result (big-endian) → result > target → reject.
        let mut strict = result;
        for b in strict.iter_mut().rev() {
            if *b > 0 {
                *b -= 1;
                break;
            } else {
                *b = 0xff;
            }
        }
        assert!(!verify_light(&cache, FULL_SIZE, &header, nonce, &mix, &strict));
    }

    #[test]
    fn header_hash_is_deterministic_and_field_sensitive() {
        let parents = vec!["a".repeat(64)];
        let a = header_hash(2, 100, 1_700_000_000_000, 0, 4096, "mr", &parents);
        let b = header_hash(2, 100, 1_700_000_000_000, 0, 4096, "mr", &parents);
        assert_eq!(a, b, "same fields → same pre-image");
        let c = header_hash(2, 101, 1_700_000_000_000, 0, 4096, "mr", &parents);
        assert_ne!(a, c, "different height → different pre-image");
    }

    #[test]
    fn consensus_params_are_well_formed() {
        assert!(DATASET_BYTES.is_multiple_of(MIX_BYTES));
        assert!(CACHE_BYTES.is_multiple_of(HASH_BYTES));
        assert!((DATASET_BYTES / HASH_BYTES).is_multiple_of(2), "item count must be even");
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(EPOCH_BLOCKS - 1), 0);
        assert_eq!(epoch_of(EPOCH_BLOCKS), 1);
    }
}
