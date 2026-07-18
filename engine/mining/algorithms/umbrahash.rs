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

use crate::config::node::node_config::NetworkMode;
use sha3::{Digest, Sha3_256, Sha3_512};
use std::sync::{Arc, Mutex, OnceLock};

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

// ─────────────────── mini-ProgPoW (ASIC-resistance ALU layer) ───────────────────
// Forces GPU-friendly 32-bit ALU work into the hashimoto loop. An ASIC would have
// to embed a general ALU (mul_hi/rotate/popcount/clz/…) to compute these — i.e.
// become a GPU — which removes its economic edge. The op SEQUENCE (the "program")
// is fixed per period (prog_seed = height / PROGPOW_PERIOD) so a GPU can optimize
// within a period but an ASIC cannot hard-wire it. Adds NO memory (compute only),
// so light-verify == full-mine still holds. All ops are byte-exact CPU<->GPU.

/// Blocks per "program" period. The random-math sequence changes every period.
pub const PROGPOW_PERIOD: u64 = 10;
/// Random-math ops per hashimoto access iteration (64 iters * this = total).
pub const PROGPOW_CNT_MATH: usize = 8;
const FNV_OFFSET: u32 = 0x811c_9dc5;

/// The program seed for a block height (stable within a PROGPOW_PERIOD window).
pub fn prog_seed_from_height(height: u64) -> u64 {
    height / PROGPOW_PERIOD
}

#[inline]
fn fnv1a(h: u32, d: u32) -> u32 {
    (h ^ d).wrapping_mul(FNV_PRIME)
}
// rotate_left(n) rotates by n % 32 — identical to the GPU kernel's `n & 31`
// handling, so these stay byte-exact CPU<->GPU.
#[inline]
fn rotl32(a: u32, n: u32) -> u32 {
    a.rotate_left(n)
}
#[inline]
fn rotr32(a: u32, n: u32) -> u32 {
    a.rotate_right(n)
}
#[inline]
fn mul_hi(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) >> 32) as u32
}

/// KISS99 PRNG (ProgPoW's), seeded deterministically from the program seed.
struct Kiss99 {
    z: u32,
    w: u32,
    jsr: u32,
    jcong: u32,
}
impl Kiss99 {
    fn seed(prog_seed: u64) -> Self {
        let lo = prog_seed as u32;
        let hi = (prog_seed >> 32) as u32;
        let z = fnv1a(FNV_OFFSET, lo);
        let w = fnv1a(z, hi);
        let jsr = fnv1a(w, lo);
        let jcong = fnv1a(jsr, hi);
        Kiss99 { z, w, jsr, jcong }
    }
    fn next(&mut self) -> u32 {
        self.z = 36969u32.wrapping_mul(self.z & 0xffff).wrapping_add(self.z >> 16);
        self.w = 18000u32.wrapping_mul(self.w & 0xffff).wrapping_add(self.w >> 16);
        let mwc = (self.z << 16).wrapping_add(self.w);
        self.jsr ^= self.jsr << 17;
        self.jsr ^= self.jsr >> 13;
        self.jsr ^= self.jsr << 5;
        self.jcong = 69069u32.wrapping_mul(self.jcong).wrapping_add(1_234_567);
        (mwc ^ self.jcong).wrapping_add(self.jsr)
    }
}

/// ProgPoW random-math: one of 11 GPU-friendly ALU ops selected by `sel`.
fn prog_math(a: u32, b: u32, sel: u32) -> u32 {
    match sel % 11 {
        0 => a.wrapping_add(b),
        1 => a.wrapping_mul(b),
        2 => mul_hi(a, b),
        3 => a.min(b),
        4 => rotl32(a, b),
        5 => rotr32(a, b),
        6 => a & b,
        7 => a | b,
        8 => a ^ b,
        9 => a.leading_zeros().wrapping_add(b.leading_zeros()),
        _ => a.count_ones().wrapping_add(b.count_ones()),
    }
}
/// ProgPoW merge: fold `b` into `a` by one of 4 selectors.
fn prog_merge(a: u32, b: u32, sel: u32) -> u32 {
    match sel % 4 {
        0 => a.wrapping_mul(33).wrapping_add(b),
        1 => (a ^ b).wrapping_mul(33),
        2 => rotl32(a, (sel >> 16) & 31) ^ b,
        _ => rotr32(a, (sel >> 16) & 31) ^ b,
    }
}

/// Core hashimoto: returns (mix_hash, result). `lookup(index)` fetches a 64-byte
/// dataset item — from VRAM when mining, regenerated from cache when verifying.
/// `prog_seed` selects the per-period mini-ProgPoW math program.
fn hashimoto<F: FnMut(u32) -> [u8; 64]>(
    header_hash: &[u8; 32],
    nonce: u64,
    full_size: usize,
    prog_seed: u64,
    mut lookup: F,
) -> ([u8; 32], [u8; 32]) {
    let n = (full_size / HASH_BYTES) as u32;
    let w = MIX_BYTES / WORD_BYTES; // 32 words
    let mixhashes = (MIX_BYTES / HASH_BYTES) as u32; // 2
    // mini-ProgPoW program PRNG — seeded once, advanced through all iterations so
    // the op sequence is a deterministic function of prog_seed (same per period).
    let mut rng = Kiss99::seed(prog_seed);

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
        // mini-ProgPoW: PROGPOW_CNT_MATH random-math ops on the mix lanes. Draw
        // order (src1, src2, dst, sel_math, sel_merge) MUST match the GPU kernel.
        let wu = w as u32;
        for _ in 0..PROGPOW_CNT_MATH {
            let src1 = (rng.next() % wu) as usize;
            let src2 = (rng.next() % wu) as usize;
            let dst = (rng.next() % wu) as usize;
            let sel_math = rng.next();
            let sel_merge = rng.next();
            let res = prog_math(u32le(&mix, src1), u32le(&mix, src2), sel_math);
            let merged = prog_merge(u32le(&mix, dst), res, sel_merge);
            put_u32le(&mut mix, dst, merged);
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
    prog_seed: u64,
) -> ([u8; 32], [u8; 32]) {
    hashimoto(header_hash, nonce, full_size, prog_seed, |idx| {
        calc_dataset_item(cache, idx)
    })
}

/// Mining path: read items from the resident full dataset.
pub fn hashimoto_full(
    dataset: &[u8],
    header_hash: &[u8; 32],
    nonce: u64,
    prog_seed: u64,
) -> ([u8; 32], [u8; 32]) {
    hashimoto(header_hash, nonce, dataset.len(), prog_seed, |idx| {
        let off = idx as usize * HASH_BYTES;
        let mut item = [0u8; 64];
        item.copy_from_slice(&dataset[off..off + 64]);
        item
    })
}

// ─────────────────────────── Consensus parameters ───────────────────────────
// Blocks per epoch: at 10 BPS this is ~3.5 days of dataset freshness.
pub const EPOCH_BLOCKS: u64 = 3_000_000;

// Consensus ceiling on block height for UmbraHash validation. `epoch_seed`
// chains SHA3-256 `epoch` times and `epoch = height / EPOCH_BLOCKS`, so an
// UNBOUNDED attacker-supplied height (e.g. u64::MAX ⇒ ~6.1e12 iterations) would
// force hours of hashing BEFORE any PoW/target check — a remote CPU-exhaustion
// stall. Every UmbraHash entry point rejects `height > UMBRA_MAX_HEIGHT` up
// front, capping the epoch (and thus epoch_seed) to a few-ms worst case. At
// 10 BPS this ceiling is ~3170 years of blocks, far beyond any real chain.
// This absolute ceiling is the cheap, context-free FLOOR only — at 1e12 it still
// admits epochs up to ~333k, i.e. a 333k-iteration epoch_seed plus a 16 MiB
// mkcache, per header. The tighter defense is the tip-relative bound below;
// callers holding a trusted tip height MUST use it (external audit H3).
pub const UMBRA_MAX_HEIGHT: u64 = 1_000_000_000_000; // 1e12

/// How many UmbraHash epochs beyond the known tip a header may claim before
/// cheap admission paths refuse to build its epoch cache. A legitimate header is
/// at most a block or two past the tip, so a couple of epochs is generous; beyond
/// that the height is either nonsense or so far ahead that we cannot validate it
/// anyway. Single source of truth for every tip-relative epoch bound.
pub const MAX_FUTURE_EPOCHS: u64 = 2;

/// True if `height`'s UmbraHash epoch is more than `MAX_FUTURE_EPOCHS` beyond the
/// epoch of `tip_height`. Pure, so the rule is testable without a live node.
///
/// SECURITY (external audit H3): `epoch_seed` + `mkcache` run on UNVALIDATED,
/// attacker-supplied heights on the header-only admission paths (light node, sync
/// header verify, relay orphan pool) BEFORE any PoW/target check, and only three
/// epoch caches stay resident — so alternating far epochs forces a fresh 16 MiB
/// rebuild per header. Gate that work on this bound wherever a tip is known.
pub fn epoch_out_of_bound(height: u64, tip_height: u64) -> bool {
    epoch_of(height) > epoch_of(tip_height).saturating_add(MAX_FUTURE_EPOCHS)
}
// Fixed dataset size (light on cards: fits any 2GB+ GPU) and its verification
// cache. Both are multiples of MIX_BYTES(128); dataset item-count is even so the
// hashimoto `mixhashes=2` fetch never runs off the end.
// TODO(external-review): Ethash uses the largest PRIME item-count below the byte
// target to avoid cache/dataset cycles; power-of-two is functionally correct but
// a prime count is the stronger, review-blessed choice before mainnet.
pub const DATASET_BYTES: usize = 1 << 30; // 1 GiB
pub const CACHE_BYTES: usize = 16 << 20; // 16 MiB

/// Header version at/above which a block uses UmbraHash PoW (below = ShadowHash).
/// This version-gates the hard fork so pre-fork blocks still validate.
pub const UMBRA_POW_VERSION: u32 = 3;

/// Height at/above which UmbraHash is MANDATORY (a block with a lower version is
/// rejected instead of validated by the cheap legacy ShadowHash path).
///
/// `None` = the NETWORK-AGNOSTIC default (no schedule). This is the fallback used
/// ONLY by non-authoritative / network-blind early-admission paths (orphan-pool
/// junk-filter, dead sync verifier, SPV header recompute) that do not carry a
/// `NetworkMode`. The AUTHORITATIVE consensus gate and the miner use the
/// network-aware `umbra_activation_height`/`umbra_required_at_for` below, so the
/// mainnet fork is enforced there regardless of this value. Kept `None` so those
/// blind paths preserve their current (pre-fork) behavior with zero regression.
pub const UMBRA_ACTIVATION_HEIGHT: Option<u64> = None;

/// Mainnet activates UmbraHash at height 1: genesis (height 0) is the sole legacy
/// ShadowHash block (validated by checkpoint, never competitively mined), and
/// every MINED block (height >= 1) MUST be UmbraHash. This retires ShadowHash for
/// all competitive mining, so mainnet has exactly ONE PoW cost floor and ONE
/// difficulty domain. A fresh mainnet launches directly on this rule (no genesis
/// re-mine needed).
pub const MAINNET_UMBRA_ACTIVATION_HEIGHT: Option<u64> = Some(1);

/// Per-network UmbraHash activation schedule (the single source of truth for the
/// hard fork). Testnet/Regtest stay unscheduled (`None`) so the live testnet and
/// unit tests — which mine legacy v2 blocks — are unaffected; the fork is a
/// MAINNET launch policy. If a mid-chain testnet activation is ever scheduled,
/// set Testnet here AND make the miner switch versions per-height (see bin/miner).
pub fn umbra_activation_height(network: &NetworkMode) -> Option<u64> {
    match network {
        NetworkMode::Mainnet => MAINNET_UMBRA_ACTIVATION_HEIGHT,
        NetworkMode::Testnet | NetworkMode::Regtest => None,
    }
}

/// Whether a block at `height` MUST use UmbraHash under the given schedule.
/// Pure over `activation` so the rule is testable without mutating any const.
pub fn umbra_required_at_with(height: u64, activation: Option<u64>) -> bool {
    matches!(activation, Some(a) if height >= a)
}

/// Whether a block at `height` MUST use UmbraHash under the network-agnostic
/// default (blind paths only — see `UMBRA_ACTIVATION_HEIGHT`).
pub fn umbra_required_at(height: u64) -> bool {
    umbra_required_at_with(height, UMBRA_ACTIVATION_HEIGHT)
}

/// Whether a block at `height` MUST use UmbraHash on `network`. This is the
/// AUTHORITATIVE rule: the consensus validator and the miner both gate on it, so
/// they agree on version/algorithm per block (miner<->verifier parity).
pub fn umbra_required_at_for(height: u64, network: &NetworkMode) -> bool {
    umbra_required_at_with(height, umbra_activation_height(network))
}

/// Process-wide memoized verification cache (holds the current epoch's 16 MiB
/// cache). Nodes call this per block; regenerated only when the epoch changes.
/// Generating the cache is ~hundreds of ms; verification then regenerates only
/// the ~64 touched dataset items on demand (no 1 GiB dataset needed).
/// Number of recent epoch caches kept resident. A SINGLE slot let an attacker
/// thrash the memo by alternating two epochs across a boundary, forcing a full
/// 16 MiB mkcache on every header BEFORE the PoW check (amplification DoS). A
/// small LRU keeps the current and adjacent epochs resident so honest
/// validation (and near-boundary crossings) never regenerates, and 2-epoch
/// alternation no longer evicts. Cost: MAX_EPOCH_CACHES × 16 MiB resident.
pub const MAX_EPOCH_CACHES: usize = 3;

/// LRU lookup: return the cached bytes for `epoch` and move it to
/// most-recently-used, or `None` on a miss. Held only under the brief global
/// lock — NEVER during a build. Pure over `slots` for cheap testing.
fn lru_lookup(slots: &mut Vec<(u64, Arc<Vec<u8>>)>, epoch: u64) -> Option<Arc<Vec<u8>>> {
    let pos = slots.iter().position(|(e, _)| *e == epoch)?;
    let hit = slots.remove(pos);
    let c = Arc::clone(&hit.1);
    slots.push(hit); // most-recently-used
    Some(c)
}

/// LRU store: insert `cache` for `epoch` (idempotent — a no-op if a concurrent
/// builder already stored it) and evict least-recently-used entries past
/// `max_slots`. Pure over `slots`.
fn lru_store(slots: &mut Vec<(u64, Arc<Vec<u8>>)>, epoch: u64, cache: Arc<Vec<u8>>, max_slots: usize) {
    if slots.iter().any(|(e, _)| *e == epoch) {
        return;
    }
    slots.push((epoch, cache));
    while slots.len() > max_slots {
        slots.remove(0); // evict least-recently-used
    }
}

/// Global LRU of completed epoch caches (Arc handles only).
type EpochCacheLru = OnceLock<Mutex<Vec<(u64, Arc<Vec<u8>>)>>>;
/// Global map of per-epoch build locks (single-flight coordination).
type EpochBuildLocks = OnceLock<Mutex<Vec<(u64, Arc<Mutex<()>>)>>>;

/// Distinct in-flight per-epoch build locks retained. The tip-relative orphan
/// bound (P0-C, full_node) already caps how many distinct epochs an attacker can
/// drive, so this stays small; pruning a lock only risks a rare redundant (still
/// correct) rebuild of that epoch.
const MAX_EPOCH_BUILD_LOCKS: usize = MAX_EPOCH_CACHES + 4;

/// Get-or-create the per-epoch build lock. The map lock is held only briefly and
/// is released before the returned lock is taken by the caller.
fn epoch_build_lock(epoch: u64) -> Arc<Mutex<()>> {
    static BUILDS: EpochBuildLocks = OnceLock::new();
    let map = BUILDS.get_or_init(|| Mutex::new(Vec::new()));
    let mut g = map.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((_, l)) = g.iter().find(|(e, _)| *e == epoch) {
        return Arc::clone(l);
    }
    let l = Arc::new(Mutex::new(()));
    g.push((epoch, Arc::clone(&l)));
    while g.len() > MAX_EPOCH_BUILD_LOCKS {
        g.remove(0);
    }
    l
}

/// Return the 16 MiB verification cache for `epoch`, building it on a miss.
///
/// CONCURRENCY (P0-C DoS fix): the global LRU lock is held ONLY for O(1)
/// lookups/inserts, NEVER during the heavy build (`epoch_seed` = O(epoch) SHA3 +
/// `mkcache` = 16 MiB). A per-epoch build lock single-flights same-epoch builders
/// while DIFFERENT epochs build concurrently — so one slow (or attacker-forced)
/// build cannot serialize every other thread's PoW validation behind one global
/// mutex, which was an amplification-DoS surface. The result bytes are identical
/// to the old path, so consensus is unchanged.
pub fn cache_for_epoch(epoch: u64) -> Arc<Vec<u8>> {
    static CACHE: EpochCacheLru = OnceLock::new();
    let lru = CACHE.get_or_init(|| Mutex::new(Vec::new()));

    // A hit check that holds the global LRU lock ONLY inside this closure body:
    // the guard `g` is a local, so it drops before the closure returns. This is
    // deliberately NOT an `if let lru.lock()…` scrutinee (whose temporary lives
    // until the end of the if-let) — the global lock must never span the build.
    let lookup = |ep: u64| -> Option<Arc<Vec<u8>>> {
        let mut g = lru.lock().unwrap_or_else(|p| p.into_inner());
        lru_lookup(&mut g, ep)
    };

    // 1. Fast path: LRU hit.
    if let Some(c) = lookup(epoch) {
        return c;
    }
    // 2. Miss: single-flight THIS epoch's build. Acquire only the per-epoch lock
    //    (different epochs proceed concurrently; the global lock is not held).
    let build_lock = epoch_build_lock(epoch);
    let _bg = build_lock.lock().unwrap_or_else(|p| p.into_inner());
    // 3. Re-check under the build lock: a peer builder may have just finished.
    if let Some(c) = lookup(epoch) {
        return c;
    }
    // 4. Build with ONLY this epoch's build lock held (global lock free).
    let cache = Arc::new(mkcache(CACHE_BYTES, &epoch_seed(epoch)));
    // 5. Store under a brief global lock (guard dropped at the end of the block).
    {
        let mut g = lru.lock().unwrap_or_else(|p| p.into_inner());
        lru_store(&mut g, epoch, Arc::clone(&cache), MAX_EPOCH_CACHES);
    }
    cache
}

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
    prev_state_commitment: Option<&str>,
) -> [u8; 32] {
    let bytes = crate::engine::mining::algorithms::shadowhash::serialize_header_template(
        version,
        height,
        timestamp,
        extra_nonce,
        difficulty,
        merkle_root,
        parents,
        prev_state_commitment,
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

/// Miner hot loop over a RESIDENT full dataset (fast). Searches nonces
/// `[start, start+count)` and returns the first `(nonce, mix_hash, result)`
/// whose `result <= target`. The miner sets header.nonce=nonce,
/// header.mix_hash=hex(mix), header.hash=hex(result).
#[allow(clippy::too_many_arguments)]
pub fn mine_full(
    dataset: &[u8],
    header_hash: &[u8; 32],
    target: &[u8; 32],
    prog_seed: u64,
    start: u64,
    count: u64,
) -> Option<(u64, [u8; 32], [u8; 32])> {
    for nonce in start..start.saturating_add(count) {
        let (mix, result) = hashimoto_full(dataset, header_hash, nonce, prog_seed);
        if le_or_eq_be(&result, target) {
            return Some((nonce, mix, result));
        }
    }
    None
}

/// Cache-only miner (no 1 GiB dataset): regenerates the touched items per nonce.
/// Slow — for tests, genesis, and very-low-power fallback only.
#[allow(clippy::too_many_arguments)]
pub fn mine_light(
    cache: &[u8],
    full_size: usize,
    header_hash: &[u8; 32],
    target: &[u8; 32],
    prog_seed: u64,
    start: u64,
    count: u64,
) -> Option<(u64, [u8; 32], [u8; 32])> {
    for nonce in start..start.saturating_add(count) {
        let (mix, result) = hashimoto_light(cache, full_size, header_hash, nonce, prog_seed);
        if le_or_eq_be(&result, target) {
            return Some((nonce, mix, result));
        }
    }
    None
}

/// Consensus light-verification of a PoW solution. Recomputes `(mix_hash,
/// result)` from the epoch cache (cheap — no dataset needed) and requires the
/// block's committed `mix_hash` to match AND `result <= target` (big-endian).
/// This is exactly what every node runs per block.
#[allow(clippy::too_many_arguments)]
pub fn verify_light(
    cache: &[u8],
    full_size: usize,
    header_hash: &[u8; 32],
    nonce: u64,
    prog_seed: u64,
    mix_hash: &[u8; 32],
    target: &[u8; 32],
) -> bool {
    let (mix, result) = hashimoto_light(cache, full_size, header_hash, nonce, prog_seed);
    &mix == mix_hash && le_or_eq_be(&result, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small params for fast tests. full_size must be a multiple of MIX_BYTES(128).
    const CACHE_SIZE: usize = 64 * 128; // 128 items
    const FULL_SIZE: usize = 64 * 512; // 512 items (even → mixhashes ok)

    const PS: u64 = 3; // a fixed mini-ProgPoW program seed for tests

    fn hh(nonce: u64) -> [u8; 32] {
        sha3_256_bytes(&nonce.to_le_bytes())
    }

    #[test]
    fn epoch_bound_rejects_far_heights_but_allows_near_tip() {
        // External audit H3: the absolute UMBRA_MAX_HEIGHT ceiling still admits
        // epochs up to ~333k, so cheap admission paths need a TIP-RELATIVE bound
        // before epoch_seed/mkcache. This pins that rule.
        let tip = 10 * EPOCH_BLOCKS + 5; // mid-epoch 10
        // Same epoch, next block, and the whole allowed margin: all admitted.
        assert!(!epoch_out_of_bound(tip, tip));
        assert!(!epoch_out_of_bound(tip + 1, tip));
        assert!(!epoch_out_of_bound(
            (epoch_of(tip) + MAX_FUTURE_EPOCHS) * EPOCH_BLOCKS,
            tip
        ));
        // One epoch past the margin: refused.
        assert!(epoch_out_of_bound(
            (epoch_of(tip) + MAX_FUTURE_EPOCHS + 1) * EPOCH_BLOCKS,
            tip
        ));
        // The attack shape — a height just under the absolute ceiling, which the
        // ceiling alone would happily build a 16 MiB cache for.
        assert!(epoch_out_of_bound(UMBRA_MAX_HEIGHT - 1, tip));
        // Scales with the tip: the same far height is fine once the chain is there.
        assert!(!epoch_out_of_bound(UMBRA_MAX_HEIGHT - 1, UMBRA_MAX_HEIGHT - 1));
        // Genesis-era tip must not underflow.
        assert!(!epoch_out_of_bound(0, 0));
        assert!(epoch_out_of_bound(UMBRA_MAX_HEIGHT - 1, 0));
    }

    #[test]
    fn light_equals_full() {
        // THE core property: verifying from the cache must equal mining from the
        // full dataset. This is what makes cheap node verification valid.
        let cache = mkcache(CACHE_SIZE, &epoch_seed(0));
        let dataset = generate_dataset(&cache, FULL_SIZE);
        for &nonce in &[1u64, 42, 12_345, 0xdead_beef, u64::MAX] {
            let h = hh(nonce);
            let light = hashimoto_light(&cache, FULL_SIZE, &h, nonce, PS);
            let full = hashimoto_full(&dataset, &h, nonce, PS);
            assert_eq!(light, full, "light != full for nonce {}", nonce);
        }
    }

    #[test]
    fn epoch_cache_lru_keeps_recent_and_evicts_oldest() {
        // Uses a trivial builder (no heavy mkcache) to exercise the LRU that
        // defends against the single-slot cross-epoch thrash DoS.
        use std::cell::Cell;
        let mut slots: Vec<(u64, Arc<Vec<u8>>)> = Vec::new();
        let builds = Cell::new(0u32);
        let get = |slots: &mut Vec<(u64, Arc<Vec<u8>>)>, e: u64| {
            if let Some(c) = lru_lookup(slots, e) {
                return c;
            }
            builds.set(builds.get() + 1);
            let c = Arc::new(vec![e as u8]);
            lru_store(slots, e, Arc::clone(&c), 3);
            c
        };

        let a0 = get(&mut slots, 0);
        let _b1 = get(&mut slots, 1);
        // Requesting epoch 0 again must HIT (no rebuild) even after touching 1 —
        // the exact 2-epoch alternation the single slot used to thrash.
        let a0b = get(&mut slots, 0);
        assert!(Arc::ptr_eq(&a0, &a0b), "epoch 0 must stay cached across epoch 1");
        assert_eq!(builds.get(), 2, "only epochs 0 and 1 were built");

        // Fill past capacity: with [1,0] resident (0 now MRU), add 2 then 3 →
        // capacity 3 holds {1,0,2} then evicts LRU (1) when 3 arrives.
        let _c2 = get(&mut slots, 2);
        let _d3 = get(&mut slots, 3);
        assert_eq!(builds.get(), 4);
        assert!(!slots.iter().any(|(e, _)| *e == 1), "epoch 1 must be evicted as LRU");
        assert!(slots.iter().any(|(e, _)| *e == 0), "epoch 0 (recently used) must survive");
        assert!(slots.len() <= 3, "LRU never exceeds MAX_EPOCH_CACHES");
    }

    #[test]
    fn cache_for_epoch_is_concurrent_and_consistent() {
        use std::thread;
        // P0-C: many threads hammering the SAME epoch must all return
        // byte-identical caches WITHOUT deadlocking (per-epoch single-flight;
        // the global lock is never held during mkcache), and two DIFFERENT
        // epochs must both resolve (built concurrently, not serialized).
        //
        // Use two UNIQUE epochs no other test touches so this run ALWAYS drives
        // the miss -> per-epoch-lock -> re-check -> build path (not a warm-cache
        // fast-path hit). A self-deadlock (double-locking the global mutex on one
        // thread) would hang here, so a green run proves deadlock-freedom.
        const EA: u64 = 424_242;
        const EB: u64 = 424_243;
        let epoch_for = |i: u64| if i.is_multiple_of(2) { EA } else { EB };
        let handles: Vec<_> = (0..8u64)
            .map(|i| thread::spawn(move || cache_for_epoch(epoch_for(i))))
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ea = cache_for_epoch(EA);
        let eb = cache_for_epoch(EB);
        for (i, r) in results.iter().enumerate() {
            let expected = if i.is_multiple_of(2) { &ea } else { &eb };
            assert_eq!(r.as_slice(), expected.as_slice(), "epoch {} cache mismatch", epoch_for(i as u64));
        }
        assert_ne!(ea.as_slice(), eb.as_slice(), "different epochs -> different caches");
        assert_eq!(ea.len(), CACHE_BYTES, "cache is CACHE_BYTES");
    }

    #[test]
    fn umbra_activation_floor_logic() {
        // Not scheduled → never required (inert; preserves the current opt-in
        // behavior where both algorithms are valid).
        assert!(!umbra_required_at_with(0, None));
        assert!(!umbra_required_at_with(u64::MAX, None));
        // Scheduled at height A → required at and above A, not below.
        assert!(!umbra_required_at_with(49, Some(50)));
        assert!(umbra_required_at_with(50, Some(50)));
        assert!(umbra_required_at_with(51, Some(50)));
        // The network-agnostic (blind-path) default is unscheduled.
        assert_eq!(UMBRA_ACTIVATION_HEIGHT, None);
        assert!(!umbra_required_at(u64::MAX));
    }

    #[test]
    fn umbra_activation_is_network_aware() {
        // Mainnet activates at height 1: genesis (h0) stays legacy, every mined
        // block (h>=1) MUST be UmbraHash.
        assert_eq!(umbra_activation_height(&NetworkMode::Mainnet), Some(1));
        assert!(!umbra_required_at_for(0, &NetworkMode::Mainnet), "mainnet genesis (h0) is legacy");
        assert!(umbra_required_at_for(1, &NetworkMode::Mainnet), "mainnet h1 MUST be UmbraHash");
        assert!(umbra_required_at_for(u64::MAX, &NetworkMode::Mainnet));
        // Testnet/Regtest are unscheduled → never required (live testnet + tests
        // that mine legacy v2 are unaffected).
        assert_eq!(umbra_activation_height(&NetworkMode::Testnet), None);
        assert_eq!(umbra_activation_height(&NetworkMode::Regtest), None);
        assert!(!umbra_required_at_for(1, &NetworkMode::Testnet));
        assert!(!umbra_required_at_for(u64::MAX, &NetworkMode::Testnet));
        assert!(!umbra_required_at_for(u64::MAX, &NetworkMode::Regtest));
    }

    #[test]
    fn deterministic() {
        let c1 = mkcache(CACHE_SIZE, &epoch_seed(1));
        let c2 = mkcache(CACHE_SIZE, &epoch_seed(1));
        assert_eq!(c1, c2, "cache generation must be deterministic");
        let h = hh(7);
        assert_eq!(
            hashimoto_light(&c1, FULL_SIZE, &h, 7, PS),
            hashimoto_light(&c2, FULL_SIZE, &h, 7, PS)
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
        let r1 = hashimoto_light(&cache, FULL_SIZE, &hh(1), 1, PS).1;
        let r2 = hashimoto_light(&cache, FULL_SIZE, &hh(1), 2, PS).1;
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
        let (mix, result) = hashimoto_full(&dataset, &header, nonce, PS);

        // target == result → result <= target holds → accept (with the real mix).
        assert!(
            verify_light(&cache, FULL_SIZE, &header, nonce, PS, &mix, &result),
            "a valid solution must verify"
        );
        // Wrong mix_hash → reject.
        let mut bad_mix = mix;
        bad_mix[0] ^= 0xff;
        assert!(!verify_light(&cache, FULL_SIZE, &header, nonce, PS, &bad_mix, &result));
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
        assert!(!verify_light(&cache, FULL_SIZE, &header, nonce, PS, &mix, &strict));
    }

    #[test]
    fn mine_finds_a_block_that_light_verify_accepts() {
        // Mine against the full dataset with a 1/256 target, then confirm the
        // cheap light-verify (what a node runs) accepts the mined solution —
        // proving mine (full) and verify (light) agree end-to-end.
        let cache = mkcache(CACHE_SIZE, &epoch_seed(0));
        let dataset = generate_dataset(&cache, FULL_SIZE);
        let header = hh(7);
        let mut target = [0xffu8; 32];
        target[0] = 0x00; // ~1/256

        let (nonce, mix, result) =
            mine_full(&dataset, &header, &target, PS, 0, 100_000).expect("should find a nonce");
        assert!(le_or_eq_be(&result, &target), "mined result must meet target");
        assert!(
            verify_light(&cache, FULL_SIZE, &header, nonce, PS, &mix, &target),
            "node light-verify must accept the mined (nonce, mix)"
        );
    }

    #[test]
    fn header_hash_is_deterministic_and_field_sensitive() {
        let parents = vec!["a".repeat(64)];
        let a = header_hash(2, 100, 1_700_000_000_000, 0, 4096, "mr", &parents, None);
        let b = header_hash(2, 100, 1_700_000_000_000, 0, 4096, "mr", &parents, None);
        assert_eq!(a, b, "same fields → same pre-image");
        let c = header_hash(2, 101, 1_700_000_000_000, 0, 4096, "mr", &parents, None);
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

    #[test]
    #[ignore = "CPU hashrate benchmark; run with --release -- --ignored --nocapture"]
    fn umbra_cpu_hashrate_benchmark() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::time::{Duration, Instant};

        let cache = mkcache(CACHE_BYTES, &epoch_seed(0));
        let prog_seed = prog_seed_from_height(0);
        let header = hh(0x00C0_FFEE);
        let window = Duration::from_secs(10);

        println!(
            "\n=== UmbraHash CPU hashrate benchmark (hashimoto_light, cache={} MiB, full_size={} MiB) ===",
            CACHE_BYTES >> 20,
            DATASET_BYTES >> 20
        );

        for n in 0..32u64 {
            let _ = hashimoto_light(&cache, DATASET_BYTES, &header, n, prog_seed);
        }
        let mut nonce = 1_000u64;
        let mut count1 = 0u64;
        let start = Instant::now();
        while start.elapsed() < window {
            let _ = hashimoto_light(&cache, DATASET_BYTES, &header, nonce, prog_seed);
            nonce = nonce.wrapping_add(1);
            count1 += 1;
        }
        let el1 = start.elapsed().as_secs_f64();
        let hps1 = count1 as f64 / el1;
        println!("single-thread : {:>10} hashes in {:.2}s => {:>8.1} H/s", count1, el1, hps1);

        let threads = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(4);
        let counter = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        let start = Instant::now();
        std::thread::scope(|s| {
            for t in 0..threads {
                let counter = &counter;
                let stop = &stop;
                let cache = &cache;
                let header = &header;
                s.spawn(move || {
                    let mut nonce = (t as u64).wrapping_mul(1_000_000_007).wrapping_add(1);
                    let mut local = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let _ = hashimoto_light(cache, DATASET_BYTES, header, nonce, prog_seed);
                        nonce = nonce.wrapping_add(1);
                        local += 1;
                        if local.is_multiple_of(128) {
                            counter.fetch_add(128, Ordering::Relaxed);
                            local = 0;
                        }
                    }
                    counter.fetch_add(local, Ordering::Relaxed);
                });
            }
            std::thread::sleep(window);
            stop.store(true, Ordering::Relaxed);
        });
        let el_n = start.elapsed().as_secs_f64();
        let count_n = counter.load(Ordering::Relaxed);
        let hps_n = count_n as f64 / el_n;
        println!(
            "multi-thread  : {:>10} hashes in {:.2}s => {:>8.1} H/s ({:.2} kH/s) across {} threads",
            count_n, el_n, hps_n, hps_n / 1000.0, threads
        );
        println!("=== end CPU benchmark ===\n");
    }
}
