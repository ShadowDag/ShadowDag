# Memory-Hard PoW (KAWPOW-style) — Design Spec

> **Status:** design-first. **CONSENSUS-CRITICAL, HARD FORK.** Replaces ShadowHash with an Ethash/ProgPoW-class
> memory-hard proof-of-work so mining is **GPU-first and strongly ASIC-resistant**, while keeping node
> verification cheap. Requires a new header field, genesis re-mine, testnet wipe, and **mandatory external
> cryptographic + consensus review before mainnet**. NOT yet implemented.

**Goal:** move PoW from the current compute-heavy ShadowHash (SHA-256 dominated, ~256KB scratchpad, weak ASIC
resistance) to a **memory-bandwidth-bound** algorithm where the bottleneck is large random VRAM access — a resource
an ASIC cannot cheaply beat a GPU on. Model: **Ethash** (the dataset/cache asymmetry that makes verification cheap)
plus the **ProgPoW** random-math layer (= **KAWPOW**, as shipped by Ravencoin) for maximal ASIC resistance.

**Honest ceiling (state up front):** no PoW is ASIC-proof forever. KAWPOW's realistic ASIC advantage is ~1.1–1.3×
(vs ~2× for plain Ethash, and large for the current hash). GPUs stay first-class; ASICs become uneconomical for a
long time. This is NOT and cannot be PoS-level low power — it is real mining, but memory-bound mining runs the GPU
**core** cooler and is more power-efficient per hash than the current compute-bound hash (miners undervolt to
roughly half TDP). "GPU mining" and "PoS-level power" are mutually exclusive; this delivers the best of the mining side.

---

## 1. Requirements

- GPU-mineable, first-class. CPU may mine but slowly (memory-bandwidth favors GPUs).
- Strong ASIC resistance (KAWPOW-level).
- **Cheap verification**: at 10 BPS every node must verify each block in ~milliseconds WITHOUT holding the full
  dataset. This is the hard constraint that killed the current large-scratchpad idea; Ethash's cache/dataset
  asymmetry is the only known way to get large-memory mining + cheap verify.
- Deterministic and **byte-for-byte identical** between the CPU verifier and the GPU miner (the same discipline that
  made the ShadowHash GPU port correct).
- Card-friendly: fixed **1 GiB** dataset (fits any 2GB+ GPU, incl. older/cheaper cards, per the "light on cards"
  requirement). Not growing (keeps old cards viable; simpler than Ethash's growth schedule).

## 2. Core structure — the Ethash asymmetry

Per **epoch** (E blocks) derive: `seed → cache (16 MiB) → dataset (1 GiB)`.
- **Miner** generates the full 1 GiB dataset once per epoch and keeps it VRAM-resident; each hash does 64 random,
  *dependent* dataset reads (the address of read k+1 depends on the value of read k → latency-bound, unprefetchable).
- **Verifier** keeps only the 16 MiB cache and regenerates just the ~64 dataset items a given (header,nonce) touches.
  Verify ≈ 64 items × item-gen (~256 cache reads each) + a few Keccaks ≈ ms.

Parameters (initial): `DATASET_BYTES = 1 GiB`, `CACHE_BYTES = 16 MiB`, `ITEM_BYTES = 64`, `ACCESSES = 64`,
`EPOCH_BLOCKS = TBD` (target ~3–4 days of freshness at 10 BPS ⇒ ~3,000,000 blocks; final value set in the plan).

## 3. Cache generation (from the epoch seed) — Ethash mkcache

- `seed(epoch)` = `keccak256` chained `epoch` times over 32 zero bytes.
- `n = CACHE_BYTES / 64`; `cache[0] = keccak512(seed)`; `cache[i] = keccak512(cache[i-1])`.
- 3 rounds of RandMemoHash: `cache[i] = keccak512(cache[(i-1+n)%n] XOR cache[cache[i][0..4] as u32 % n])`.
- Byte-exact to the Ethash spec (reference vectors exist to pin it).

## 4. Dataset item generation (from cache) — Ethash calc_dataset_item

`item(i)`: `mix = keccak512(cache[i % n] with mix[0] ^= i)`; then for `j in 0..256`:
`p = fnv(i ^ j, mix[j % 16]) % n; mix = fnv(mix, cache[p])`; return `keccak512(mix)`. (`fnv(a,b) = (a*0x01000193) ^ b`,
per-u32 lane.) Each 64-byte item = 256 cache reads; deterministic; identical on CPU and GPU.

## 5. Hashimoto (shared by mine + verify) + ProgPoW math (KAWPOW)

- `header_hash` = `keccak256(serialize_header_no_nonce_no_mix)` — header serialized WITHOUT `nonce` and `mix_hash`.
- `seed = keccak512(header_hash || nonce_le)`; `mix` = seed replicated to the mix width (KAWPOW: 32 lanes × u32).
- Loop `ACCESSES` times: derive a dataset index from `mix`, read that item (VRAM when mining / regen-from-cache when
  verifying), `mix = fnv(mix, item)`; **and** run the ProgPoW random-math round for `prog_seed = height /
  PROGPOW_PERIOD` — a keccak-seeded sequence of GPU-friendly u32 ops (`mul_hi`, `add`, `xor`, `rotl`, `popcount`,
  `clz`) over the register file plus small L1-cache-sized random reads. The random math is what forces an ASIC to
  contain a general ALU, shrinking its edge to ~1.1×. (Phase-2; see §9.)
- `mix_hash` = `fnv_compress(mix)` → 32 bytes; `result` = `keccak256(seed || mix_hash)`.
- **Valid iff `result ≤ target`** (target = existing difficulty→target; unchanged).

## 6. Consensus data-model changes

- **BlockHeader gains `mix_hash: String` (32-byte hex)** — committed to the block, stored, gossiped, and part of
  the block identity. (Ethash-style: the header carries BOTH `nonce` and `mix_hash`.)
- `header_hash` (the PoW pre-image) EXCLUDES `nonce` and `mix_hash`; mining varies `nonce` → `mix_hash` → `result`.
- The PoW check moves from `shadow_hash_raw_full` + `meets_difficulty` to `verify_pow_light(header, nonce, mix_hash,
  target)`. All hash/PoW call sites (miner, block validator, template, genesis) switch to the new path.
- `GENESIS_VERSION` bumped again (era marker: ms-era → pow2-era); genesis re-mined under the new algorithm.
- ShadowHash stays only as a library function/tests for history; it is no longer the consensus PoW.

## 7. Verification (cheap path) — what every node runs

`verify_pow_light(header, nonce, mix_hash, target)`:
1. `epoch = height / EPOCH_BLOCKS`; ensure the node holds `cache(epoch)` (regenerate on epoch change; ~16 MiB, ~ms).
2. `(mix', result) = hashimoto_light(cache, header_hash, nonce)` — regenerates each touched dataset item from cache.
3. Require `mix' == mix_hash` AND `result ≤ target`.
Nodes NEVER build the 1 GiB dataset. Cache regen happens once per epoch; verify is 64 item-regens ≈ low ms.

## 8. GPU miner (reuse existing infra)

Reuse `gpu-opencl` feature, `OpenClMiner`, `build.rs`/vendored `OpenCL.lib`, and the Keccak already written for the
ShadowHash kernel. New kernels: (a) **dataset build** (fill 1 GiB in VRAM from the cache, once per epoch), (b)
**hashimoto search** (batch nonces against the resident dataset). Dataset stays resident across batches; rebuilt only
on epoch change. Same CPU-authoritative re-check before submit.

## 9. Rollout — phased to de-risk

- **Phase 1 — Ethash-core:** cache + dataset + hashimoto (NO ProgPoW math). A working, cheaply-verified, memory-hard
  PoW (~2× ASIC ceiling). Fully CPU↔GPU byte-exact + integrated + testnet-verified.
- **Phase 2 — KAWPOW math:** add the ProgPoW random-math layer (→ ~1.1× ASIC ceiling). Another consensus bump.
- Each phase: genesis re-mine + testnet wipe on activation. **External crypto + consensus review MANDATORY before
  mainnet** (do NOT self-certify a new PoW).

## 10. Test plan (each stage byte-exact, like the ShadowHash GPU proof)

1. Cache vectors: `cache[0], cache[1], cache[n-1]` for a fixed seed vs a reference.
2. Dataset-item vectors: `item(0), item(1), item(k)` vs reference.
3. Hashimoto vectors: `(header_hash, nonce) → (mix_hash, result)` vs reference (Ethash test vectors adapted).
4. **Light == full**: `hashimoto_light(cache,...) == hashimoto_full(dataset,...)` for random inputs.
5. **CPU == GPU**: GPU dataset-build and search byte-identical to the CPU (the acceptance oracle).
6. Epoch transition: cache/seed roll over correctly at the boundary.
7. Verify cost: measured per-block verify time < a few ms at the chosen params.
8. Miner E2E: GPU finds a nonce+mix_hash the node accepts; a mined block validates via the light path on all nodes.

## 11. Non-goals / honest caveats

- Not ASIC-proof (KAWPOW-level, ~1.1–1.3×). Not PoS-level power — it is real mining.
- 1 GiB VRAM minimum (fits the dev RTX 2060 and any 2GB+ card).
- No dataset growth in v1 (revisit only if ASICs appear).
- Does not change privacy/DAG/consensus-ordering — PoW hash only. Difficulty/retarget semantics unchanged (result ≤ target).
