# ShadowDAG WASM / JavaScript SDK

Portable wallet primitives for **browsers, Node.js, and dApps** — the same role
Kaspa's WASM SDK plays for its ecosystem. It compiles the chain's address
derivation to WebAssembly so a web wallet, browser extension, or dApp can create
accounts and addresses **without running a full node**.

This is a **standalone crate** that deliberately avoids the node's native
dependencies (RocksDB, tokio) so it can target `wasm32-unknown-unknown`. It
re-implements the chain's exact derivation chain and is verified against
reference vectors from the main crate — addresses generated here are
**byte-identical** to `shadowdag-wallet`.

## What it does today

**Accounts & addresses**

| Function | Purpose |
|---|---|
| `new_wallet(network)` | Generate a fresh 12-word mnemonic + its address |
| `generate_mnemonic()` | Fresh 12-word mnemonic (256-bit entropy) |
| `address_from_mnemonic(mnemonic, passphrase, network)` | Restore the primary address |
| `address_from_seed(seedHex, account, index, change, network)` | Derive a specific address |
| `address_from_public_key(pubkeyHex, network)` | Address for a raw Ed25519 public key |
| `mnemonic_to_seed_hex(mnemonic, passphrase)` | The 64-byte seed (hex) |
| `validate_address(address)` | Validate a ShadowDAG address |

**Transactions & RPC**

| Function | Purpose |
|---|---|
| `build_signed_transfer_json(inputs, outputs, fee, timestamp, anchor, privHex, pubHex, network)` | Build + Ed25519-sign a transparent transfer; returns node-ready tx JSON |
| `sendrawtransaction_body(txJson)` | Wrap a signed tx in a JSON-RPC `sendrawtransaction` body |
| `json_rpc_body(method, paramsJsonArray)` | Build any JSON-RPC 2.0 request body |

`inputs` is an array of JSON strings `'{"txid":"<hex>","index":0,"owner":"SD1..."}'`;
`outputs` an array of `'{"address":"SD1...","amount":1000}'`; `anchor` is a recent
tip hash for replay protection (`""` for none). The SDK builds + signs locally;
your JS does the `fetch` to the node's RPC (keeps the SDK dependency-light).

`network` is `"mainnet" | "testnet" | "regtest"`.

The tx hash and signature are **byte-identical** to the node — verified against a
reference vector (`tx_builder.rs::tests::wasm_sdk_tx_reference_vector`).

## Build

Install the toolchain once:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

Then build for your target:

```bash
cd wasm-sdk
wasm-pack build --target web      # browser (ES modules)
wasm-pack build --target nodejs   # Node.js (CommonJS)
wasm-pack build --target bundler  # webpack / vite
```

Output lands in `wasm-sdk/pkg/`.

## Use it — browser

```html
<script type="module">
  import init, { new_wallet, address_from_mnemonic, validate_address }
    from './pkg/shadowdag_wasm_sdk.js';

  await init();

  // Create a wallet
  const [mnemonic, address] = new_wallet('mainnet').split('\n');
  console.log('mnemonic:', mnemonic);
  console.log('address :', address);

  // Restore it later
  const restored = address_from_mnemonic(mnemonic, '', 'mainnet');
  console.log(restored === address);          // true

  console.log(validate_address(address));     // true
</script>
```

## Use it — Node.js

```js
const sdk = require('./pkg/shadowdag_wasm_sdk.js');
const [mnemonic, address] = sdk.new_wallet('mainnet').split('\n');
```

## Send a transaction (browser)

```js
import init, * as sdk from './pkg/shadowdag_wasm_sdk.js';
await init();

const inputs  = [JSON.stringify({ txid: utxoTxid, index: 0, owner: myAddress })];
const outputs = [JSON.stringify({ address: toAddress, amount: 1000n })];
const now = BigInt(Math.floor(Date.now() / 1000));

const txJson = sdk.build_signed_transfer_json(
  inputs, outputs, 10n, now, recentTipHash, privHex, pubHex, 'mainnet');

const body = sdk.sendrawtransaction_body(txJson);
const res  = await fetch('http://localhost:9332', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
});
console.log(await res.json());
```

(`u64` parameters map to JS `BigInt` — note the `n` suffixes.)

## Roadmap (next increments)

- JSON-RPC query helpers (balance / UTXO selection) — currently `json_rpc_body`
  builds the request; UTXO selection is left to the caller.
- TypeScript typings (`wasm-pack` emits a `.d.ts`; add hand-written ergonomic wrappers).
- Confidential (RingCT) address + scan + spend helpers.
- Multi-output / multi-input coin-selection helpers.

## Correctness

`cargo test` (native) runs cross-verification against vectors captured from the
main crate (`service/wallet/core/wallet.rs::tests::wasm_sdk_reference_vectors`).
If the chain's derivation ever changes, both that test and this crate's tests
fail — keeping the SDK in lockstep with the node.
