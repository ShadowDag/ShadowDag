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

| Function | Purpose |
|---|---|
| `new_wallet(network)` | Generate a fresh 12-word mnemonic + its address |
| `generate_mnemonic()` | Fresh 12-word mnemonic (256-bit entropy) |
| `address_from_mnemonic(mnemonic, passphrase, network)` | Restore the primary address |
| `address_from_seed(seedHex, account, index, change, network)` | Derive a specific address |
| `address_from_public_key(pubkeyHex, network)` | Address for a raw Ed25519 public key |
| `mnemonic_to_seed_hex(mnemonic, passphrase)` | The 64-byte seed (hex) |
| `validate_address(address)` | Validate a ShadowDAG address |

`network` is `"mainnet" | "testnet" | "regtest"`.

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

## Roadmap (next increments)

- Transaction building + Ed25519 signing (construct & sign transfers client-side).
- JSON-RPC client helpers (submit tx, query balance/UTXOs) over `fetch`.
- TypeScript typings (`wasm-pack` emits a `.d.ts`; add hand-written ergonomic wrappers).
- Confidential (RingCT) address + scan helpers.

## Correctness

`cargo test` (native) runs cross-verification against vectors captured from the
main crate (`service/wallet/core/wallet.rs::tests::wasm_sdk_reference_vectors`).
If the chain's derivation ever changes, both that test and this crate's tests
fail — keeping the SDK in lockstep with the node.
