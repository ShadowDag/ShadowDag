# ShadowDAG Python SDK

Portable wallet primitives for **backends, exchanges, and scripts** — the Python
counterpart to the WASM/JS SDK. **Zero third-party dependencies** (pure standard
library + a self-contained RFC 8032 Ed25519), so it runs anywhere Python 3.8+ does.

Addresses, mnemonics, seeds, and signatures are **byte-identical** to
`shadowdag-wallet` — verified against reference vectors from the main crate
(run the self-test: `python shadowdag_sdk.py`).

## Install

Copy `shadowdag_sdk.py` into your project (no `pip install` needed):

```python
import shadowdag_sdk as sdk
```

## Accounts & addresses

```python
mnemonic = sdk.entropy_to_mnemonic(__import__("os").urandom(32))   # new 12-word mnemonic
address  = sdk.address_from_mnemonic(mnemonic, "", "mainnet")
print(mnemonic, address)

assert sdk.validate_address(address)
```

Lower-level:

```python
seed   = sdk.mnemonic_to_seed(mnemonic)             # 64 bytes
sk     = sdk.derive_key(seed, account=0, index=0, change=False)  # 32-byte Ed25519 key
pubkey = sdk.ed25519_publickey(sk)
addr   = sdk.address_from_public_key(pubkey, "mainnet")
```

## Build, sign & send a transfer

```python
import json, urllib.request, shadowdag_sdk as sdk

priv = sk.hex(); pub = pubkey.hex()
tx = sdk.build_signed_transfer(
    inputs=[{"txid": utxo_txid, "index": 0, "owner": addr}],
    outputs=[{"address": to_addr, "amount": 1000}],
    fee=10, timestamp=int(__import__("time").time()),
    private_key_hex=priv, public_key_hex=pub, network="mainnet",
    anchor=recent_tip_hash,   # optional replay protection; omit/None for none
)

body = json.dumps(sdk.sendrawtransaction_body(tx)).encode()
req  = urllib.request.Request("http://localhost:9332", body,
                              {"Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req)))
```

## Notes

- The bundled Ed25519 is the readable RFC 8032 reference — correct but not fast.
  For high signing throughput, swap `ed25519_publickey`/`ed25519_sign` for
  `cryptography`'s `Ed25519PrivateKey` (same RFC 8032 result).
- Confidential (RingCT) sends are not yet in the SDK (transparent transfers only),
  matching the WASM SDK's current scope.

## Correctness

`python shadowdag_sdk.py` runs the reference-vector self-test (address from pubkey,
seed derivation, full mnemonic path, and a full transaction hash + signature). All
vectors are pinned from the Rust tests `wallet.rs::wasm_sdk_reference_vectors` and
`tx_builder.rs::wasm_sdk_tx_reference_vector`.
