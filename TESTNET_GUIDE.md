# ShadowDAG Testnet — Quick Start Guide

Get running in 10 minutes.

## Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- RocksDB dependencies (see README.md)

## 1. Build

```bash
git clone https://github.com/ShadowDag/ShadowDag.git
cd ShadowDag
cargo build --release
```

## 2. Start a Node

```bash
# Testnet mode
./target/release/shadowdag-node --network testnet

# Or local devnet (instant blocks, ephemeral)
./target/release/shadowdag-node --devnet
```

## 3. Get Testnet Coins

```bash
# Faucet (when available at testnet.shadowdag.org/faucet)
curl -X POST https://testnet.shadowdag.org/faucet \
  -d '{"address":"YOUR_ADDRESS"}'

# Or mine locally
./target/release/shadowdag-miner --network testnet --address YOUR_ADDRESS
```

## 4. Deploy a Contract

```bash
# Write a contract
cat > counter.sasm << 'EOF'
;; @fn increment():uint64
;; @test init
PUSH1 0
SLOAD
PUSH1 1
ADD
PUSH1 0
SSTORE
STOP
EOF

# Build
./target/release/shadowasm build counter.sasm

# Test locally
./target/release/shadowasm test counter.sasm

# Deploy via RPC
curl -X POST http://localhost:19332 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"deploy_contract",
    "params":["'$(cat counter.pkg.json | jq -r .bytecode | xxd -p -c9999)'","YOUR_ADDRESS",0,10000000],
    "id":1
  }'
```

## 5. Call a Contract

```bash
curl -X POST http://localhost:19332 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "method":"call_contract",
    "params":["SD1c_CONTRACT_ADDRESS","","YOUR_ADDRESS",0,1000000],
    "id":1
  }'
```

## 6. Check Receipt

```bash
curl -X POST http://localhost:19332 \
  -d '{"jsonrpc":"2.0","method":"get_transaction_receipt","params":["TX_HASH"],"id":1}'
```

## 7. Verify Contract

```bash
./target/release/shadowasm verify counter.pkg.json
```

## Network Info

| Parameter | Value |
|-----------|-------|
| Chain ID | 0xDA0C0002 (testnet) |
| RPC Port | 19332 |
| P2P Port | 19333 |
| Block Time | ~1 second |
| VM Version | 1 |
| Max Block Gas | 100,000,000 |

## Useful Commands

```bash
# Node status
curl -s localhost:19332 -d '{"jsonrpc":"2.0","method":"getnodeinfo","id":1}' | jq

# Block height
curl -s localhost:19332 -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}' | jq

# Contract code
curl -s localhost:19332 -d '{"jsonrpc":"2.0","method":"get_contract_code","params":["SD1c_ADDR"],"id":1}' | jq

# Storage slot
curl -s localhost:19332 -d '{"jsonrpc":"2.0","method":"get_storage_at","params":["SD1c_ADDR","0"],"id":1}' | jq
```
