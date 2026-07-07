# RingCT Confidential Send — Live Testnet E2E Runbook

Acceptance oracle for the RingCT block-enforcement change (PR: *enforce RingCT
confidential sends on consensus paths*). It walks a real **A → B confidential
send** on testnet: build → mempool → mined → recipient `scan` finds the output.

This E2E is **one of two gates** before mainnet. The other is a **mandatory
external cryptographic + consensus review** — this change alters block validity
and is inflation-risk, so it must **not** be self-certified.

Testnet ports: **P2P 19333** (public), **RPC 19332** (localhost only), explorer
`18080` → container `8080`.

---

## Phase 0 — Consensus warning & no DB wipe

- **Coordinated upgrade is mandatory.** Enabling confidential txs on the
  consensus path is effectively a **hard fork**: a block containing a
  confidential tx is accepted by the new binary and rejected by the old one, so
  mixed versions **split the chain**. Upgrade **every** testnet node *before*
  broadcasting any confidential send.
- **No database wipe is required.** This is a validation-logic change only — it
  does not touch genesis, the transaction format, or block-hash computation, and
  the existing chain contains no confidential txs (they were rejected before).
  The new binary accepts the entire existing chain → clean rolling upgrade.

## Phase 1 — Deploy the fix to every testnet node (Docker)

RPC is localhost-only, so run these on each server itself.

```bash
cd /path/to/ShadowDag
git fetch origin
# Trial directly on the fix branch:
git checkout claude/ringct-blockenforce && git pull
#   (or, after the PR is merged: git checkout feature/privacy-hdwallet-docs && git pull)

cd deploy/testnet
docker compose -f docker-compose.testnet.yml up -d --build
docker logs -f shadowdag-testnet
```

Verify the node is up and advancing:

```bash
curl -s http://127.0.0.1:19332 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getnodeinfo","params":[]}'
curl -s http://127.0.0.1:19332 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getpeerinfo","params":[]}'    # peers connected?
curl -s http://127.0.0.1:19332 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'  # increasing?
```

Repeat on **every** seed node before proceeding.

> Bare-metal alternative: `sudo ./deploy.sh` then `journalctl -u shadowdag-testnet -f`.

## Phase 2 — Prepare wallets A (sender) and B (recipient)

```bash
shadowdag-wallet new testnet     # A: save seed + addresses
shadowdag-wallet new testnet     # B
shadowdag-wallet info            # on B: note its confidential (…1p) address, e.g. ST1p…
```

> Run the wallet on the node's host (RPC 19332 is localhost-only), or tunnel it:
> `ssh -L 19332:127.0.0.1:19332 user@server`.

## Phase 3 — Fund A via mining

Mine to A's transparent (ST1…) address and let the coinbase mature:

```bash
docker exec shadowdag-testnet cat /data/rpc_password    # RPC password (miner + broadcast auth)
shadowdag-miner --network=testnet --address=<A_ST1_transparent> --threads=2 --rpc=127.0.0.1:19332
```

> Or set `MINER_ADDRESS=<A_ST1>` in the compose file to mine from the built-in miner.

## Phase 4 — Bootstrap the confidential pool (decoys) via `shield`

A confidential send needs at least `MIN_RING_SIZE` (4) on-chain confidential
outputs as decoys. From wallet A, run several `shield` ops to A's own
confidential address and wait for them to be mined.

```bash
export SHADOWDAG_RPC=127.0.0.1:19332
export SHADOWDAG_RPC_PASSWORD="$(docker exec shadowdag-testnet cat /data/rpc_password)"
shadowdag-wallet info                                   # on A: its …1p address
shadowdag-wallet shield <A_…1p> 1000                    # repeat 4–8 times to seed decoys
# Confirm the confidential-output index is populated:
curl -s http://127.0.0.1:19332 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getconfidentialoutputs","params":[0,100]}'
```

## Phase 5 — Confidential send A → B (the step this change unblocks)

```bash
export SHADOWDAG_RPC=127.0.0.1:19332
export SHADOWDAG_RPC_PASSWORD="$(docker exec shadowdag-testnet cat /data/rpc_password)"
shadowdag-wallet send <B_…1p> 500        # builds hidden-amount tx, pulls decoys, broadcasts
```

- **Before the fix:** this surfaced `transaction rejected by mempool (duplicate,
  conflict, or full)` — the exact blocker removed by this change
  (`verify_signatures_for_network` rejected ring inputs).
- **Now expected:** accepted into the mempool; prints the tx hash.

## Phase 6 — Confirm + scan (the acceptance oracle)

```bash
# 1) Confirm it was mined: watch getblockcount advance + the explorer http://<host>:18080
# 2) On wallet B:
export SHADOWDAG_RPC=127.0.0.1:19332
shadowdag-wallet scan                    # detects the received confidential output
shadowdag-wallet balance                 # shows the correct hidden amount
# 3) (optional, stronger) B respends the received funds:
shadowdag-wallet send <C_…1p> 100
```

## Acceptance criteria

- [ ] Confidential send is admitted to the mempool with **no rejection**.
- [ ] It is mined into a block, and **every upgraded node accepts the block**
      (no split — `getblockcount` / tips stay in agreement across nodes).
- [ ] `scan` on B finds the output and `balance` shows the correct amount.
- [ ] (Stronger) B can respend the received output.

## Rollback

If a split or unexpected rejection appears: stop broadcasting and revert the
binary on all nodes (the same rolling upgrade in reverse). No wipe is normally
required; but if a node enters a crash-loop after an unclean shutdown, recover
with a full wipe (`/root/.shadowdag-testnet/db` for the raw script, or the
`shadowdag-testnet-data` volume for Docker).

---

**Do not treat a green E2E as mainnet clearance.** It is the functional
acceptance oracle only; the mandatory external cryptographic + consensus review
is a separate, required gate.
