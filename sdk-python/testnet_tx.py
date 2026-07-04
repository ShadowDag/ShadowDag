#!/usr/bin/env python3
"""End-to-end testnet transaction driver — built on the zero-dependency SDK.

This is a thin command-line wrapper around `shadowdag_sdk` that performs a real
transfer against a running node, using only the Python standard library
(`urllib`) for HTTP. It is meant to be run on the node host, where the RPC
endpoint (default 127.0.0.1:19332) is reachable.

Commands
--------
  addr         Derive the ST1/SD1/SR1 address (and keys) from a mnemonic.
  listunspent  Show an address's spendable outpoints via the node RPC.
  send         Build, sign, and broadcast a transfer, then print the tx id.

Why mine to an SDK address (not the wallet's): the node only accepts a spend
when the UTXO owner equals `<prefix> + SHA256("ShadowDAG_Addr_v1" || pubkey)[:20]`
(see tx_validator::verify_input_ownership). `address_from_public_key` produces
exactly that string, so a coinbase mined to an SDK address is spendable by the
SDK signer. Mine to the address printed by `addr`.

Example
-------
  # 1) sender + recipient addresses (pick any two mnemonics)
  python3 testnet_tx.py addr --mnemonic "$SENDER" --network testnet
  python3 testnet_tx.py addr --mnemonic "$RECIPIENT" --network testnet

  # 2) point the miner at the sender address, mine past coinbase maturity
  #    (10 blocks on testnet), then:
  python3 testnet_tx.py send \
      --mnemonic "$SENDER" --to ST1<recipient> --amount 100000000 \
      --network testnet \
      --rpc http://127.0.0.1:19332 \
      --rpc-password "$(cat /data/rpc_password)"
"""

import argparse
import json
import sys
import time
import urllib.request

import shadowdag_sdk as sdk


def rpc_call(url, method, params, token=None, timeout=15):
    """POST a JSON-RPC request; returns the parsed `result` or raises."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            out = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        # The node returns validation rejections as HTTP 500 with a JSON error
        # body — surface that body instead of a bare "HTTP Error 500".
        raw = e.read().decode(errors="replace")
        try:
            out = json.loads(raw)
        except ValueError:
            raise RuntimeError("RPC %s HTTP %s: %s" % (method, e.code, raw.strip()))
    if isinstance(out, dict) and out.get("error"):
        raise RuntimeError("RPC %s error: %s" % (method, out["error"]))
    return out.get("result") if isinstance(out, dict) else out


def keys_from_mnemonic(mnemonic, network):
    """Mnemonic -> (private_key_hex, public_key_hex, address) at account 0/0."""
    seed = sdk.mnemonic_to_seed(mnemonic)
    sk = sdk.derive_key(seed, 0, 0, False)
    pk = sdk.ed25519_publickey(sk)
    addr = sdk.address_from_public_key(pk, network)
    return sk.hex(), pk.hex(), addr


def cmd_addr(args):
    sk_hex, pk_hex, addr = keys_from_mnemonic(args.mnemonic, args.network)
    print(json.dumps(
        {"network": args.network, "address": addr,
         "public_key": pk_hex, "private_key": sk_hex},
        indent=2))


def cmd_listunspent(args):
    res = rpc_call(args.rpc, "listunspent", [args.address])
    print(json.dumps(res, indent=2))


def cmd_send(args):
    sk_hex, pk_hex, sender = keys_from_mnemonic(args.mnemonic, args.network)
    print("sender:", sender)

    # 1) Discover spendable outpoints owned by the sender.
    res = rpc_call(args.rpc, "listunspent", [sender])
    mature = [u for u in res.get("utxos", []) if u.get("mature") and u["amount"] > 0]
    mature.sort(key=lambda u: u["amount"], reverse=True)
    if not mature:
        sys.exit("No mature spendable UTXOs for %s (spendable=%s). "
                 "Mine to this address and wait for coinbase maturity."
                 % (sender, res.get("spendable")))

    # 2) Estimate the fee from the actual canonical size. The node enforces a
    #    per-byte floor (MIN_FEE_RATE = 1.0 sat/byte) on top of the flat
    #    MIN_RELAY_FEE, so a flat 100-sat fee is rejected for a ~400-byte tx.
    #    --fee acts as a lower bound; we bump it to size + margin when needed.
    MIN_FEE_RATE = 1.0        # sat/byte (matches MempoolConfig::MIN_FEE_RATE)
    FEE_MARGIN = 50           # small cushion so we sit strictly above the floor

    def build(fee):
        need = args.amount + fee
        selected, total_in = [], 0
        for u in mature:
            selected.append(u)
            total_in += u["amount"]
            if total_in >= need:
                break
        if total_in < need:
            sys.exit("Insufficient funds: have %d, need %d (amount %d + fee %d)"
                     % (total_in, need, args.amount, fee))
        inputs = [{"txid": u["txid"], "index": u["vout"], "owner": sender}
                  for u in selected]
        outputs = [{"address": args.to, "amount": args.amount}]
        change = total_in - args.amount - fee
        if change > 0:
            outputs.append({"address": sender, "amount": change})  # change to self
        return inputs, outputs, total_in

    # First pass with the requested floor, measure the canonical size, then set
    # the fee to satisfy the per-byte rate and rebuild (size is independent of
    # the fee/change amounts, so a single re-estimate is exact).
    inputs, outputs, total_in = build(args.fee)
    ts = int(time.time() * 1000)  # unix epoch MILLISECONDS (block/tx ts are ms)
    size = len(sdk._canonical_bytes(inputs, pk_hex, outputs, args.fee, ts, None))
    fee = max(args.fee, int(size * MIN_FEE_RATE) + FEE_MARGIN)
    if fee != args.fee:
        inputs, outputs, total_in = build(fee)
        print("fee auto-sized to %d sat for a %d-byte tx (rate floor 1 sat/byte)"
              % (fee, size))

    # 3) Build + sign the transfer with the SDK (matches node tx-id/sign scheme).
    tx = sdk.build_signed_transfer(
        inputs, outputs, fee, ts, sk_hex, pk_hex, args.network)
    print("tx hash:   ", tx["hash"])
    print("inputs:    ", len(inputs), "  total_in:", total_in, "  fee:", fee)
    print("outputs:   ", outputs)

    # 4) Authenticate (write RPC requires a bearer token) and broadcast.
    token = rpc_call(args.rpc, "login",
                     [{"username": args.rpc_user, "password": args.rpc_password}])
    token = token["token"] if isinstance(token, dict) else token
    # sendrawtransaction expects params[0] to be the tx serialized as a JSON
    # STRING (the node does params[0].as_str() then serde_json::from_str), not a
    # nested JSON object.
    result = rpc_call(args.rpc, "sendrawtransaction", [json.dumps(tx)], token=token)
    print("sendrawtransaction result:")
    print(json.dumps(result, indent=2))


def main():
    p = argparse.ArgumentParser(description="ShadowDAG testnet transaction driver")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("addr", help="derive address + keys from a mnemonic")
    pa.add_argument("--mnemonic", required=True)
    pa.add_argument("--network", default="testnet",
                    choices=["mainnet", "testnet", "regtest"])
    pa.set_defaults(func=cmd_addr)

    pl = sub.add_parser("listunspent", help="list an address's spendable outpoints")
    pl.add_argument("--address", required=True)
    pl.add_argument("--rpc", default="http://127.0.0.1:19332")
    pl.set_defaults(func=cmd_listunspent)

    ps = sub.add_parser("send", help="build, sign, and broadcast a transfer")
    ps.add_argument("--mnemonic", required=True, help="sender mnemonic")
    ps.add_argument("--to", required=True, help="recipient address")
    ps.add_argument("--amount", required=True, type=int, help="amount in satoshis")
    ps.add_argument("--fee", default=100, type=int, help="fee in satoshis")
    ps.add_argument("--network", default="testnet",
                    choices=["mainnet", "testnet", "regtest"])
    ps.add_argument("--rpc", default="http://127.0.0.1:19332")
    ps.add_argument("--rpc-user", default="admin")
    ps.add_argument("--rpc-password", required=True,
                    help="RPC password (contents of the node's rpc_password file)")
    ps.set_defaults(func=cmd_send)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
