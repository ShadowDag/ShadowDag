# ShadowDAG JSON-RPC API Reference

The node exposes a **JSON-RPC 2.0** API over HTTP (hand-rolled server, no TLS).
Default port **9332**.

```
POST http://<host>:9332
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{ ... }}
```

> Method names + the auth policy below are taken directly from the dispatcher in
> `service/network/rpc/rpc_server.rs`. Read-only methods are public; state-changing
> and sensitive methods require a bearer token (see Authentication).

## Authentication

Most methods are **public** (read-only queries). The following require a bearer
token (`requires_auth`):

```
sendrawtransaction, submitblock, getblocktemplate, getwork,
deploy_contract, call_contract, verify_contract, estimate_gas,
get_logs, get_storage_at, get_contract_code, get_transaction_receipt,
get_contract_info, stop
```

`stop` additionally requires the **admin** role (`requires_admin`); a miner /
read-only token is rejected.

**Getting a token.** The node generates an admin credential on first boot and
writes it to `<data_dir>/rpc_password`. Authenticate with the `login` method to
receive a token, then send it as a header:

```
Authorization: Bearer <token>
```

Rotate the credential with the `shadowdag-rotate-rpc-password` binary (deletes the
stored password so the next boot regenerates it).

## Key methods (for wallets, exchanges, explorers)

### Chain state
- **`getblockcount`** → current height. `params: []`
- **`getbestblockhash`** → selected-tip hash. `params: []`
- **`getblock`** `[hash]` → block header + tx ids.
- **`getblockfull`** `[hash]` → full block (header + full transactions).
- **`getblockheader`** `[hash]` → header only.
- **`getblocksbyheight`** `[height]` → block(s) at a height (DAG may have several).
- **`getblockhash`** `[height]` → hash of the selected block at a height.

### Balances & UTXOs
- **`getbalance`** `[address]` → spendable balance.
- **`getbalancebyaddress`** `[address]` → balance (explorer-style).
- **`getutxobyaddress`** `[address]` → UTXOs owned by an address (for coin selection).
- **`gettxout`** `[txid, index]` → a specific unspent output.
- **`validateaddress`** `[address]` → validity + decoded metadata.

### Transactions
- **`sendrawtransaction`** `[tx]` 🔒 → submit a signed transaction (see the WASM
  SDK / `docs/AUDIT_SCOPE.md` for the tx format). Returns the txid.
- **`getrawtransaction`** `[txid]` → the transaction.
- **`gettxstatus`** `[txid]` → pending / confirmed / unknown.
- **`gettxconfirmations`** `[txid]` → confirmation count.
- **`gettxinfo`** `[txid]` → decoded transaction details.
- **`estimatefee`** / **`estimatetxfee`** `[inN, outN]` → suggested fee.

### Mining
- **`getblocktemplate`** 🔒 → template for mining a block.
- **`getwork`** 🔒 → work unit (header + target).
- **`submitblock`** `[block]` 🔒 → submit a mined block.
- **`getmininginfo`**, **`getdifficulty`**, **`getnetworkhashps`**,
  **`getcoinbasematurity`** → mining stats.

### Smart contracts (ShadowVM)
- **`deploy_contract`** `[...]` 🔒 → deploy bytecode.
- **`call_contract`** `[...]` 🔒 → call a contract (state-changing).
- **`estimate_gas`** `[...]` 🔒 → gas estimate.
- **`get_transaction_receipt`** `[txid]` 🔒 → execution receipt + logs.
- **`get_contract_code`** `[addr]` 🔒, **`get_storage_at`** `[addr, slot]` 🔒,
  **`get_logs`** `[filter]` 🔒.

### Network & node
- **`getnetworkinfo`**, **`getpeerinfo`**, **`getconnectioncount`**,
  **`getnodeinfo`**, **`getversion`**, **`gethealth`**, **`getsyncstatus`**.

🔒 = requires authentication.

## Full method list (by category)

**Blocks** — getblock, getblockfull, getblocks, getblockcount, getbestblockhash,
getblockheader, getblocksbyheight, getblockhash, getblocksize, getblocktxs,
getrawblock, getblockparents, getblockchildren, getblockrange, getblockneighbors.

**Transactions** — sendrawtransaction🔒, gettxinfo, getrawtransaction, gettxstatus,
gettxconfirmations, decodetransaction, gettxout, gettxhistory, estimatetxfee,
gettxbuilderinfo, gettxpool.

**Balances / UTXO / addresses** — getbalance, getbalancebyaddress, getutxobyaddress,
getutxoset, validateaddress, getaddressinfo, getrichlist, getaddresstypes.

**Mining** — getblocktemplate🔒, submitblock🔒, getwork🔒, getmininginfo, getminerinfo,
getmineraddress, gethashrate, getnetworkhashps, getnetworksolps, getcoinbasematurity,
getminingprofiles, getscratchpadinfo, getpowinfo, getstratuminfo, getpoolstats, getbpsinfo.

**DAG / consensus** — getdaginfo, gettips, getchain, getchaintips, getvirtualchain,
getbluework, getbluescore, getselectedparent, getanticone, getdagwidth, getdagstats,
getdagslice, getdifficulty, getconsensusparams, getcheckpoints, getfinalityinfo.

**Network / peers** — getnetworkinfo, getpeerinfo, getconnectioncount, getaddednodeinfo,
getbannedpeers, getpeerversions, getbandwidthstats, getrelayinfo, getdandelioninfo,
getdandelionstate.

**Mempool** — getmempoolinfo, gettxpool.

**Contracts / VM** — deploy_contract🔒, call_contract🔒, estimate_gas🔒,
get_transaction_receipt🔒, get_contract_code🔒, get_storage_at🔒, get_logs🔒,
verify_contract🔒, get_contract_info🔒, getcontractinfo, getvminfo, getgasprice,
getgaslimits, getcodelength, getopcodes, getprecompiles.

**Supply / emission / fees** — getemission, getmaxsupply, gethalvinginfo, getsupplyinfo,
getrewardinfo, getdevfundinfo, estimatefee, getfeeestimate, getbasefee, getfeestats.

**Privacy** — getprivacyinfo, getringsize, getconfidentialinfo, getstealthinfo.

**Wallet info** — getwalletinfo, getwalletfeatures, gethddrivation, getencryptioninfo,
getmultisiginfo.

**SPV / light** — getmerkleproof, verifymerkleproof, getspvinfo, getlightnodeinfo,
getcompactblockinfo.

**Node / system** — getnodeinfo, getversion, getapiversion, ping, uptime, getmemoryinfo,
getdebuginfo, help, gethealth, getdbstats, getstorageinfo, getsnapshotinfo,
getrecoveryinfo, getpruninginfo, getsyncstatus, getmetrics, getprometheusurl,
getcapabilities, getprotocolinfo, getsecurityinfo, getperformanceinfo, getchangelog,
getrpcmethods, getfeatures, getconsolidationinfo.

**Feature info** — getswapinfo, getswapchainsupport, gethardwarewalletinfo, gettokeninfo,
getdexinfo, getorderbookinfo, gettradingpairs, getpostquantuminfo, getwasminfo.

**Admin** — stop🔒 (admin only).

> `getrpcmethods` returns the live method list from a running node; `help [method]`
> returns usage for a method. Treat those as the authoritative runtime source.
