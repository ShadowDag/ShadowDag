#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  RingCT confidential-send live E2E — automates Phases 4–6 of
#  RINGCT_CONFIDENTIAL_E2E_RUNBOOK.md:
#     Phase 4  bootstrap the confidential pool (shield -> decoys), then A scans
#     Phase 5  A -> B confidential send  (the step the fix unblocks)
#     Phase 6  B scans; assert the confidential output arrived  (acceptance oracle)
#
#  PREREQUISITES (not done by this script):
#    * The RingCT fix is deployed on EVERY testnet node (coordinated upgrade).
#    * A node is running and its RPC is reachable at $RPC (localhost only).
#    * Wallets A (sender) and B (recipient) already exist and A is FUNDED with
#      mature transparent coins (Phase 3 — mine to A's ST1… address).
#
#  Amounts are in SDAG (same unit as `shadowdag-wallet send/shield`).
#  Wallet commands return exit 0 even on soft errors, so success is detected by
#  parsing their output markers, not exit codes.
#
#  Usage:
#    RPC=127.0.0.1:19332 DOCKER_CONTAINER=shadowdag-testnet \
#    A_DIR=~/.sdag-e2e/A A_DB=~/.sdag-e2e/A/db A_PASSWORD=... \
#    B_DIR=~/.sdag-e2e/B B_DB=~/.sdag-e2e/B/db B_PASSWORD=... \
#    ./ringct_confidential_e2e.sh
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Config (override via environment) ──────────────────────────────────────
NETWORK="${NETWORK:-testnet}"
RPC="${RPC:-127.0.0.1:19332}"
WALLET_BIN="${WALLET_BIN:-shadowdag-wallet}"

# Two isolated wallets. Each needs its own DIR (seed.dat) + DB + unlock password.
A_DIR="${A_DIR:-$HOME/.sdag-e2e/A}";  A_DB="${A_DB:-$A_DIR/db}";  A_PASSWORD="${A_PASSWORD:-}"
B_DIR="${B_DIR:-$HOME/.sdag-e2e/B}";  B_DB="${B_DB:-$B_DIR/db}";  B_PASSWORD="${B_PASSWORD:-}"

# RPC write auth (broadcast). Provide ONE of these.
RPC_PASSWORD="${SHADOWDAG_RPC_PASSWORD:-}"          # explicit
RPC_PASSWORD_FILE="${RPC_PASSWORD_FILE:-}"          # read from a file
DOCKER_CONTAINER="${DOCKER_CONTAINER:-}"            # `docker exec <c> cat /data/rpc_password`

SHIELD_AMOUNT="${SHIELD_AMOUNT:-50}"   # SDAG per shield (bootstrap)
SEND_AMOUNT="${SEND_AMOUNT:-10}"       # SDAG for the A->B confidential send
DECOY_TARGET="${DECOY_TARGET:-8}"      # min confidential outputs on-chain before sending (ring floor is 4)
MAX_SHIELDS="${MAX_SHIELDS:-8}"        # cap on bootstrap shields
CONFIRM_BLOCKS="${CONFIRM_BLOCKS:-3}"  # blocks to wait for a tx to be mined
POLL_TIMEOUT="${POLL_TIMEOUT:-240}"    # seconds to wait for an on-chain change
POLL_INTERVAL="${POLL_INTERVAL:-5}"    # seconds between polls

CONF_RE='(SD1p|ST1p|SR1p)[0-9a-f]{136}'

log()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\n\033[1;31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

# ── Preflight ──────────────────────────────────────────────────────────────
command -v curl    >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found (used to parse JSON-RPC)"
command -v "$WALLET_BIN" >/dev/null || die "wallet binary not found: $WALLET_BIN (set WALLET_BIN=path)"
[ -n "$A_PASSWORD" ] || die "A_PASSWORD is empty (wallet A unlock password; min 8 chars)"
[ -n "$B_PASSWORD" ] || die "B_PASSWORD is empty (wallet B unlock password; min 8 chars)"

if [ -z "$RPC_PASSWORD" ]; then
  if   [ -n "$RPC_PASSWORD_FILE" ]; then RPC_PASSWORD="$(cat "$RPC_PASSWORD_FILE")"
  elif [ -n "$DOCKER_CONTAINER" ];  then RPC_PASSWORD="$(docker exec "$DOCKER_CONTAINER" cat /data/rpc_password)"
  else die "No RPC write password. Set SHADOWDAG_RPC_PASSWORD, RPC_PASSWORD_FILE, or DOCKER_CONTAINER."
  fi
fi
[ -n "$RPC_PASSWORD" ] || die "resolved RPC password is empty"

# ── Helpers ────────────────────────────────────────────────────────────────
# rpc METHOD PARAMS_JSON  -> prints .result as compact JSON (exits non-zero on RPC error)
rpc() {
  local method="$1" params="$2" body resp
  body=$(printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}' "$method" "$params")
  resp=$(curl -s --max-time 15 "http://$RPC" -H 'Content-Type: application/json' -d "$body") \
    || { echo "rpc: curl failed for $method" >&2; return 1; }
  RPC_RESP="$resp" python3 - "$method" <<'PY'
import os, sys, json
try:
    d = json.loads(os.environ["RPC_RESP"])
except Exception as e:
    sys.stderr.write("rpc: bad JSON from %s: %s\n" % (sys.argv[1], e)); sys.exit(2)
if d.get("error"):
    sys.stderr.write("rpc error (%s): %s\n" % (sys.argv[1], json.dumps(d["error"]))); sys.exit(3)
print(json.dumps(d.get("result")))
PY
}
json_field() { python3 -c 'import sys,json;print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

block_height() { rpc getblockcount '[]'; }
conf_total()   { rpc getconfidentialoutputs '[0,1]' | json_field total; }

# run a wallet subcommand with an isolated, non-interactive environment
run_wallet() {  # run_wallet DIR DB PASS <args...>
  local dir="$1" db="$2" pass="$3"; shift 3
  mkdir -p "$dir"
  env SHADOWDAG_NETWORK="$NETWORK" SHADOWDAG_RPC="$RPC" SHADOWDAG_RPC_PASSWORD="$RPC_PASSWORD" \
      SHADOWDAG_WALLET_DIR="$dir" SHADOWDAG_WALLET_DB="$db" SHADOWDAG_WALLET_PASSWORD="$pass" \
      "$WALLET_BIN" "$@"
}
wallet_a() { run_wallet "$A_DIR" "$A_DB" "$A_PASSWORD" "$@"; }
wallet_b() { run_wallet "$B_DIR" "$B_DB" "$B_PASSWORD" "$@"; }

conf_addr() {  # conf_addr wallet_fn  -> prints the wallet's …1p confidential address
  "$1" stealth 2>/dev/null | grep -oE "$CONF_RE" | head -1
}

# wait until `cmd` prints a value strictly greater than $1, or timeout
wait_gt() {  # wait_gt BASELINE "cmd..."
  local baseline="$1"; shift
  local deadline=$(( $(date +%s) + POLL_TIMEOUT )) cur
  while :; do
    cur="$("$@" 2>/dev/null || echo "$baseline")"
    [ "${cur:-0}" -gt "$baseline" ] 2>/dev/null && { echo "$cur"; return 0; }
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep "$POLL_INTERVAL"
  done
}

wait_height() {  # wait_height TARGET
  local target="$1" deadline=$(( $(date +%s) + POLL_TIMEOUT )) h
  while :; do
    h="$(block_height 2>/dev/null || echo 0)"
    [ "${h:-0}" -ge "$target" ] 2>/dev/null && { echo "$h"; return 0; }
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep "$POLL_INTERVAL"
  done
}

# ── Preflight RPC + wallets ────────────────────────────────────────────────
log "Preflight"
H0="$(block_height)" || die "node RPC not reachable at $RPC"
info "node RPC ok  (height=$H0, confidential outputs on-chain=$(conf_total))"

A_CONF="$(conf_addr wallet_a)"; [ -n "$A_CONF" ] || die "could not derive A's confidential address (does wallet A exist and unlock?)"
B_CONF="$(conf_addr wallet_b)"; [ -n "$B_CONF" ] || die "could not derive B's confidential address (does wallet B exist and unlock?)"
info "A …1p : $A_CONF"
info "B …1p : $B_CONF"

# ── Phase 4: bootstrap decoys, then A scans its own confidential funds ──────
log "Phase 4 — bootstrap confidential pool (target: >= $DECOY_TARGET on-chain outputs)"
cur="$(conf_total)"; n=0
while [ "$cur" -lt "$DECOY_TARGET" ] && [ "$n" -lt "$MAX_SHIELDS" ]; do
  n=$((n+1))
  info "shield #$n: $SHIELD_AMOUNT SDAG -> A (current on-chain confidential outputs: $cur)"
  out="$(wallet_a shield "$A_CONF" "$SHIELD_AMOUNT" 2>&1)" || true
  echo "$out" | grep -q "Broadcast OK" || { echo "$out"; die "shield #$n did not broadcast (is A funded with mature transparent coins?)"; }
  cur="$(wait_gt "$cur" conf_total)" || die "timed out waiting for shield #$n to be mined"
  info "  mined; confidential outputs on-chain: $cur"
done
[ "$cur" -ge "$DECOY_TARGET" ] || die "only $cur confidential outputs after $n shields (< $DECOY_TARGET). Fund A more, or lower DECOY_TARGET."

info "A scans to record its own shielded (confidential) funds…"
a_scan="$(wallet_a scan 2>&1)" || true
echo "$a_scan" | sed 's/^/      /'
a_sats="$(echo "$a_scan" | grep -oE 'Confidential balance:[^(]*\([0-9]+ sats\)' | grep -oE '[0-9]+ sats' | grep -oE '[0-9]+' | head -1 || true)"
[ -n "${a_sats:-}" ] && [ "$a_sats" -gt 0 ] || die "A has no confidential balance after scan — cannot send. (Wait for shields to mature/scan again.)"
info "A confidential balance: $a_sats sats"

# ── Phase 5: A -> B confidential send ──────────────────────────────────────
log "Phase 5 — confidential send  A -> B  ($SEND_AMOUNT SDAG, amount hidden on-chain)"
send_out="$(wallet_a send "$B_CONF" "$SEND_AMOUNT" 2>&1)" || true
echo "$send_out" | sed 's/^/      /'
echo "$send_out" | grep -q "Broadcast OK" \
  || die "confidential send was NOT accepted to mempool (this is exactly the path the fix unblocks — check node logs)"
TXID="$(echo "$send_out" | grep -oE 'TxID[ ]*:[ ]*[0-9a-f]+' | grep -oE '[0-9a-f]+$' | head -1 || true)"
info "accepted to mempool. TxID: ${TXID:-<unknown>}"

# ── Phase 6: wait for mining, B scans (acceptance oracle) ──────────────────
log "Phase 6 — wait for confirmation, then B scans"
h="$(block_height)"
info "waiting for +$CONFIRM_BLOCKS blocks (from height $h)…"
wait_height "$((h + CONFIRM_BLOCKS))" >/dev/null || die "chain did not advance $CONFIRM_BLOCKS blocks within ${POLL_TIMEOUT}s (is a miner running?)"

found=0; b_sats=0; tries=0
while [ "$tries" -lt 6 ]; do
  tries=$((tries+1))
  b_scan="$(wallet_b scan 2>&1)" || true
  found="$(echo "$b_scan" | grep -oE 'New confidential outputs found this scan: [0-9]+' | grep -oE '[0-9]+$' | head -1 || echo 0)"
  b_sats="$(echo "$b_scan" | grep -oE 'Confidential balance:[^(]*\([0-9]+ sats\)' | grep -oE '[0-9]+ sats' | grep -oE '[0-9]+' | head -1 || echo 0)"
  [ "${found:-0}" -ge 1 ] 2>/dev/null && { echo "$b_scan" | sed 's/^/      /'; break; }
  info "  scan #$tries: nothing yet; waiting for the block to index…"
  sleep "$POLL_INTERVAL"
done

# ── Verdict ────────────────────────────────────────────────────────────────
echo
if [ "${found:-0}" -ge 1 ] 2>/dev/null && [ "${b_sats:-0}" -gt 0 ] 2>/dev/null; then
  printf '\033[1;32mPASS\033[0m — B detected the confidential output.\n'
  info "TxID              : ${TXID:-<unknown>}"
  info "New outputs (B)   : $found"
  info "B confidential bal: $b_sats sats"
  info "Acceptance oracle met: build -> mempool -> mined -> recipient scan found the output."
  echo
  echo "NOTE: this is the FUNCTIONAL oracle only. The mandatory external"
  echo "cryptographic + consensus review is a separate, required gate before mainnet."
  exit 0
else
  die "B did NOT detect the confidential output (found=$found, sats=$b_sats). Check: all nodes upgraded? miner running? node logs for a rejection?"
fi
