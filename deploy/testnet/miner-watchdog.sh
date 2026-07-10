#!/bin/bash
# Liveness watchdog for the dockerized ShadowDAG testnet miner.
# Health signal = block height ADVANCING (ps is unreliable in this container).
# On stall: kill ALL stray in-container miners/loops (root+bash builtin), start one.
# Self-installs /data/miner_loop.sh if missing (e.g. after a `down -v` wiped the
# data volume) so a wipe can never leave the watchdog with nothing to start.
set +e
CT=shadowdag-testnet
LOOP_PATH=/data/miner_loop.sh
INTERVAL=30
STALL_LIMIT=3
log(){ echo "[wd $(date +%H:%M:%S)] $*"; }
height(){
  local rp
  rp=$(docker exec "$CT" cat /data/rpc_password 2>/dev/null)
  docker exec "$CT" curl -s -X POST http://127.0.0.1:19332 \
    -H "Authorization: Bearer $rp" -H "content-type: application/json" \
    --data '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' 2>/dev/null \
    | grep -oE '"result":[0-9]+' | grep -oE '[0-9]+'
}
ensure_loop_script(){
  # A `down -v` wipes the data volume, taking /data/miner_loop.sh with it, which
  # would make start_one silently fail (No such file) and freeze mining. Recreate
  # it from this embedded copy if it is missing. Keep in sync with miner_loop.sh.
  if docker exec "$CT" test -f "$LOOP_PATH" 2>/dev/null; then return; fi
  log "miner loop $LOOP_PATH missing -> installing"
  docker exec -u root -i "$CT" tee "$LOOP_PATH" >/dev/null <<'LOOP'
#!/bin/bash
while true; do
  RP=$(cat /data/rpc_password)
  shadowdag-miner --network=testnet \
    --address=ST139bb5faaf52e899a029c75ca59425babc0a1efce \
    --threads=2 --pow=umbra \
    --rpc-password="$RP"
  echo "[miner-loop] miner exited; restart in 2s" >&2
  sleep 2
done
LOOP
  docker exec -u root "$CT" chmod +x "$LOOP_PATH"
}
kill_all_miners(){
  docker exec -u root "$CT" bash -c '
    for sig in TERM KILL; do
      for p in /proc/[0-9]*; do
        c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null)
        case "$c" in *shadowdag-miner*|*miner_loop.sh*) kill -$sig "${p##*/}" 2>/dev/null;; esac
      done
      sleep 1
    done
  '
}
start_one(){ ensure_loop_script; docker exec -d "$CT" bash "$LOOP_PATH"; }

log "start: resetting to a single miner instance"
kill_all_miners
start_one
sleep "$INTERVAL"
last=$(height); miss=0
while true; do
  cur=$(height)
  if [ -z "$cur" ]; then
    log "height unavailable (node busy?) - skip sample"
  elif [ -z "$last" ]; then
    last="$cur"
  elif [ "$cur" -gt "$last" ] 2>/dev/null; then
    miss=0; last="$cur"
  else
    miss=$((miss+1))
    log "no advance (cur=$cur last=$last) miss=$miss/$STALL_LIMIT"
    if [ "$miss" -ge "$STALL_LIMIT" ]; then
      log "STALL confirmed -> healing (kill strays + start one miner)"
      kill_all_miners; start_one; miss=0; sleep 10; last=$(height)
    fi
  fi
  sleep "$INTERVAL"
done
