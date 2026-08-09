#!/bin/bash
# Supervised UmbraHash miner loop. Restarts the miner if it exits.
# Lifecycle managed by host unit shadowdag-testnet-miner.service.
while true; do
  RP=$(cat /data/rpc_password)
  shadowdag-miner --network=testnet \
    --address=ST139bb5faaf52e899a029c75ca59425babc0a1efce \
    --threads=2 --pow=umbra \
    --rpc-password="$RP"
  echo "[miner-loop] miner exited; restart in 2s" >&2
  sleep 2
done
