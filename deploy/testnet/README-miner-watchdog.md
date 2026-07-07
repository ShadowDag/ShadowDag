# Testnet miner liveness watchdog

Keeps the dockerized testnet miner alive. The in-container miner loop
(`docker exec -d`) is not supervised by any init, so it can die and silently
stall the chain. This host-side systemd watchdog supervises mining by
**block-height liveness** (the only reliable signal — `ps` is unreliable in the
container), and self-heals a dead miner in ~90s.

## Files

- `miner_loop.sh` — the in-container loop; runs `shadowdag-miner` and restarts it
  if it exits. Lives on the container volume at `/data/miner_loop.sh`.
- `miner-watchdog.sh` — host script; every 30s samples `getblockcount`, and after
  3 consecutive no-advance samples (~90s) it kills every stray in-container miner
  and starts exactly one loop. Installs to
  `/usr/local/bin/shadowdag-testnet-miner-watchdog.sh`.
- `shadowdag-testnet-miner.service` — host systemd unit (`Restart=always`,
  enabled on boot) that runs the watchdog.

## Install (on the seed host)

```sh
# 1. in-container loop (the volume is mounted at /data)
docker exec -u root -i shadowdag-testnet tee /data/miner_loop.sh < miner_loop.sh > /dev/null
docker exec -u root shadowdag-testnet chmod +x /data/miner_loop.sh

# 2. host watchdog + unit
install -m 0755 miner-watchdog.sh /usr/local/bin/shadowdag-testnet-miner-watchdog.sh
install -m 0644 shadowdag-testnet-miner.service /etc/systemd/system/

# 3. enable + start
systemctl daemon-reload
systemctl enable --now shadowdag-testnet-miner.service
journalctl -u shadowdag-testnet-miner.service -f
```

The unit name is deliberately distinct from the bare-metal mainnet
`shadowdag-miner.service`; the two do not interact.

## Notes / gotchas

- The container has **no standalone `kill` binary** — killing must go through a
  shell builtin: `docker exec -u root shadowdag-testnet bash -c 'kill -9 <pid>'`
  (`bash`, not `sh`).
- Processes started by `docker exec -d` show `PPid=0` inside the container's PID
  namespace (orphaned, no reaper) but are still killable by root via the builtin.
- The container entrypoint also auto-starts a miner when `MINER_ADDRESS` is set.
  That is harmless: the watchdog only heals on a real stall, so a healthy
  entrypoint miner is left alone; on watchdog (re)start its kill+start converges
  to a single instance.
- Adjust the payout address / threads in `miner_loop.sh` before installing.
