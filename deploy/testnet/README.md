# Deploy a ShadowDAG Testnet Node

Two paths: **Docker** (fastest) or **bare-metal + systemd** (build script).
Testnet ports: **P2P 19333** (public), **RPC 19332** (keep local), explorer 8080.

> A public testnet means running ≥1 reachable node (ideally the configured seed
> hosts), then having others connect. The seed addresses live in
> `config/network/bootstrap_nodes.rs` — point the `seedN-testnet.shadowdag.network`
> DNS records at your testnet servers, or peers can dial the static IP fallbacks.

---

## Option A — Docker (recommended)

On an Ubuntu/Debian VPS:

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh

# 2. Clone + enter
git clone https://github.com/ShadowDag/ShadowDag.git
cd ShadowDag/deploy/testnet

# 3. Build + run the testnet node
docker compose -f docker-compose.testnet.yml up -d --build

# 4. Open the P2P port on the firewall
sudo ufw allow 19333/tcp

# 5. Watch logs
docker logs -f shadowdag-testnet
```

Stop / update:

```bash
docker compose -f docker-compose.testnet.yml down
git pull && docker compose -f docker-compose.testnet.yml up -d --build
```

## Option B — bare-metal + systemd

```bash
git clone https://github.com/ShadowDag/ShadowDag.git
cd ShadowDag/deploy/testnet
sudo ./deploy.sh                 # builds, installs, starts the service
sudo ufw allow 19333/tcp
journalctl -u shadowdag-testnet -f
```

---

## Verify the node is up

From the server (RPC is local-only):

```bash
curl -s http://127.0.0.1:19332 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getnodeinfo","params":[]}'

curl -s http://127.0.0.1:19332 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getpeerinfo","params":[]}'   # peers connecting?
```

Metrics (for the Grafana stack): `curl http://127.0.0.1:19332/metrics`.

## Make it a seed node

1. Give the server a static public IP.
2. Ensure **19333/tcp** is open (firewall + cloud security group).
3. Add its IP/DNS to `config/network/bootstrap_nodes.rs::testnet()` (and point the
   `seedN-testnet.shadowdag.network` A-records at it), so new nodes discover it.
4. Run ≥2–3 such nodes in different locations for a resilient testnet.

## Mining on testnet (optional)

```bash
# create a testnet reward address first:  shadowdag-wallet new testnet
shadowdag-miner --network=testnet --address=ST1<addr> --threads=2 --rpc=127.0.0.1:19332
```

## Checklist

- [ ] P2P 19333 reachable from the internet (`nc -vz <ip> 19333` from elsewhere).
- [ ] RPC 19332 NOT publicly reachable.
- [ ] At least 2–3 nodes peering with each other (`getpeerinfo` shows peers).
- [ ] Blocks advancing (`getblockcount` increases) once mining starts.
- [ ] Monitoring stack scraping `/metrics` (see `monitoring/`).
