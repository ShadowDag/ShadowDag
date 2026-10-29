# ShadowDAG Monitoring (Prometheus + Grafana)

A ready-to-run observability stack that scrapes the node's `GET /metrics`
endpoint (served on the RPC port) and visualizes it in Grafana.

## Quick start (with the node, via Docker)

From the repo root:

```bash
docker compose -f docker-compose.yml -f monitoring/docker-compose.monitoring.yml up -d
```

This starts the node, Prometheus, and Grafana on one network. Prometheus scrapes
`node:9332/metrics` internally, so you don't need to publish the RPC port.

- **Grafana:** http://localhost:3001  (login `admin` / `admin`, then change it)
- **Prometheus:** http://localhost:9090

The "ShadowDAG Node" dashboard is auto-provisioned (folder *ShadowDAG*).

## Monitoring a host (non-Docker) node

If the node runs on the host, point Prometheus at it. Edit
`monitoring/prometheus.yml`:

```yaml
    static_configs:
      - targets: ["127.0.0.1:9332"]
```

and run Prometheus with host networking (or set the reachable host:port).

## Metrics exposed

The node serves these gauges at `GET /metrics` (text exposition format):

| Metric | Meaning |
|---|---|
| `shadowdag_block_count` | Total blocks stored |
| `shadowdag_height` | Current selected-chain height |
| `shadowdag_mempool_size` | Transactions in the mempool |
| `shadowdag_peer_count` | Known/connected peers |
| `shadowdag_utxo_count` | UTXO set size |

The dashboard adds a derived **blocks/min** panel via `rate(shadowdag_block_count[5m])`.

## Security

`/metrics` is unauthenticated (the values are non-sensitive chain stats) but is
served on the RPC port — keep that port on a private/Docker network, not the
public internet (see `docs/NODE_OPERATOR_GUIDE.md`). Change the default Grafana
password on first login.

## Extending

Add gauges in `RpcServer::prometheus_metrics` (service/network/rpc/rpc_server.rs)
and new panels in `grafana/dashboards/shadowdag.json`.
