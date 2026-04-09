# ShadowDAG Operations Runbook

## Incident Response

### 1. Node Divergence (state_root mismatch)

**Symptoms**: Two nodes report different state_root for the same block height.

**Steps**:
1. Check both nodes' best tip: `curl -s :9332 -d '{"method":"getbestblockhash","id":1}'`
2. Compare block headers: check receipt_root and state_root fields
3. If tips differ: likely a reorg in progress — wait 10 blocks
4. If state_root differs at same tip:
   - Stop the diverged node
   - Delete contract state: `rm -rf ~/.shadowdag/<network>/contracts/`
   - Restart with `--reindex` flag to rebuild from blocks
5. Report to team with: block height, both state_roots, node versions

### 2. Receipt/State Mismatch

**Symptoms**: InvariantChecker reports violations.

**Steps**:
1. Check logs: `grep "invariant_violation" shadowdag.log`
2. Identify the block: height and hash from the violation
3. Re-execute the block's contract TXs manually via RPC
4. Compare receipt_root: `compute_receipt_root(receipts)` vs header value
5. If mismatch is reproducible: this is a consensus bug — escalate immediately
6. If transient: likely a crash during persistence — restart and verify

### 3. Abnormal Reorg

**Symptoms**: Reorg depth > 10 blocks.

**Steps**:
1. Check reorg depth: `grep "reorg_rollback_complete" shadowdag.log`
2. If depth > MAX_REORG_DEPTH (1000): node will reject automatically
3. If 10 < depth < 1000: investigate
   - Is there a network partition?
   - Is there a mining centralization issue?
   - Check peer connections: `curl :9332 -d '{"method":"getpeerinfo","id":1}'`
4. If malicious: blacklist the attacking peer IPs

### 4. Faucet Abuse

**Symptoms**: Single address or IP requesting excessive coins.

**Steps**:
1. Rate limit: max 1 request per IP per hour
2. Amount limit: max 100 SDAG per request
3. Cooldown: 24h between requests to same address
4. Ban persistent abusers at IP level
5. Monitor total faucet outflow per day

### 5. Seed Node Failure

**Symptoms**: New nodes can't bootstrap.

**Steps**:
1. Check seed node status: `nc -zv seed1.shadowdag.org 19333`
2. If down: restart the seed node service
3. If multiple seeds down: update bootstrap_nodes.rs with backup IPs
4. Emergency: publish IP list on project website/Discord

### 6. Safe Restart/Recovery

**Steps**:
1. Stop node gracefully: `kill -SIGTERM <pid>` (NOT kill -9)
2. Wait for "shutdown complete" in logs
3. Verify data integrity: check last block's state_root
4. Restart: `shadowdag-node --network <network>`
5. Monitor: watch for "state_recovered" and "consistency_check_passed" in logs
6. If recovery fails: `shadowdag-node --network <network> --reindex`

## Monitoring Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Block time | > 5s avg | > 30s avg |
| Reorg depth | > 5 blocks | > 20 blocks |
| Mempool size | > 50,000 txs | > 200,000 txs |
| OOG rate | > 5% | > 20% |
| Revert rate | > 30% | > 60% |
| Invariant violations | ANY | ANY |
| Peer count | < 4 | < 2 |
| Disk usage | > 80% | > 95% |

## Exit Criteria for Public Testnet

- [ ] 72h soak test without divergence
- [ ] 0 state_root/receipt_root mismatches across nodes
- [ ] Reorg/restart tests pass 100%
- [ ] No silent data corruption
- [ ] Block time < 2s average
- [ ] < 5% OOG rate under normal load
- [ ] Recovery from crash completes without manual intervention
