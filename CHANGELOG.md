# Changelog

All notable changes to ShadowDAG are documented in this file.

## [v1.0.0-testnet.1] — 2026-04-09

### Smart Contract Layer
- **VM Opcodes**: All 7 system opcodes implemented — CALL, STATICCALL, DELEGATECALL, CALLCODE, CREATE, CREATE2, SELFDESTRUCT
- **V1 Spec**: 74 officially supported opcodes with canonical byte values, gas costs, and validation
- **Execution Engine**: Reentrant `ExecutionEnvironment` with StateManager snapshots, EIP-150 gas forwarding, EIP-6780 SELFDESTRUCT
- **27 Additional Opcodes**: CALLDATALOAD/SIZE/COPY, RETURNDATASIZE/COPY, CODESIZE/CODECOPY, EXTCODESIZE, ADDRESS, GAS, PC, MSTORE8, MSIZE, LOG1-LOG4, DUP2-DUP8, SWAP2-SWAP4
- **Precompile Routing**: CALL/STATICCALL to addresses 0x01-0x09 route to precompile registry
- **Contract TX Format**: Frozen with consensus fields — gas_limit, deploy_code, calldata, contract_address, vm_version
- **Receipt Model**: Deterministic receipts with execution_success, return_data, revert_reason, logs with topics
- **Block Integration**: Canonical VM execution in block processing with atomic rollback
- **receipt_root + state_root**: Committed to block header, verified by validator
- **Persistent State**: Contract state in ~/.shadowdag/<network>/contracts/ with undo log for reorg rollback
- **Receipt Persistence**: RocksDB-backed receipt storage with batch operations
- **Receipt/Log Index**: Filter by address, topic0, topic1, block range with RocksDB prefix scanning
- **VM Versioning**: VM_VERSION=1, VM_V1_ACTIVATION_HEIGHT=0, contract TX validation

### Developer Toolchain
- **shadowasm build**: Assemble .sasm -> .pkg.json package + .manifest.json
- **shadowasm test**: Run ;; @test annotations with assertions on return/storage/logs/gas
- **shadowasm trace**: Execution trace with gas/storage/call details
- **shadowasm verify**: Validate package integrity + V1 compliance
- **shadowasm script**: Deploy pipeline with @deploy/@call/@fund annotations, manifest output
- **shadowasm info/disassemble**: Package inspection and bytecode disassembly
- **Contract Package Format**: bytecode + ABI + vm_version + bytecode_hash + format_version
- **Build Manifest**: Reproducible builds with compiler version, source hashes
- **Deployment Manifest**: Per-network contract registry with chain_id, rpc_url, migration version
- **Source Maps**: PC->line mapping, stack traces, REVERT reason decoding
- **Contract Verification**: SHA-256 bytecode matching + metadata persistence
- **ABI Layer**: Function selectors, return decoding, event decoding from topics+data

### Wallet & CLI
- **Wallet Contract Flow**: build_deploy_tx(), build_call_tx() with UTXO selection
- **CLI Commands**: deploy, call, receipt, logs, deploy-package, verify
- **Network Isolation**: wallet_db/seed paths separated per network, chain_id in signing

### RPC Endpoints (9 new)
- deploy_contract, call_contract, estimate_gas
- get_transaction_receipt, get_contract_code, get_storage_at, get_logs
- verify_contract, get_contract_info

### Mempool & Mining
- Contract TX validation: intrinsic gas, gas_limit, vm_version checks
- Block gas budget: MAX_BLOCK_GAS = 100,000,000
- Gas-aware block template construction

### Rust SDK
- ShadowDagSdk: deploy, call, estimateGas, getReceipt, waitForReceipt, getLogs, verify

### Testing (134 tests)
- 20 E2E contract lifecycle tests
- 8 multi-node determinism tests
- 7 chaos/adversarial tests
- 4 soak tests (100-block, mixed, reorg, multi-node)
- 7 invariant checker tests
- 4 observability/exit criteria tests
- 7 receipt index tests
- 25 VM execution tests
- 5 v1 spec tests
- Plus contract package, verifier, manifest, ABI tests

### Security Audit Fixes (150+ bugs)
- Consensus: difficulty, finality, validation, reorg, rewards
- UTXO: spend safety, coinbase maturity, apply_block hash
- Mempool: flush prefix, RBF, orphan promotion
- P2P: flush_outbound, chain_id, targeted messages, peer manager
- RPC: password handling, WS subscriptions, gRPC shutdown
- Wallet: path isolation, chain_id signing, multisig validation
- VM: opcode drift, precompile naming, journal, memory, event_log
- Storage: get() Result type, error propagation
- Telemetry: metrics, logging, JSON escaping, Prometheus
- CLI: parse_flag safety, network fallback prevention

### Architecture
- Single execution engine: ExecutionEnvironment replaces VM stubs
- Unified constants: MAX_CALL_DEPTH=1024 everywhere
- VMContext returns Result for storage errors
- StateManager is source of truth during execution
- Gas refund cap 50% (v1 parameter), GAS opcode enabled

## [v0.1.0] — Initial Release
- BlockDAG consensus with GHOSTDAG protocol (K=180)
- UTXO model with atomic WriteBatch on RocksDB
- 4-layer validation pipeline
- Privacy: CLSAG ring signatures, Pedersen commitments, Bulletproofs, stealth addresses
- ShadowHash PoW (4-stage ASIC-resistant)
- Smooth emission schedule (0.38%/month decay, 21B SDAG max supply)
- P2P with connection puzzle, Dandelion++
- EIP-1559 style fee market
