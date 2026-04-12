// =============================================================================
//                           S H A D O W D A G
//         E2E tests for the complete contract lifecycle:
//         deploy -> execute -> receipt -> persistence -> recovery -> reorg
// =============================================================================

#[cfg(test)]
mod contract_e2e {
    use crate::runtime::vm::core::execution_env::*;
    use crate::runtime::vm::core::vm::ExecutionResult;
    use crate::runtime::vm::core::executor::Executor;
    use crate::runtime::vm::core::vm_context::VMContext;
    use crate::runtime::vm::contracts::contract_storage::{ContractStorage, ContractUndoData};
    use crate::domain::transaction::tx_receipt::{
        TxReceipt, compute_receipt_root, persist_receipt, load_receipt, persist_receipts_batch,
    };

    // ── Opcode byte constants (from v1_spec.rs) ─────────────────────────
    const STOP: u8          = 0x00;
    const PUSH1: u8         = 0x10;
    const PUSH2: u8         = 0x11;
    const PUSH4: u8         = 0x12;
    const ADD: u8           = 0x20;
    const SLOAD: u8         = 0x50;
    const SSTORE: u8        = 0x51;
    const CALLVALUE: u8     = 0x71;
    const JUMP: u8          = 0x80;
    const JUMPDEST: u8      = 0x82;
    const MSTORE: u8        = 0x91;
    const LOG: u8           = 0xA0;
    const CALL: u8          = 0xB0;
    const RETURN: u8        = 0xB6;
    const REVERT: u8        = 0xB7;
    const CALLDATALOAD: u8  = 0xC0;

    // ── Helper: unique temp path for DB isolation between tests ──────────
    fn tmp_path(suffix: &str) -> String {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("shadowdag_e2e_{}_{}_{}", suffix, ts, id));
        dir.to_str().unwrap().to_string()
    }

    // ── Helper: create a fresh ExecutionEnvironment ──────────────────────
    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment::new(BlockContext {
            timestamp: 1000,
            block_hash: "00".repeat(32),
            network: "mainnet".to_string(),
        })
    }

    // ── Helper: build a CallContext for a contract ───────────────────────
    fn make_call(address: &str, caller: &str, calldata: Vec<u8>) -> CallContext {
        CallContext {
            address: address.into(),
            code_address: address.into(),
            caller: caller.into(),
            value: 0,
            gas_limit: 1_000_000,
            calldata,
            is_static: false,
            depth: 0,
            is_delegate: false,
        }
    }

    // ── Helper: build a fresh Executor backed by a temp DB ──────────────
    fn make_executor() -> Executor {
        let path = tmp_path("executor");
        let storage = ContractStorage::new(&path)
            .expect("ContractStorage::new should succeed");
        let ctx = VMContext::new(storage);
        Executor::new(ctx)
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 1: Full deploy -> call -> verify state
    // Contract stores calldata[0..32] into storage slot 0
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_deploy_and_call_stores_value() {
        // Bytecode: PUSH1 0, CALLDATALOAD, PUSH1 0, SSTORE, STOP
        // Reads first 32 bytes of calldata, stores in slot 0
        let code = vec![PUSH1, 0, CALLDATALOAD, PUSH1, 0, SSTORE, STOP];

        let mut env = make_env();
        env.state.set_code("contract1", code).unwrap();
        env.state.set_balance("user", 1_000_000).unwrap();

        // Call with calldata = 42 (as big-endian U256)
        let mut calldata = vec![0u8; 32];
        calldata[31] = 42;

        let ctx = CallContext {
            address: "contract1".into(),
            code_address: "contract1".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 1_000_000,
            calldata,
            is_static: false,
            depth: 0,
            is_delegate: false,
        };

        let result = env.execute_frame(&ctx);
        assert!(
            matches!(result, CallOutcome::Success { .. }),
            "Call should succeed, got: {:?}",
            result,
        );

        // Verify storage -- the VM stores as "0x{hex}" in key "slot:0"
        let stored = env.state.storage_load("contract1", "slot:0");
        assert!(stored.is_some(), "Slot 0 should have a value after SSTORE");
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 2: Failed execution (REVERT) does not pollute state
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_failed_execution_clean_state() {
        let mut env = make_env();

        // Contract: stores 99 at slot 0, then REVERTs
        // PUSH1 99, PUSH1 0, SSTORE, PUSH1 0, PUSH1 0, REVERT
        let code = vec![PUSH1, 99, PUSH1, 0, SSTORE, PUSH1, 0, PUSH1, 0, REVERT];
        env.state.set_code("contract", code).unwrap();

        let ctx = make_call("contract", "user", vec![]);
        let result = env.execute_frame(&ctx);

        assert!(
            matches!(result, CallOutcome::Revert { .. }),
            "Should revert, got: {:?}",
            result,
        );

        // State must be clean -- REVERT rolls back the SSTORE
        assert!(
            env.state.storage_load("contract", "slot:0").is_none(),
            "REVERT must not leave state changes",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 3: Out of gas does not pollute state
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_out_of_gas_clean_state() {
        let mut env = make_env();

        // Contract: stores 77 at slot 0, then loops forever
        //   PUSH1 77, PUSH1 0, SSTORE   (positions 0-4)
        //   JUMPDEST                     (position 5)
        //   PUSH1 5, JUMP               (jump back to pos 5)
        let code = vec![
            PUSH1, 77, PUSH1, 0, SSTORE, // store 77 at slot 0
            JUMPDEST,                     // pos 5
            PUSH1, 5,                     // push target
            JUMP,                         // jump back to 5
        ];
        env.state.set_code("contract", code).unwrap();

        let ctx = CallContext {
            address: "contract".into(),
            code_address: "contract".into(),
            caller: "user".into(),
            value: 0,
            gas_limit: 500, // Very low gas -- will run out during loop
            calldata: vec![],
            is_static: false,
            depth: 0,
            is_delegate: false,
        };

        let result = env.execute_frame(&ctx);
        assert!(
            matches!(result, CallOutcome::Failure { .. }),
            "Should fail with OOG, got: {:?}",
            result,
        );

        // State must be clean -- entire frame rolled back on failure
        assert!(
            env.state.storage_load("contract", "slot:0").is_none(),
            "OOG must rollback all state including early SSTOREs",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 4: Cross-contract call with state verification
    //
    // Contract A CALLs contract B. B stores CALLVALUE in slot 0.
    // We verify that B's storage was written after A's execution.
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_cross_contract_call_state() {
        let mut env = make_env();
        env.state.set_balance("contract_a", 10_000).unwrap();

        // Contract B: stores CALLVALUE in slot 0, then STOP
        let code_b = vec![CALLVALUE, PUSH1, 0, SSTORE, STOP];

        // CALL resolves its target via `resolve_address` — a 20-byte
        // canonical body popped off the stack is reconstructed as
        // `"SD1c" + hex(body)` using the block context's network.
        // PUSH1 0x0b pushes `[0u8; 19, 0x0b]` as the right-aligned
        // body inside a 32-byte U256 word, so the resolved target
        // string is `"SD1c" + hex([0u8; 19, 0x0b])` — a 44-char
        // mainnet contract address. Store B's code at that exact key.
        let mut body = [0u8; 20];
        body[19] = 0x0b;
        let target_addr = format!("SD1c{}", hex::encode(body));
        env.state.set_code(&target_addr, code_b).unwrap();

        // Contract A: CALL B with value=100
        // Stack layout for CALL: gas, addr, value, argsOff, argsLen, retOff, retLen
        //   PUSH1 0 (retLen)
        //   PUSH1 0 (retOff)
        //   PUSH1 0 (argsLen)
        //   PUSH1 0 (argsOff)
        //   PUSH1 100 (value)
        //   PUSH1 0x0b (addr -- will resolve to hex "0000...000b")
        //   PUSH4 50000 (gas)
        //   CALL
        //   STOP
        let code_a = vec![
            PUSH1, 0,     // retLen
            PUSH1, 0,     // retOff
            PUSH1, 0,     // argsLen
            PUSH1, 0,     // argsOff
            PUSH1, 100,   // value = 100
            PUSH1, 0x0b,  // target addr = 11
            PUSH4, 0x00, 0x00, 0xC3, 0x50, // gas = 50000
            CALL,
            STOP,
        ];
        env.state.set_code("contract_a", code_a).unwrap();

        let ctx = make_call("contract_a", "user", vec![]);
        let result = env.execute_frame(&ctx);

        assert!(
            matches!(result, CallOutcome::Success { .. }),
            "Cross-contract call should succeed, got: {:?}",
            result,
        );

        // Verify: B's storage should have the value from CALLVALUE (100)
        let stored = env.state.storage_load(&target_addr, "slot:0");
        assert!(
            stored.is_some(),
            "Contract B should have stored CALLVALUE in slot 0",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 5: Receipt generation and determinism
    // Same code + same input = same gas, same receipt root.
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_receipt_deterministic() {
        let code = vec![PUSH1, 42, PUSH1, 0, SSTORE, STOP];

        // First execution
        let mut env1 = make_env();
        env1.state.set_code("c", code.clone()).unwrap();
        let ctx = make_call("c", "u", vec![]);
        let result1 = env1.execute_frame(&ctx);
        let gas1 = match &result1 {
            CallOutcome::Success { gas_used, .. } => *gas_used,
            other => panic!("Expected success, got: {:?}", other),
        };

        // Second execution (fresh environment, same code)
        let mut env2 = make_env();
        env2.state.set_code("c", code).unwrap();
        let result2 = env2.execute_frame(&ctx);
        let gas2 = match &result2 {
            CallOutcome::Success { gas_used, .. } => *gas_used,
            other => panic!("Expected success, got: {:?}", other),
        };

        assert_eq!(gas1, gas2, "Deterministic execution: gas must be identical");

        // Receipt root determinism
        let r1 = TxReceipt::new_pending("tx1".into(), 100, 1, 0);
        let r2 = TxReceipt::new_pending("tx2".into(), 200, 1, 0);
        let root_a = compute_receipt_root(&[r1.clone(), r2.clone()]);
        let root_b = compute_receipt_root(&[r1, r2]);
        assert_eq!(root_a, root_b, "Same receipts must produce the same root");
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 6: Receipt persistence and load via RocksDB
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_receipt_persist_and_load() {
        let path = tmp_path("receipts");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &path).unwrap();

        let mut receipt = TxReceipt::new_pending("tx_abc".into(), 500, 2, 1000);
        receipt.gas_used = 50_000;
        receipt.execution_success = true;
        receipt.contract_addr = Some("SD1c123abc".into());
        receipt.vm_version = 1;

        persist_receipt(&db, &receipt);

        let loaded = load_receipt(&db, "tx_abc");
        assert!(loaded.is_some(), "Receipt should be loadable after persist");
        let loaded = loaded.unwrap();
        assert_eq!(loaded.tx_hash, "tx_abc");
        assert_eq!(loaded.gas_used, 50_000);
        assert!(loaded.execution_success);
        assert_eq!(loaded.contract_addr, Some("SD1c123abc".into()));
        assert_eq!(loaded.vm_version, 1);

        // Non-existent receipt returns None
        assert!(load_receipt(&db, "nonexistent").is_none());
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 7: Batch receipt persistence
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_receipt_batch_persist() {
        let path = tmp_path("batch_receipts");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &path).unwrap();

        let r1 = TxReceipt::new_pending("tx_1".into(), 100, 1, 500);
        let r2 = TxReceipt::new_pending("tx_2".into(), 200, 2, 1000);
        let r3 = TxReceipt::new_pending("tx_3".into(), 300, 1, 1500);

        persist_receipts_batch(&db, &[r1, r2, r3]);

        assert!(load_receipt(&db, "tx_1").is_some(), "Batch-persisted receipt 1 should load");
        assert!(load_receipt(&db, "tx_2").is_some(), "Batch-persisted receipt 2 should load");
        assert!(load_receipt(&db, "tx_3").is_some(), "Batch-persisted receipt 3 should load");
        assert!(load_receipt(&db, "tx_4").is_none(), "Non-persisted receipt should be absent");
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 8: Contract state persistence and reload via
    //         ContractStorage (persist_to_storage / load_contract)
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_state_persist_and_reload() {
        let path = tmp_path("contracts");
        let storage = ContractStorage::new(&path).unwrap();

        // Execute contract that stores a value
        let mut env = make_env();
        let code = vec![PUSH1, 42, PUSH1, 0, SSTORE, STOP];
        env.state.set_code("contract1", code).unwrap();

        let ctx = make_call("contract1", "user", vec![]);
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }));

        // Persist to storage
        env.persist_to_storage(&storage).unwrap();

        // Reload in a completely fresh environment
        let mut env2 = make_env();
        env2.load_contract_from_storage(&storage, "contract1")
            .expect("load_contract_from_storage should succeed on valid state");

        // Code should be loadable from the reloaded env
        let code = env2.state.get_code("contract1");
        assert!(!code.is_empty(), "Code should persist across reload");
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 9: Contract undo data and rollback
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_undo_rollback() {
        let path = tmp_path("undo_test");
        let storage = ContractStorage::new(&path).unwrap();

        // Set initial state to simulate pre-existing account
        storage.set_state("account:contract1", "0|0|empty").unwrap();

        // Execute and persist with undo
        let mut env = make_env();
        env.state.set_code("contract1", vec![PUSH1, 55, PUSH1, 0, SSTORE, STOP]).unwrap();

        let ctx = make_call("contract1", "user", vec![]);
        env.execute_frame(&ctx);

        // Persist with undo data for block_123
        let undo = env.persist_with_undo(&storage, "block_123", None, None).unwrap();
        assert!(
            !undo.modified_keys.is_empty(),
            "Undo should capture modified keys",
        );

        // Verify state was updated
        let new_state = storage.get_state("account:contract1");
        assert!(new_state.is_some(), "State should be updated after persist");
        assert_ne!(
            new_state.as_deref(),
            Some("0|0|empty"),
            "State should differ from original after execution",
        );

        // Also verify undo data was saved
        assert!(
            storage.has_undo_data("block_123"),
            "Undo data should be saved for block_123",
        );

        // Rollback
        storage.rollback_block("block_123").unwrap();

        // Verify state restored to original
        let restored = storage.get_state("account:contract1");
        assert_eq!(
            restored,
            Some("0|0|empty".to_string()),
            "Rollback should restore original state",
        );

        // Undo data itself should be cleaned up
        assert!(
            !storage.has_undo_data("block_123"),
            "Undo data should be deleted after rollback",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 10: Multiple TXs in one block share state
    // TX1 stores a value; TX2 reads it from the same env.
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_intra_block_state_visibility() {
        let mut env = make_env();

        // TX 1: store 42 at slot 0
        let code1 = vec![PUSH1, 42, PUSH1, 0, SSTORE, STOP];
        env.state.set_code("contract", code1).unwrap();

        let ctx1 = make_call("contract", "user", vec![]);
        let r1 = env.execute_frame(&ctx1);
        assert!(matches!(r1, CallOutcome::Success { .. }));

        // TX 2: load slot 0, store it at slot 1
        let code2 = vec![PUSH1, 0, SLOAD, PUSH1, 1, SSTORE, STOP];
        env.state.set_code("contract", code2).unwrap();

        let ctx2 = make_call("contract", "user", vec![]);
        let r2 = env.execute_frame(&ctx2);
        assert!(matches!(r2, CallOutcome::Success { .. }));

        // Slot 1 should have the value from slot 0 (cross-TX visibility)
        let slot1 = env.state.storage_load("contract", "slot:1");
        assert!(
            slot1.is_some(),
            "TX2 should see TX1's state changes within the same block env",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 11: STATICCALL enforcement -- SSTORE in static context
    //          must fail and leave no state behind
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_staticcall_enforcement() {
        let mut env = make_env();

        // Target contract tries to SSTORE -- should fail under static context
        let target_code = vec![PUSH1, 1, PUSH1, 0, SSTORE, STOP];
        env.state.set_code("target", target_code).unwrap();

        // Execute the target in static mode
        let ctx = CallContext {
            address: "target".into(),
            code_address: "target".into(),
            caller: "caller".into(),
            value: 0,
            gas_limit: 1_000_000,
            calldata: vec![],
            is_static: true, // STATIC -- no state writes allowed
            depth: 0,
            is_delegate: false,
        };

        let result = env.execute_frame(&ctx);
        assert!(
            matches!(result, CallOutcome::Failure { .. }),
            "SSTORE in static context must fail, got: {:?}",
            result,
        );
        assert!(
            env.state.storage_load("target", "slot:0").is_none(),
            "No state leakage from failed static call",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 12: Gas accounting accuracy
    // Simple operations should consume predictable, small gas.
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_gas_accounting() {
        let mut env = make_env();

        // Simple contract: PUSH1 + PUSH1 + ADD + STOP
        let code = vec![PUSH1, 5, PUSH1, 3, ADD, STOP];
        env.state.set_code("c", code).unwrap();

        let ctx = make_call("c", "u", vec![]);
        let result = env.execute_frame(&ctx);

        match result {
            CallOutcome::Success { gas_used, .. } => {
                assert!(gas_used > 0, "Should consume some gas");
                assert!(
                    gas_used < 1000,
                    "Simple contract should use little gas, used {}",
                    gas_used,
                );
            }
            other => panic!("Should succeed, got: {:?}", other),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 13: RETURN data propagation
    // Store 0xBEEF in memory, then RETURN 2 bytes from offset 30
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_return_data_correct() {
        let mut env = make_env();

        // PUSH2 0xBEEF -> memory[0..32] via MSTORE -> RETURN 2 bytes from offset 30
        let code = vec![
            PUSH2, 0xBE, 0xEF, // push 0xBEEF
            PUSH1, 0,           // offset 0
            MSTORE,             // memory[0..32] = U256(0xBEEF) big-endian
            PUSH1, 2,           // size = 2
            PUSH1, 30,          // offset = 30  (last 2 bytes of the 32-byte word)
            RETURN,
        ];
        env.state.set_code("c", code).unwrap();

        let ctx = make_call("c", "u", vec![]);
        let result = env.execute_frame(&ctx);

        match result {
            CallOutcome::Success { return_data, .. } => {
                assert_eq!(return_data.len(), 2, "Should return exactly 2 bytes");
                assert_eq!(
                    return_data,
                    vec![0xBE, 0xEF],
                    "Returned bytes should be 0xBEEF",
                );
            }
            other => panic!("Should succeed with return data, got: {:?}", other),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 14: Log emission
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_log_emission() {
        let mut env = make_env();

        // Contract emits LOG0 with data = 0xFF
        let code = vec![PUSH1, 0xFF, LOG, STOP];
        env.state.set_code("c", code).unwrap();

        let ctx = make_call("c", "u", vec![]);
        let result = env.execute_frame(&ctx);

        match result {
            CallOutcome::Success { logs, .. } => {
                assert!(!logs.is_empty(), "Should emit at least one log");
                assert_eq!(logs[0].contract, "c", "Log should be from contract 'c'");
            }
            other => panic!("Should succeed with logs, got: {:?}", other),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 15: V1 spec validation rejects non-v1 opcodes
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_v1_spec_rejects_invalid() {
        use crate::runtime::vm::core::v1_spec::validate_v1_bytecode;

        // 0xEE is not a v1 opcode -- must be rejected
        assert!(
            validate_v1_bytecode(&[0xEE]).is_err(),
            "0xEE is not a valid v1 opcode",
        );

        // Valid bytecode passes
        assert!(
            validate_v1_bytecode(&[PUSH1, 42, STOP]).is_ok(),
            "PUSH1 42 STOP is valid v1 bytecode",
        );

        // PUSH data that looks like invalid opcode is OK (0xEE is a data byte)
        assert!(
            validate_v1_bytecode(&[PUSH1, 0xEE, STOP]).is_ok(),
            "0xEE as PUSH1 data byte should not be rejected",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 16: Executor deploy + call end-to-end via ContractStorage
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_executor_deploy_and_call() {
        let exec = make_executor();

        // Deploy a contract: PUSH1 42, STOP
        let bytecode = vec![PUSH1, 42, STOP];
        let (addr, result) = exec.deploy(
            &bytecode, "SD1deployer", 0, 100_000, 1000, "blockhash", 0,
        ).unwrap();

        assert!(addr.starts_with("SD1c"), "Contract address should start with SD1c");
        match result {
            ExecutionResult::Success { .. } => {}
            other => panic!("Deploy should succeed, got: {:?}", other),
        }

        assert!(exec.contract_exists(&addr), "Contract should exist after deploy");
        let code = exec.get_code(&addr);
        assert_eq!(code, Some(bytecode), "Stored code should match deployed bytecode");
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 17: Executor rejects empty bytecode deploy
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_executor_rejects_empty_deploy() {
        let exec = make_executor();
        let result = exec.deploy(&[], "SD1x", 0, 100_000, 1000, "bh", 0);
        assert!(result.is_err(), "Deploying empty bytecode should fail");
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 18: ContractStorage set/get/delete round-trip
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_contract_storage_crud() {
        let path = tmp_path("crud");
        let storage = ContractStorage::new(&path).unwrap();

        // Set and get
        storage.set_state("key1", "value1").unwrap();
        assert_eq!(storage.get_state("key1"), Some("value1".to_string()));

        // Overwrite
        storage.set_state("key1", "value2").unwrap();
        assert_eq!(storage.get_state("key1"), Some("value2".to_string()));

        // Delete
        storage.delete_state("key1").unwrap();
        assert_eq!(storage.get_state("key1"), None);

        // Get non-existent
        assert_eq!(storage.get_state("nonexistent"), None);
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 19: Receipt root changes with different receipts
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_receipt_root_varies() {
        let r1 = TxReceipt::new_pending("tx1".into(), 100, 1, 0);
        let r2 = TxReceipt::new_pending("tx2".into(), 200, 1, 0);

        let root_12 = compute_receipt_root(&[r1.clone(), r2.clone()]);
        let root_21 = compute_receipt_root(&[r2, r1]);

        // Different ordering must produce a different root
        assert_ne!(
            root_12, root_21,
            "Receipt root must be order-dependent",
        );

        // Empty receipt list
        let root_empty = compute_receipt_root(&[]);
        assert_ne!(root_empty, root_12, "Empty receipt root should differ from non-empty");
    }

    // ═══════════════════════════════════════════════════════════════
    // TEST 20: Undo prune for finalized blocks
    // ═══════════════════════════════════════════════════════════════
    #[test]
    fn e2e_undo_prune_finalized() {
        let path = tmp_path("prune");
        let storage = ContractStorage::new(&path).unwrap();

        // Create some undo data
        let undo = ContractUndoData {
            modified_keys: vec![("key1".into(), Some("old_val".into()))],
            created_accounts: vec![],
            destroyed_accounts: vec![],
            receipt_root: None,
            state_root: None,
        };

        storage.save_undo("block_a", &undo).unwrap();
        storage.save_undo("block_b", &undo).unwrap();
        assert!(storage.has_undo_data("block_a"));
        assert!(storage.has_undo_data("block_b"));

        // Prune finalized blocks
        let pruned = storage.prune_finalized_undo_data(&["block_a".into()]);
        assert_eq!(pruned, 1, "Should prune exactly 1 entry");
        assert!(!storage.has_undo_data("block_a"), "block_a undo should be gone");
        assert!(storage.has_undo_data("block_b"), "block_b undo should remain");
    }
}
