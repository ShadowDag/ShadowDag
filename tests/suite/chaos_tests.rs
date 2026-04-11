//! Chaos Tests — adversarial and edge-case scenarios.

#[cfg(test)]
mod chaos {
    use crate::runtime::vm::core::execution_env::*;
    use crate::runtime::vm::contracts::contract_storage::ContractStorage;
    use crate::domain::transaction::tx_receipt::TxReceipt;

    const PUSH1: u8 = 0x10;
    const SSTORE: u8 = 0x51;
    const STOP: u8 = 0x00;
    const REVERT: u8 = 0xB7;
    const CALL: u8 = 0xB0;
    const JUMP: u8 = 0x80;
    const JUMPDEST: u8 = 0x82;
    const LOG0: u8 = 0xA0;

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment::new(BlockContext {
            timestamp: 1_000_000,
            block_hash: "00".repeat(32),
            network: "mainnet".to_string(),
        })
    }

    #[test]
    fn chaos_gas_saturation() {
        let mut env = make_env();
        // Infinite loop — should OOG cleanly
        let code = vec![JUMPDEST, PUSH1, 0, JUMP]; // JUMPDEST, PUSH1 0, JUMP
        env.state.set_code("loop", code).unwrap();

        let ctx = CallContext {
            address: "loop".into(), code_address: "loop".into(),
            caller: "user".into(), value: 0, gas_limit: 1000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Failure { .. }), "Should OOG");
        // State must be clean
        assert!(env.state.storage_load("loop", "slot:0").is_none());
    }

    #[test]
    fn chaos_large_calldata() {
        let mut env = make_env();
        let code = vec![STOP];
        env.state.set_code("c", code).unwrap();

        // 100KB calldata
        let calldata = vec![0xAB; 100_000];
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 10_000_000,
            calldata, is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Success { .. }), "Large calldata should work");
    }

    #[test]
    fn chaos_crash_between_utxo_and_contract() {
        // Simulates: contract state persisted, then "crash" (drop env)
        // On "restart", state should be loadable
        let path = {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_nanos();
            format!("{}/shadowdag_chaos_{}", std::env::temp_dir().display(), ts)
        };

        // Phase 1: execute and persist
        {
            let storage = ContractStorage::new(&path).unwrap();
            let mut env = make_env();
            env.state.set_code("contract", vec![PUSH1, 42, PUSH1, 0, SSTORE, STOP]).unwrap();
            let ctx = CallContext {
                address: "contract".into(), code_address: "contract".into(),
                caller: "u".into(), value: 0, gas_limit: 1_000_000,
                calldata: vec![], is_static: false, depth: 0,
            };
            env.execute_frame(&ctx);
            env.persist_to_storage(&storage).unwrap();
            // "Crash" — env and storage drop here
        }

        // Phase 2: "restart" — reload state
        {
            let storage = ContractStorage::new(&path).unwrap();
            let mut env = make_env();
            env.load_contract_from_storage(&storage, "contract")
                .expect("load_contract_from_storage should succeed on valid state");
            let code = env.state.get_code("contract");
            assert!(!code.is_empty(), "Code should survive crash/restart");
        }
    }

    #[test]
    fn chaos_reorg_with_contracts() {
        let mut env = make_env();
        let code = vec![PUSH1, 99, PUSH1, 0, SSTORE, STOP];
        env.state.set_code("c", code).unwrap();

        // Block 1: execute on chain A
        let snap = env.state.snapshot();
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 1_000_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        env.execute_frame(&ctx);
        let root_chain_a = env.state.state_root();

        // Reorg: rollback
        env.state.rollback(snap).ok();
        let root_after_reorg = env.state.state_root();

        // State should differ — chain A had writes, reorg undid them
        assert_ne!(root_chain_a, root_after_reorg, "Reorg should change state_root");
    }

    #[test]
    fn chaos_duplicate_tx_detection() {
        let mut env = make_env();
        let code = vec![PUSH1, 1, PUSH1, 0, SSTORE, STOP];
        env.state.set_code("c", code).unwrap();

        // Execute same TX twice
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 1_000_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        env.execute_frame(&ctx);
        let root1 = env.state.state_root();

        env.execute_frame(&ctx);
        let root2 = env.state.state_root();

        // Same operation twice should be deterministic
        // (both succeed and write same value)
        assert_eq!(root1, root2, "Duplicate TX should not change state_root (idempotent store)");
    }

    #[test]
    fn chaos_contract_log_spam() {
        let mut env = make_env();
        // Contract that emits many logs via LOG0
        // LOG0 pops offset and size from the stack: we push offset=0, size=1
        let mut code = Vec::new();
        for _ in 0..50 {
            code.extend_from_slice(&[PUSH1, 1, PUSH1, 0, LOG0]); // size=1, offset=0, LOG0
        }
        code.push(STOP);
        env.state.set_code("spammer", code).unwrap();

        let ctx = CallContext {
            address: "spammer".into(), code_address: "spammer".into(),
            caller: "u".into(), value: 0, gas_limit: 10_000_000,
            calldata: vec![], is_static: false, depth: 0,
        };
        let result = env.execute_frame(&ctx);
        match result {
            CallOutcome::Success { logs, .. } => {
                assert_eq!(logs.len(), 50, "All 50 logs should be captured");
            }
            _ => panic!("Log spam should succeed with enough gas"),
        }
    }

    #[test]
    fn chaos_max_call_depth() {
        let mut env = make_env();
        // Try calling at maximum depth
        let ctx = CallContext {
            address: "c".into(), code_address: "c".into(),
            caller: "u".into(), value: 0, gas_limit: 1_000_000,
            calldata: vec![], is_static: false,
            depth: 1025, // Over limit
        };
        let result = env.execute_frame(&ctx);
        assert!(matches!(result, CallOutcome::Failure { .. }), "Over max depth should fail");
    }
}
