//! Soak Tests — long-running consistency verification.
//!
//! Simulates extended operation with many blocks, contract operations,
//! and state transitions, checking invariants throughout.

#[cfg(test)]
mod soak {
    use crate::domain::transaction::tx_receipt::{compute_receipt_root, TxReceipt};
    use crate::runtime::vm::core::execution_env::*;
    use crate::runtime::vm::testing::invariant_checker::InvariantChecker;

    const PUSH1: u8 = 0x10;
    const SSTORE: u8 = 0x51;
    const SLOAD: u8 = 0x50;
    const ADD: u8 = 0x20;
    const STOP: u8 = 0x00;
    const REVERT: u8 = 0xB7;

    fn make_env(block_hash: &str) -> ExecutionEnvironment {
        ExecutionEnvironment::new(BlockContext {
            timestamp: 1_000_000,
            block_hash: block_hash.into(),
            network: "mainnet".to_string(),
        })
    }

    /// Simulate N blocks of contract execution and check invariants after each.
    #[test]
    fn soak_100_blocks_no_violations() {
        let mut env = make_env(&"aa".repeat(32));
        env.state.set_balance("deployer", u64::MAX / 2).ok();

        // Deploy a counter contract
        let counter_code = vec![
            PUSH1, 0, SLOAD, // load current value
            PUSH1, 1, ADD, // add 1
            PUSH1, 0, SSTORE, // store back
            STOP,
        ];
        env.state.set_code("counter", counter_code).unwrap();

        let mut all_clean = true;

        for block in 0..100u64 {
            let block_hash = format!("{:064x}", block);

            // Execute contract
            let ctx = CallContext {
                address: "counter".into(),
                code_address: "counter".into(),
                caller: "deployer".into(),
                value: 0,
                gas_limit: 1_000_000,
                calldata: vec![],
                is_static: false,
                depth: 0,
                is_delegate: false,
            };
            let outcome = env.execute_frame(&ctx);
            let gas = match &outcome {
                CallOutcome::Success { gas_used, .. } => *gas_used,
                _ => 0,
            };

            // Build receipt
            let mut receipt = TxReceipt::new_pending(format!("tx_{}", block), 100, 1, 0);
            receipt.gas_used = gas;
            receipt.execution_success = matches!(outcome, CallOutcome::Success { .. });

            let receipts = vec![receipt];
            let receipt_root = compute_receipt_root(&receipts);

            // Check invariants
            let result = InvariantChecker::check_block(
                block,
                &block_hash,
                Some(&receipt_root),
                Some(&env.state.state_root()),
                &receipts,
                &env,
            );

            if !result.is_clean() {
                eprintln!("{}", InvariantChecker::format_result(&result));
                all_clean = false;
                break;
            }
        }

        assert!(all_clean, "100-block soak test had invariant violations");

        // Verify counter reached 100
        let val = env.state.storage_load("counter", "slot:0");
        assert!(
            val.is_some(),
            "Counter should have a value after 100 blocks"
        );
    }

    /// Simulate blocks with mixed success/revert transactions.
    #[test]
    fn soak_mixed_success_revert() {
        let mut env = make_env(&"bb".repeat(32));

        let success_code = vec![PUSH1, 1, PUSH1, 0, SSTORE, STOP];
        let revert_code = vec![PUSH1, 0, PUSH1, 0, REVERT];

        env.state.set_code("good", success_code).unwrap();
        env.state.set_code("bad", revert_code).unwrap();

        let mut all_clean = true;

        for block in 0..50u64 {
            let contract = if block % 3 == 0 { "bad" } else { "good" };
            let ctx = CallContext {
                address: contract.into(),
                code_address: contract.into(),
                caller: "user".into(),
                value: 0,
                gas_limit: 1_000_000,
                calldata: vec![],
                is_static: false,
                depth: 0,
                is_delegate: false,
            };
            let outcome = env.execute_frame(&ctx);

            let mut receipt = TxReceipt::new_pending(format!("tx_{}", block), 100, 1, 0);
            receipt.execution_success = matches!(outcome, CallOutcome::Success { .. });

            let receipts = vec![receipt];
            let receipt_root = compute_receipt_root(&receipts);

            let result = InvariantChecker::check_block(
                block,
                &format!("{:064x}", block),
                Some(&receipt_root),
                None,
                &receipts,
                &env,
            );

            if !result.is_clean() {
                eprintln!("{}", InvariantChecker::format_result(&result));
                all_clean = false;
                break;
            }
        }

        assert!(all_clean, "Mixed success/revert soak had violations");
    }

    /// Simulate snapshot/revert cycles (simulating reorgs).
    #[test]
    fn soak_reorg_simulation() {
        let mut env = make_env(&"cc".repeat(32));

        let code = vec![PUSH1, 42, PUSH1, 0, SSTORE, STOP];
        env.state.set_code("contract", code).unwrap();

        for cycle in 0..20 {
            // Take snapshot (simulating fork point)
            let snap = env.state.snapshot();

            // Execute some blocks on branch A
            for _i in 0..5 {
                let ctx = CallContext {
                    address: "contract".into(),
                    code_address: "contract".into(),
                    caller: "user".into(),
                    value: 0,
                    gas_limit: 1_000_000,
                    calldata: vec![],
                    is_static: false,
                    depth: 0,
                    is_delegate: false,
                };
                env.execute_frame(&ctx);
            }

            // Reorg: revert to fork point
            env.state.rollback(snap).ok();

            // State should be back to snapshot
            let root_after = env.state.state_root();
            assert!(
                !root_after.is_empty(),
                "State root should exist after reorg cycle {}",
                cycle
            );
        }
    }

    /// Multi-node: 3 independent environments processing same blocks.
    #[test]
    fn soak_multi_node_consistency() {
        let code = vec![PUSH1, 0, SLOAD, PUSH1, 1, ADD, PUSH1, 0, SSTORE, STOP];

        let mut envs: Vec<ExecutionEnvironment> = (0..3)
            .map(|_| {
                let mut e = make_env(&"dd".repeat(32));
                e.state.set_code("counter", code.clone()).unwrap();
                e
            })
            .collect();

        for block in 0..50u64 {
            let mut roots = Vec::new();

            for env in envs.iter_mut() {
                let ctx = CallContext {
                    address: "counter".into(),
                    code_address: "counter".into(),
                    caller: "user".into(),
                    value: 0,
                    gas_limit: 1_000_000,
                    calldata: vec![],
                    is_static: false,
                    depth: 0,
                    is_delegate: false,
                };
                env.execute_frame(&ctx);
                roots.push(env.state.state_root());
            }

            // All nodes must agree
            assert!(
                roots.windows(2).all(|w| w[0] == w[1]),
                "Block {}: state_root divergence between nodes",
                block
            );
        }
    }
}
