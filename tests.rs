// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

// ── Original test modules ─────────────────────────────────────────────────
#[path = "tests/suite/dos_tests.rs"]
pub mod dos_tests;
#[path = "tests/suite/genesis_tests.rs"]
pub mod genesis_tests;
#[path = "tests/suite/mempool_tests.rs"]
pub mod mempool_tests;
#[path = "tests/suite/pow_genesis_tests.rs"]
pub mod pow_genesis_tests;
#[path = "tests/suite/rpc_tests.rs"]
pub mod rpc_tests;
#[path = "tests/suite/tx_layer_tests.rs"]
pub mod tx_layer_tests;
#[path = "tests/suite/tx_validator_tests.rs"]
pub mod tx_validator_tests;
#[path = "tests/suite/utxo_layer_tests.rs"]
pub mod utxo_layer_tests;
#[path = "tests/suite/utxo_tests.rs"]
pub mod utxo_tests;

// ── Comprehensive test suite (added) ─────────────────────────────────────
#[path = "tests/suite/consensus_tests.rs"]
pub mod consensus_tests;
#[path = "tests/suite/dag_tests.rs"]
pub mod dag_tests;
#[path = "tests/suite/db_tests.rs"]
pub mod db_tests;
#[path = "tests/suite/determinism_tests.rs"]
pub mod determinism_tests;
#[path = "tests/suite/mempool_advanced_tests.rs"]
pub mod mempool_advanced_tests;
#[path = "tests/suite/p2p_network_tests.rs"]
pub mod p2p_network_tests;
#[path = "tests/suite/performance_tests.rs"]
pub mod performance_tests;
#[path = "tests/suite/recovery_tests.rs"]
pub mod recovery_tests;
#[path = "tests/suite/security_tests.rs"]
pub mod security_tests;
#[path = "tests/suite/stress_tests.rs"]
pub mod stress_tests;
#[path = "tests/suite/transaction_tests.rs"]
pub mod transaction_tests;
#[path = "tests/suite/utxo_state_tests.rs"]
pub mod utxo_state_tests;

// ── Property-based tests ─────────────────────────────────────────────────
#[path = "tests/suite/edge_case_tests.rs"]
pub mod edge_case_tests;
#[path = "tests/suite/proptest_consensus.rs"]
pub mod proptest_consensus;
#[path = "tests/suite/proptest_dag.rs"]
pub mod proptest_dag;
#[path = "tests/suite/proptest_safety.rs"]
pub mod proptest_safety;
#[path = "tests/suite/proptest_security.rs"]
pub mod proptest_security;
#[path = "tests/suite/proptest_transactions.rs"]
pub mod proptest_transactions;

// ── Contract lifecycle E2E tests ─────────────────────────────────────
#[path = "tests/suite/contract_e2e_tests.rs"]
pub mod contract_e2e_tests;

// ── Multi-node determinism tests ────────────────────────────────────
#[path = "tests/suite/multi_node_tests.rs"]
pub mod multi_node_tests;

// ── Soak, chaos, and adversarial tests ─────────────────────────────
#[path = "tests/suite/chaos_tests.rs"]
pub mod chaos_tests;
#[path = "tests/suite/soak_tests.rs"]
pub mod soak_tests;
