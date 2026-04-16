// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#![warn(dead_code)]
#![allow(clippy::module_inception)]
#![warn(unused_variables, unused_imports, unused_mut)]

pub mod errors;

pub mod daemon;

pub mod sdk {
    pub mod shadowdag_sdk;
}

pub mod config {
    pub mod consensus {
        pub mod consensus_params;
        pub mod emission_schedule;
        pub mod mempool_config;
    }
    pub mod genesis {
        pub mod genesis;
    }
    pub mod network {
        pub mod bootstrap_nodes;
        pub mod network_params;
    }
    pub mod checkpoints;
    pub mod node {
        pub mod node_config;
        pub mod node_roles;
    }
}

pub mod domain {
    pub mod address {
        pub mod address;
        pub mod invisible_wallet;
        pub mod key_derivation;
        pub mod stealth_address;
    }
    pub mod block {
        pub mod block;
        pub mod block_body;
        pub mod block_builder;
        pub mod block_header;
        pub mod block_rules;
        pub mod merkle_proof;
        pub mod merkle_tree;
        pub mod merkle_verifier;
    }
    pub mod transaction {
        pub mod decoy_transaction;
        pub mod transaction;
        pub mod tx_builder;
        pub mod tx_fee;
        pub mod tx_hash;
        pub mod tx_receipt;
        pub mod tx_validator;
    }
    pub mod types {
        pub mod amount;
        pub mod difficulty;
        pub mod hash;
        pub mod peer_address;
        pub mod timestamp;
    }
    pub mod utxo {
        pub mod utxo;
        pub mod utxo_key;
        pub mod utxo_set;
        pub mod utxo_snapshot;
        pub mod utxo_spend;
        pub mod utxo_validator;
    }
    pub mod traits {
        pub mod block_processor;
        pub mod content_hasher;
        pub mod peer_info;
        pub mod pow_checker;
        pub mod sync_peers;
        pub mod tx_pool;
        pub mod utxo_backend;
    }
}

pub mod engine {
    pub mod consensus {
        pub mod core {
            pub mod consensus;
            pub mod consensus_manager;
            pub mod fork_choice;
        }
        pub mod difficulty {
            pub mod difficulty;
            pub mod difficulty_adjustment;
            pub mod difficulty_window;
            pub mod retarget;
        }
        pub mod rewards {
            pub mod developer_reward;
            pub mod emission;
            pub mod miner_reward;
            pub mod reward;
        }
        pub mod validation {
            pub mod block_context;
            pub mod block_validator;
            pub mod consensus_validator;
        }
        pub mod block_processor;
        pub mod chain_manager;
        pub mod finality;
        pub mod reorg;
        pub mod state;
    }
    pub mod crypto {
        pub mod hash {
            pub mod blake3;
            pub mod keccak;
            pub mod muhash;
            pub mod sha3;
            pub mod shadowhash;
        }
        pub mod keys {
            pub mod keypair;
            pub mod private_key;
            pub mod public_key;
        }
        pub mod random {
            pub mod csprng;
            pub mod entropy;
        }
        pub mod signatures {
            pub mod dilithium;
            pub mod ed25519;
            pub mod falcon;
            pub mod schnorr;
        }
        pub mod serialization;
    }
    pub mod dag {
        pub mod core {
            pub mod block_graph;
            pub mod bps_engine;
            pub mod dag;
            pub mod dag_manager;
            pub mod dag_state;
        }
        pub mod ghostdag {
            pub mod blue_set;
            pub mod ghostdag;
            pub mod ordering;
            pub mod red_set;
        }
        pub mod security {
            pub mod dag_shield;
            pub mod dos_protection;
            pub mod flood_protection;
            pub mod selfish_mining_guard;
            pub mod spam_filter;
        }
        pub mod sync {
            pub mod block_locator;
            pub mod dag_sync;
            pub mod header_sync;
        }
        pub mod validation {
            pub mod conflict_detector;
            pub mod dag_validator;
            pub mod parent_validator;
        }
        pub mod tips {
            pub mod tip_manager;
        }
        pub mod simulator {
            pub mod network_simulator;
        }
        pub mod conflicts;
        pub mod traversal;
    }
    pub mod mining {
        pub mod algorithms {
            pub mod anti_asic;
            pub mod hash_mix;
            pub mod shadowhash;
        }
        pub mod gpu {
            pub mod cuda_miner;
            pub mod gpu_miner;
            pub mod opencl_miner;
        }
        pub mod miner {
            pub mod block_template;
            pub mod fair_ordering;
            pub mod miner;
            pub mod miner_controller;
            pub mod miner_stats;
        }
        pub mod pow {
            pub mod pow_difficulty;
            pub mod pow_engine;
            pub mod pow_validator;
        }
        pub mod stratum {
            pub mod stratum_server;
        }
    }
    pub mod privacy {
        pub mod confidential {
            pub mod bulletproofs;
            pub mod confidential_tx;
            pub mod pedersen;
            pub mod pedersen_commitment;
            pub mod range_proof;
        }
        pub mod ringct {
            pub mod clsag;
            pub mod key_image;
            pub mod ring_builder;
            pub mod ring_signature;
            pub mod ring_validator;
        }
        pub mod shadow_pool {
            pub mod mixer;
            pub mod pool_manager;
            pub mod shadow_pool;
            pub mod shadow_transaction;
        }
        pub mod stealth {
            pub mod stealth_address;
            pub mod stealth_scanner;
            pub mod view_key;
        }
    }
    pub mod anti_double_spend;
    pub mod orphans;
    pub mod pruning;
    pub mod state_snapshot;
    pub mod tx_validation;
    // Swap and DEX modules — wired into consensus via TxType::SwapTx
    // and TxType::DexOrder. Validation rules in block_validator.rs and
    // mempool.rs enforce payload, fee, and structural requirements.
    pub mod swap {
        pub mod atomic_swap;
    }
    pub mod dex {
        pub mod order_book;
    }
}

pub mod infrastructure {
    pub mod storage {
        pub mod rocksdb {
            pub mod blocks {
                pub mod block_index;
                pub mod block_store;
                pub mod header_store;
            }
            pub mod core {
                pub mod column_families;
                pub mod db;
                pub mod disk_monitor;
                pub mod migrations;
            }
            pub mod dag {
                pub mod dag_index;
                pub mod dag_store;
            }
            pub mod transactions {
                pub mod tx_index;
                pub mod tx_store;
            }
            pub mod utxo {
                pub mod utxo_index;
                pub mod utxo_store;
            }
            pub mod peers {
                pub mod peer_store;
            }
            pub mod state {
                pub mod state_store;
            }
        }
    }
}

pub mod runtime {
    pub mod event_bus {
        pub mod event_bus;
        pub mod event_dispatcher;
        pub mod event_types;
    }
    pub mod node_runtime {
        pub mod lifecycle;
        pub mod runtime;
        pub mod runtime_manager;
    }
    pub mod scheduler {
        pub mod async_runtime;
        pub mod task_scheduler;
    }
    pub mod vm {
        pub mod contracts {
            pub mod build_manifest;
            pub mod contract;
            pub mod contract_abi;
            pub mod contract_deployer;
            pub mod contract_package;
            pub mod contract_storage;
            pub mod contract_verifier;
            pub mod deployment_manifest;
            pub mod token_standard;
        }
        pub mod core {
            pub mod assembler;
            pub mod call_stack;
            pub mod event_log;
            pub mod execution_env;
            pub mod execution_result;
            pub mod execution_trace;
            pub mod executor;
            pub mod journal;
            pub mod memory;
            pub mod opcodes;
            pub mod source_map;
            pub mod state_manager;
            pub mod u256;
            pub mod v1_spec;
            pub mod vm;
            pub mod vm_address;
            pub mod vm_context;
        }
        pub mod gas {
            pub mod gas_meter;
            pub mod gas_rules;
        }
        pub mod testing {
            pub mod invariant_checker;
            pub mod observability;
            pub mod script_runner;
            pub mod test_runner;
        }
        pub mod precompiles {
            pub mod crypto_precompiles;
            pub mod hash_precompiles;
            pub mod math_precompiles;
            pub mod precompile_registry;
        }
    }
    pub mod wasm {
        pub mod sdk;
    }
}

pub mod service {
    pub mod mempool {
        pub mod core {
            pub mod mempool;
            pub mod mempool_manager;
            pub mod rbf;
        }
        pub mod fees {
            pub mod base_fee;
            pub mod fee_market;
            pub mod tx_prioritizer;
        }
        pub mod pools {
            pub mod orphan_pool;
            pub mod tx_pool;
        }
        pub mod eviction;
        pub mod index;
    }
    pub mod network {
        pub mod discovery {
            pub mod dns_seeds;
            pub mod peer_discovery;
        }
        pub mod nodes {
            pub mod boot;
            pub mod full_node;
            pub mod light_node;
            pub mod shadow_node;
        }
        pub mod p2p {
            pub mod connection_puzzle;
            pub mod message;
            pub mod p2p;
            pub mod peer;
            pub mod peer_diversity;
            pub mod peer_manager;
            pub mod protocol;
        }
        pub mod relay {
            pub mod block_relay;
            pub mod compact_block;
            pub mod inv_relay;
            pub mod tx_relay;
        }
        pub mod rpc {
            pub mod grpc_server;
            pub mod health;
            pub mod rpc_server;
            pub mod ws_server;
        }
        pub mod address_manager;
        pub mod block_sync;
        pub mod bootstrap;
        pub mod connection_manager;
        pub mod dos_guard;
        pub mod gossip;
        pub mod propagation;
        pub mod rate_limiter;
        pub mod reputation;
        pub mod sync;
        pub mod sync_engine;
        pub mod protocol {
            pub mod messages;
        }
        pub mod contract_ide;
        pub mod explorer;
    }
    pub mod wallet {
        pub mod core {
            pub mod wallet;
            pub mod wallet_manager;
            pub mod wallet_sync;
        }
        pub mod keys {
            pub mod hardware_wallet;
            pub mod hd_wallet;
            pub mod key_manager;
            pub mod multisig;
        }
        pub mod storage {
            pub mod address_book;
            pub mod wallet_db;
        }
    }
    pub mod events;
    pub mod security {
        pub mod dos_protection;
    }
    pub mod rpc {
        pub mod auth;
    }
}

pub mod indexes {
    pub mod explorer;
    pub mod receipt_index;
    pub mod tx_index;
    pub mod utxo_index;
}

pub mod cache {
    pub mod block_cache;
}

pub mod metrics;

pub mod storage;

pub mod telemetry {
    pub mod logging {
        pub mod log_config;
        pub mod logger;
        pub mod structured;
    }
    pub mod metrics {
        pub mod metrics;
        pub mod prometheus;
        pub mod registry;
    }
    pub mod tracing {
        pub mod tracing;
    }
    pub mod diagnostics;
}

#[cfg(test)]
pub mod tests;
