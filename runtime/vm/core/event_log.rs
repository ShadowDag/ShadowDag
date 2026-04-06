// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Event Log — LOG0-LOG4 system for emitting indexed events from contracts.
//
// Events are stored in transaction receipts and can be filtered by:
//   - Contract address
//   - Topics (indexed parameters)
//   - Block range
//
// Gas cost: 375 base + 375 per topic + 8 per data byte
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};
use crate::errors::VmError;

/// Gas costs for LOG operations
pub const LOG_BASE_GAS: u64 = 375;
pub const LOG_TOPIC_GAS: u64 = 375;
pub const LOG_DATA_BYTE_GAS: u64 = 8;

/// Maximum topics per event (LOG0-LOG4)
pub const MAX_TOPICS: usize = 4;

/// Maximum data size per event (16 KB)
pub const MAX_LOG_DATA: usize = 16_384;

/// A single log entry emitted by a contract
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    /// Contract address that emitted this log
    pub address: String,
    /// Indexed topics (0-4, each is 32 bytes hex-encoded)
    pub topics: Vec<String>,
    /// Non-indexed data (arbitrary bytes, hex-encoded)
    pub data: String,
    /// Block height when emitted
    pub block_height: u64,
    /// Transaction hash that produced this log
    pub tx_hash: String,
    /// Index of this log within the transaction
    pub log_index: u32,
}

impl LogEntry {
    /// Calculate gas cost for this log entry
    pub fn gas_cost(&self) -> u64 {
        let data_bytes = self.data.len() as u64 / 2; // hex-encoded, 2 chars per byte
        LOG_BASE_GAS
            .saturating_add((self.topics.len() as u64).saturating_mul(LOG_TOPIC_GAS))
            .saturating_add(data_bytes.saturating_mul(LOG_DATA_BYTE_GAS))
    }
}

/// Accumulator for logs during contract execution
pub struct EventCollector {
    logs: Vec<LogEntry>,
    contract_address: String,
    tx_hash: String,
    block_height: u64,
    log_counter: u32,
    total_gas: u64,
}

impl EventCollector {
    pub fn new(contract_address: String, tx_hash: String, block_height: u64) -> Self {
        Self {
            logs: Vec::with_capacity(32),
            contract_address,
            tx_hash,
            block_height,
            log_counter: 0,
            total_gas: 0,
        }
    }

    /// Emit a LOG0 (no topics)
    pub fn log0(&mut self, data: &[u8]) -> Result<u64, VmError> {
        self.emit(vec![], data)
    }

    /// Emit a LOG1 (1 topic)
    pub fn log1(&mut self, topic0: &str, data: &[u8]) -> Result<u64, VmError> {
        self.emit(vec![topic0.to_string()], data)
    }

    /// Emit a LOG2 (2 topics)
    pub fn log2(&mut self, topic0: &str, topic1: &str, data: &[u8]) -> Result<u64, VmError> {
        self.emit(vec![topic0.to_string(), topic1.to_string()], data)
    }

    /// Emit a LOG3 (3 topics)
    pub fn log3(&mut self, t0: &str, t1: &str, t2: &str, data: &[u8]) -> Result<u64, VmError> {
        self.emit(vec![t0.to_string(), t1.to_string(), t2.to_string()], data)
    }

    /// Emit a LOG4 (4 topics)
    pub fn log4(&mut self, t0: &str, t1: &str, t2: &str, t3: &str, data: &[u8]) -> Result<u64, VmError> {
        self.emit(vec![t0.to_string(), t1.to_string(), t2.to_string(), t3.to_string()], data)
    }

    /// Core emit function
    fn emit(&mut self, topics: Vec<String>, data: &[u8]) -> Result<u64, VmError> {
        if topics.len() > MAX_TOPICS {
            return Err(VmError::Other(format!("too many topics: {} (max {})", topics.len(), MAX_TOPICS)));
        }

        if data.len() > MAX_LOG_DATA {
            return Err(VmError::Other(format!("log data too large: {} bytes (max {})", data.len(), MAX_LOG_DATA)));
        }

        let entry = LogEntry {
            address: self.contract_address.clone(),
            topics,
            data: hex::encode(data),
            block_height: self.block_height,
            tx_hash: self.tx_hash.clone(),
            log_index: self.log_counter,
        };

        let gas = entry.gas_cost();
        self.total_gas = self.total_gas.saturating_add(gas);
        self.log_counter += 1;
        self.logs.push(entry);

        Ok(gas)
    }

    /// Get all collected logs
    pub fn logs(&self) -> &[LogEntry] {
        &self.logs
    }

    /// Take ownership of logs (consumes collector)
    pub fn into_logs(self) -> Vec<LogEntry> {
        self.logs
    }

    /// Total gas used for all log operations
    pub fn total_gas_used(&self) -> u64 {
        self.total_gas
    }

    /// Number of logs emitted
    pub fn count(&self) -> usize {
        self.logs.len()
    }
}

/// Filter for querying logs
#[derive(Debug, Clone)]
pub struct LogFilter {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub addresses: Vec<String>,
    pub topics: Vec<Option<String>>, // None = wildcard
}

impl LogFilter {
    pub fn matches(&self, entry: &LogEntry) -> bool {
        // Block range check
        if let Some(from) = self.from_block {
            if entry.block_height < from { return false; }
        }
        if let Some(to) = self.to_block {
            if entry.block_height > to { return false; }
        }

        // Address check
        if !self.addresses.is_empty() && !self.addresses.contains(&entry.address) {
            return false;
        }

        // Topic check
        for (i, filter_topic) in self.topics.iter().enumerate() {
            if let Some(expected) = filter_topic {
                match entry.topics.get(i) {
                    Some(actual) if actual == expected => {}
                    _ => return false,
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log0_basic() {
        let mut ec = EventCollector::new("0xContract".into(), "0xTx".into(), 100);
        let gas = ec.log0(b"hello").unwrap();
        assert!(gas > 0);
        assert_eq!(ec.count(), 1);
        assert_eq!(ec.logs()[0].topics.len(), 0);
    }

    #[test]
    fn log2_with_topics() {
        let mut ec = EventCollector::new("0xC".into(), "0xT".into(), 50);
        ec.log2("Transfer", "0xFrom", b"data").unwrap();
        assert_eq!(ec.logs()[0].topics.len(), 2);
        assert_eq!(ec.logs()[0].topics[0], "Transfer");
    }

    #[test]
    fn gas_cost_scales_with_topics() {
        let mut ec = EventCollector::new("a".into(), "t".into(), 1);
        let g0 = ec.log0(b"x").unwrap();

        let mut ec2 = EventCollector::new("a".into(), "t".into(), 1);
        let g1 = ec2.log1("topic", b"x").unwrap();

        assert!(g1 > g0);
        assert_eq!(g1 - g0, LOG_TOPIC_GAS);
    }

    #[test]
    fn filter_matches_block_range() {
        let entry = LogEntry {
            address: "0xA".into(), topics: vec![], data: String::new(),
            block_height: 50, tx_hash: "tx".into(), log_index: 0,
        };

        let filter = LogFilter {
            from_block: Some(40), to_block: Some(60),
            addresses: vec![], topics: vec![],
        };
        assert!(filter.matches(&entry));

        let filter2 = LogFilter {
            from_block: Some(60), to_block: Some(100),
            addresses: vec![], topics: vec![],
        };
        assert!(!filter2.matches(&entry));
    }

    #[test]
    fn max_data_enforced() {
        let mut ec = EventCollector::new("a".into(), "t".into(), 1);
        let big_data = vec![0u8; MAX_LOG_DATA + 1];
        assert!(ec.log0(&big_data).is_err());
    }
}
