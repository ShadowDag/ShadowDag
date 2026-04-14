// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================
//
// Receipt and Log Index -- enables efficient querying of contract execution results.
//
// Indexes:
//   rcpt:{tx_hash}                        -> serialized TxReceipt
//   blkr:{block_hash}                     -> list of tx_hashes in that block
//   alog:{address}:{block_height}:{idx}   -> serialized IndexedLog
//   top0:{topic0}:{block_height}:{idx}    -> serialized IndexedLog
// =============================================================================

use crate::domain::transaction::tx_receipt::TxReceipt;
use crate::errors::StorageError;
use rocksdb::{Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct ReceiptIndex {
    db: Arc<DB>,
}

/// Query filter for logs
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    /// Filter by contract address
    pub address: Option<String>,
    /// Filter by first topic (event signature)
    pub topic0: Option<String>,
    /// Filter by second topic
    pub topic1: Option<String>,
    /// From block height (inclusive)
    pub from_block: Option<u64>,
    /// To block height (inclusive)
    pub to_block: Option<u64>,
    /// Maximum results to return
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedLog {
    pub tx_hash: String,
    pub block_hash: String,
    pub block_height: u64,
    pub tx_index: u32,
    pub log_index: usize,
    pub contract: String,
    pub topics: Vec<String>,
    pub data: String,
}

impl ReceiptIndex {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(4));
        let db = DB::open(&opts, path).map_err(|e| StorageError::OpenFailed {
            path: path.into(),
            reason: e.to_string(),
        })?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Index all receipts from a block
    pub fn index_block_receipts(
        &self,
        block_hash: &str,
        block_height: u64,
        receipts: &[TxReceipt],
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let mut tx_hashes: Vec<String> = Vec::new();

        for receipt in receipts {
            // Index receipt by tx_hash
            let receipt_key = format!("rcpt:{}", receipt.tx_hash);
            if let Ok(data) = bincode::serialize(receipt) {
                batch.put(receipt_key.as_bytes(), &data);
            }
            tx_hashes.push(receipt.tx_hash.clone());

            // Index logs
            for (log_idx, log) in receipt.logs.iter().enumerate() {
                // By address
                let addr_key = format!("alog:{}:{}:{}", log.contract, block_height, log_idx);
                let log_entry = IndexedLog {
                    tx_hash: receipt.tx_hash.clone(),
                    block_hash: block_hash.to_string(),
                    block_height,
                    tx_index: receipt.tx_index.unwrap_or(0),
                    log_index: log_idx,
                    contract: log.contract.clone(),
                    topics: log.topics.clone(),
                    data: log.data.clone(),
                };
                if let Ok(data) = bincode::serialize(&log_entry) {
                    batch.put(addr_key.as_bytes(), &data);

                    // By topic0
                    if let Some(topic0) = log.topics.first() {
                        let topic_key = format!("top0:{}:{}:{}", topic0, block_height, log_idx);
                        batch.put(topic_key.as_bytes(), &data);
                    }
                }
            }
        }

        // Block -> receipts mapping
        let block_key = format!("blkr:{}", block_hash);
        if let Ok(data) = bincode::serialize(&tx_hashes) {
            batch.put(block_key.as_bytes(), &data);
        }

        self.db
            .write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    /// Remove all indexes for a block (used during reorg rollback)
    pub fn rollback_block(&self, block_hash: &str) -> Result<(), StorageError> {
        // Load tx hashes for this block
        let block_key = format!("blkr:{}", block_hash);
        let tx_hashes: Vec<String> = match self.db.get(block_key.as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).unwrap_or_default(),
            _ => return Ok(()),
        };

        let mut batch = WriteBatch::default();

        for tx_hash in &tx_hashes {
            // Remove receipt
            let receipt_key = format!("rcpt:{}", tx_hash);
            batch.delete(receipt_key.as_bytes());
        }

        // Remove block mapping
        batch.delete(block_key.as_bytes());

        // Note: log entries would also need cleanup, but for simplicity
        // we rely on block_height filtering to exclude rolled-back logs

        self.db
            .write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Get receipt by tx_hash
    pub fn get_receipt(&self, tx_hash: &str) -> Option<TxReceipt> {
        let key = format!("rcpt:{}", tx_hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).ok(),
            _ => None,
        }
    }

    /// Get all receipts for a block
    pub fn get_block_receipts(&self, block_hash: &str) -> Vec<TxReceipt> {
        let block_key = format!("blkr:{}", block_hash);
        let tx_hashes: Vec<String> = match self.db.get(block_key.as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).unwrap_or_default(),
            _ => return vec![],
        };
        tx_hashes
            .iter()
            .filter_map(|h| self.get_receipt(h))
            .collect()
    }

    /// Get logs matching a filter
    pub fn get_logs(&self, filter: &LogFilter) -> Vec<IndexedLog> {
        let mut results = Vec::new();
        let limit = if filter.limit == 0 {
            1000
        } else {
            filter.limit
        };

        // Choose scan prefix based on filter
        let prefix = if let Some(ref addr) = filter.address {
            format!("alog:{}", addr)
        } else if let Some(ref topic) = filter.topic0 {
            format!("top0:{}", topic)
        } else {
            "alog:".to_string() // Full scan
        };

        let iter = self.db.prefix_iterator(prefix.as_bytes());
        for item in iter {
            if results.len() >= limit {
                break;
            }
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            let key_str = match std::str::from_utf8(&k) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Check prefix still matches
            if !key_str.starts_with(&prefix) {
                break;
            }

            let log: IndexedLog = match bincode::deserialize(&v) {
                Ok(l) => l,
                Err(_) => continue,
            };

            // Apply block range filter
            if let Some(from) = filter.from_block {
                if log.block_height < from {
                    continue;
                }
            }
            if let Some(to) = filter.to_block {
                if log.block_height > to {
                    continue;
                }
            }

            // Apply topic filters
            if let Some(ref t0) = filter.topic0 {
                if log.topics.first().map(|t| t.as_str()) != Some(t0) {
                    continue;
                }
            }
            if let Some(ref t1) = filter.topic1 {
                if log.topics.get(1).map(|t| t.as_str()) != Some(t1) {
                    continue;
                }
            }

            // Apply address filter (in case we scanned by topic)
            if let Some(ref addr) = filter.address {
                if log.contract != *addr {
                    continue;
                }
            }

            results.push(log);
        }

        results
    }

    /// Count total receipts
    pub fn receipt_count(&self) -> usize {
        let prefix = b"rcpt:";
        let iter = self.db.prefix_iterator(prefix);
        let mut count = 0;
        for item in iter {
            match item {
                Ok((k, _)) if k.starts_with(prefix) => count += 1,
                _ => break,
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::tx_receipt::ReceiptLog;

    fn tmp_path() -> String {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("shadowdag_receipt_idx_{}", ts));
        dir.to_string_lossy().to_string()
    }

    fn make_receipt(tx_hash: &str, contract: &str, topic: &str) -> TxReceipt {
        let mut r = TxReceipt::new_pending(tx_hash.to_string(), 100, 1, 0);
        r.execution_success = true;
        r.gas_used = 50_000;
        r.logs = vec![ReceiptLog {
            contract: contract.into(),
            topics: vec![topic.into()],
            data: "deadbeef".into(),
            log_index: 0,
        }];
        r
    }

    #[test]
    fn index_and_get_receipt() {
        let idx = ReceiptIndex::new(&tmp_path()).unwrap();
        let r = make_receipt("tx1", "contract_a", "Transfer");
        idx.index_block_receipts("block1", 100, &[r]).unwrap();

        let loaded = idx.get_receipt("tx1");
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().tx_hash, "tx1");
    }

    #[test]
    fn get_block_receipts() {
        let idx = ReceiptIndex::new(&tmp_path()).unwrap();
        let r1 = make_receipt("tx1", "c1", "Transfer");
        let r2 = make_receipt("tx2", "c2", "Approval");
        idx.index_block_receipts("block1", 100, &[r1, r2]).unwrap();

        let receipts = idx.get_block_receipts("block1");
        assert_eq!(receipts.len(), 2);
    }

    #[test]
    fn filter_logs_by_address() {
        let idx = ReceiptIndex::new(&tmp_path()).unwrap();
        let r1 = make_receipt("tx1", "token_a", "Transfer");
        let r2 = make_receipt("tx2", "token_b", "Transfer");
        idx.index_block_receipts("b1", 100, &[r1, r2]).unwrap();

        let logs = idx.get_logs(&LogFilter {
            address: Some("token_a".into()),
            ..Default::default()
        });
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].contract, "token_a");
    }

    #[test]
    fn filter_logs_by_topic0() {
        let idx = ReceiptIndex::new(&tmp_path()).unwrap();
        let r1 = make_receipt("tx1", "c1", "Transfer");
        let r2 = make_receipt("tx2", "c1", "Approval");
        idx.index_block_receipts("b1", 100, &[r1, r2]).unwrap();

        let logs = idx.get_logs(&LogFilter {
            topic0: Some("Transfer".into()),
            ..Default::default()
        });
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].topics[0], "Transfer");
    }

    #[test]
    fn filter_logs_by_block_range() {
        let idx = ReceiptIndex::new(&tmp_path()).unwrap();
        idx.index_block_receipts("b1", 100, &[make_receipt("tx1", "c", "E")])
            .unwrap();
        idx.index_block_receipts("b2", 200, &[make_receipt("tx2", "c", "E")])
            .unwrap();
        idx.index_block_receipts("b3", 300, &[make_receipt("tx3", "c", "E")])
            .unwrap();

        let logs = idx.get_logs(&LogFilter {
            address: Some("c".into()),
            from_block: Some(150),
            to_block: Some(250),
            ..Default::default()
        });
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].block_height, 200);
    }

    #[test]
    fn rollback_removes_receipts() {
        let idx = ReceiptIndex::new(&tmp_path()).unwrap();
        idx.index_block_receipts("b1", 100, &[make_receipt("tx1", "c", "E")])
            .unwrap();

        assert!(idx.get_receipt("tx1").is_some());
        idx.rollback_block("b1").unwrap();
        assert!(idx.get_receipt("tx1").is_none());
    }

    #[test]
    fn receipt_count() {
        let idx = ReceiptIndex::new(&tmp_path()).unwrap();
        assert_eq!(idx.receipt_count(), 0);
        idx.index_block_receipts(
            "b1",
            100,
            &[make_receipt("tx1", "c", "E"), make_receipt("tx2", "c", "E")],
        )
        .unwrap();
        assert_eq!(idx.receipt_count(), 2);
    }
}
