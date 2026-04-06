// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch};
use std::path::Path;
use crate::domain::transaction::transaction::Transaction;
use crate::errors::StorageError;

pub struct TxStore {
    db: DB,
}

impl TxStore {
    pub fn new(path: &str) -> Option<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(32 * 1024 * 1024);
        match DB::open(&opts, Path::new(path)) {
            Ok(db) => Some(Self { db }),
            Err(_e) => {
                None
            }
        }
    }

    pub fn new_required(path: &str) -> Result<Self, StorageError> {
        Self::new(path).ok_or_else(|| {
            StorageError::OpenFailed {
                path: path.to_string(),
                reason: "cannot open DB — check permissions and disk space".to_string(),
            }
        })
    }

    pub fn save_tx(&self, tx: &Transaction) -> bool {
        match bincode::serialize(tx) {
            Ok(data) => {
                match self.db.put(tx.hash.as_bytes(), &data) {
                    Ok(_)  => true,
                    Err(_e) => {
                        false
                    }
                }
            }
            Err(_e) => {
                false
            }
        }
    }

    pub fn get_tx(&self, hash: &str) -> Option<Transaction> {
        match self.db.get(hash.as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).ok(),
            Ok(None)       => None,
            Err(_e)         => {
                None
            }
        }
    }

    pub fn tx_exists(&self, hash: &str) -> bool {
        match self.db.get(hash.as_bytes()) {
            Ok(Some(_)) => true,
            Ok(None)    => false,
            Err(_e)      => {
                false
            }
        }
    }

    pub fn save_batch(&self, txs: &[Transaction]) -> bool {
        let mut batch = WriteBatch::default();
        for tx in txs {
            match bincode::serialize(tx) {
                Ok(data) => batch.put(tx.hash.as_bytes(), &data),
                Err(_e) => {
                    return false;
                }
            }
        }
        match self.db.write(batch) {
            Ok(_)  => true,
            Err(_e) => {
                false
            }
        }
    }

    pub fn delete_tx(&self, hash: &str) -> bool {
        match self.db.delete(hash.as_bytes()) {
            Ok(_)  => true,
            Err(_e) => {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput};

    fn tmp_path() -> String {
        format!(
            "/tmp/test_tx_store_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    fn make_tx(hash: &str) -> Transaction {
        Transaction::new(
            hash.to_string(),
            vec![],
            vec![TxOutput::new("addr1".into(), 100)],
            10,
            1000,
        )
    }

    #[test]
    fn save_and_get_tx_roundtrip() {
        let store = TxStore::new(&tmp_path()).expect("open TxStore");
        let tx = make_tx("tx_abc");

        assert!(store.save_tx(&tx));

        let loaded = store.get_tx("tx_abc").expect("tx should exist");
        assert_eq!(loaded.hash, "tx_abc");
        assert_eq!(loaded.fee, 10);
        assert_eq!(loaded.outputs.len(), 1);
        assert_eq!(loaded.outputs[0].amount, 100);
    }

    #[test]
    fn get_returns_none_for_unknown_tx() {
        let store = TxStore::new(&tmp_path()).expect("open TxStore");

        assert!(store.get_tx("nonexistent").is_none());
    }

    #[test]
    fn tx_exists_check() {
        let store = TxStore::new(&tmp_path()).expect("open TxStore");
        let tx = make_tx("exists_check");

        assert!(!store.tx_exists("exists_check"));
        store.save_tx(&tx);
        assert!(store.tx_exists("exists_check"));
        assert!(!store.tx_exists("no_such_tx"));
    }
}
