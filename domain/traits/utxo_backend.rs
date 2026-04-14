// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::utxo::utxo::Utxo;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::errors::StorageError;

/// A single write operation in an atomic batch.
///
/// Used by `UtxoBackend::write_batch()` to group multiple key-value
/// mutations into a single atomic commit. Either all operations in the
/// batch succeed, or none do — this is critical for consensus safety.
pub enum BatchWrite {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

/// Abstract UTXO storage backend.
///
/// domain/ defines this trait; infrastructure/storage implements it.
/// This breaks the domain → infrastructure dependency.
///
/// All typed UTXO operations use `UtxoKey` (36-byte canonical binary key).
/// Raw key-value access uses `&[u8]` for metadata (undo data, commitments).
/// The `write_batch()` method ensures atomicity across multiple writes.
pub trait UtxoBackend: Send + Sync {
    // ── Typed UTXO operations (binary key) ──────────────────────────
    fn add_utxo(&self, key: &UtxoKey, utxo: &Utxo) -> Result<(), StorageError>;
    fn get_utxo(&self, key: &UtxoKey) -> Result<Option<Utxo>, StorageError>;
    fn spend_utxo(&self, key: &UtxoKey) -> Result<(), StorageError>;
    fn exists(&self, key: &UtxoKey) -> Result<bool, StorageError>;
    fn get_balance(&self, address: &str) -> Result<u64, StorageError>;
    fn count_utxos(&self) -> usize;
    fn clear_all(&self);

    // ── Raw key-value access (for undo data, commitments, metadata) ──
    fn get_raw(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn put_raw(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    fn delete_raw(&self, key: &[u8]) -> Result<(), StorageError>;

    // ── Bulk export ─────────────────────────────────────────────────
    /// Export all unspent UTXOs as (key, Utxo) pairs.
    /// Used by commitment hashing and crash recovery.
    fn export_all(&self) -> Result<Vec<(UtxoKey, Utxo)>, StorageError>;

    // ── Atomic batch writes ──────────────────────────────────────────
    /// Write multiple operations atomically — all succeed or all fail.
    /// Critical for consensus: UTXO changes + undo data + commitments
    /// must be committed together.
    fn write_batch(&self, ops: Vec<BatchWrite>) -> Result<(), StorageError>;

    // ── Maintenance ─────────────────────────────────────────────────
    /// Prune spent UTXOs to reclaim storage. Returns count pruned.
    fn prune_spent(&self) -> Result<u64, StorageError> {
        Ok(0)
    }

    /// Compact underlying storage after pruning
    fn compact(&self) {}
}
