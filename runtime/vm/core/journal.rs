// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// State Journal — Tracks all state changes during contract execution
// so they can be rolled back on REVERT.
//
// Every SSTORE, SDELETE, balance transfer, and log is recorded.
// On success: journal is committed to persistent storage.
// On revert: journal is discarded, all changes undone.
// ═══════════════════════════════════════════════════════════════════════════

/// A single state change entry
#[derive(Debug, Clone)]
pub enum JournalEntry {
    /// Storage slot written: (contract, slot, old_value)
    StorageWrite {
        contract: String,
        slot:     String,
        old_value: Option<String>,
    },
    /// Storage slot deleted: (contract, slot, old_value)
    StorageDelete {
        contract: String,
        slot:     String,
        old_value: Option<String>,
    },
    /// Balance transfer: (from, to, amount)
    BalanceTransfer {
        from:   String,
        to:     String,
        amount: u64,
    },
    /// Log emitted
    LogEmitted {
        contract: String,
        topics:   Vec<[u8; 32]>,
        data:     Vec<u8>,
    },
    /// Contract created
    ContractCreated {
        address:  String,
        code:     Vec<u8>,
    },
    /// Contract self-destructed
    ContractDestroyed {
        address:     String,
        beneficiary: String,
        balance:     u64,
    },
    /// Nonce incremented
    NonceIncrement {
        address: String,
        old_nonce: u64,
    },
}

/// Checkpoint for nested calls (savepoint)
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub journal_len: usize,
    pub gas_used:    u64,
    pub depth:       usize,
}

use crate::errors::VmError;

/// State journal that tracks all changes for rollback
pub struct StateJournal {
    /// All state changes in order
    entries: Vec<JournalEntry>,
    /// Checkpoints for nested calls
    checkpoints: Vec<Checkpoint>,
    /// Current call depth
    depth: usize,
    /// Maximum call depth (prevent stack overflow)
    max_depth: usize,
    /// Total gas refund counter
    gas_refund: u64,
}

impl Default for StateJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl StateJournal {
    pub fn new() -> Self {
        Self {
            entries:     Vec::with_capacity(256),
            checkpoints: Vec::with_capacity(16),
            depth:       0,
            max_depth:   1024,
            gas_refund:  0,
        }
    }

    /// Record a state change
    pub fn record(&mut self, entry: JournalEntry) {
        // Track gas refund for storage deletions
        if matches!(&entry, JournalEntry::StorageDelete { old_value: Some(_), .. }) {
            self.gas_refund += 2_400; // SDELETE refund
        }
        self.entries.push(entry);
    }

    /// Create a checkpoint before a nested CALL
    pub fn checkpoint(&mut self, gas_used: u64) -> Result<usize, VmError> {
        if self.depth >= self.max_depth {
            return Err(VmError::StackOverflow(self.depth));
        }
        let cp = Checkpoint {
            journal_len: self.entries.len(),
            gas_used,
            depth: self.depth,
        };
        let id = self.checkpoints.len();
        self.checkpoints.push(cp);
        self.depth += 1;
        Ok(id)
    }

    /// Commit a checkpoint (nested call succeeded)
    pub fn commit_checkpoint(&mut self, id: usize) {
        if id < self.checkpoints.len() {
            // Remove checkpoint but keep journal entries (they're committed)
            self.checkpoints.truncate(id);
            if self.depth > 0 { self.depth -= 1; }
        }
    }

    /// Revert to a checkpoint (nested call failed)
    /// Returns the journal entries that were rolled back
    pub fn revert_to_checkpoint(&mut self, id: usize) -> Vec<JournalEntry> {
        if id >= self.checkpoints.len() {
            return Vec::new();
        }

        let cp = self.checkpoints[id].clone();
        let reverted = self.entries.split_off(cp.journal_len);

        // Recalculate gas refund
        self.gas_refund = 0;
        for entry in &self.entries {
            if matches!(entry, JournalEntry::StorageDelete { old_value: Some(_), .. }) {
                self.gas_refund += 2_400;
            }
        }

        self.checkpoints.truncate(id);
        if self.depth > 0 { self.depth -= 1; }
        reverted
    }

    /// Revert ALL changes (top-level REVERT)
    pub fn revert_all(&mut self) -> Vec<JournalEntry> {
        let all = std::mem::take(&mut self.entries);
        self.checkpoints.clear();
        self.depth = 0;
        self.gas_refund = 0;
        all
    }

    /// Get all committed entries (for applying to persistent storage)
    pub fn committed_entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// Get the storage writes that need to be applied
    pub fn storage_writes(&self) -> Vec<(&str, &str, &str)> {
        self.entries.iter().filter_map(|e| {
            if let JournalEntry::StorageWrite { contract, slot, .. } = e {
                // We'd need the new value here — this is a simplified view
                Some((contract.as_str(), slot.as_str(), ""))
            } else {
                None
            }
        }).collect()
    }

    /// Get all logs emitted during execution
    pub fn logs(&self) -> Vec<&JournalEntry> {
        self.entries.iter().filter(|e| matches!(e, JournalEntry::LogEmitted { .. })).collect()
    }

    /// Stats
    pub fn entry_count(&self) -> usize { self.entries.len() }
    pub fn checkpoint_count(&self) -> usize { self.checkpoints.len() }
    pub fn current_depth(&self) -> usize { self.depth }
    pub fn gas_refund(&self) -> u64 { self.gas_refund }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_count() {
        let mut j = StateJournal::new();
        j.record(JournalEntry::StorageWrite {
            contract: "c1".into(), slot: "0".into(), old_value: None,
        });
        j.record(JournalEntry::StorageWrite {
            contract: "c1".into(), slot: "1".into(), old_value: Some("old".into()),
        });
        assert_eq!(j.entry_count(), 2);
    }

    #[test]
    fn checkpoint_and_commit() {
        let mut j = StateJournal::new();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "0".into(), old_value: None,
        });
        let cp = j.checkpoint(100).unwrap();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "1".into(), old_value: None,
        });
        j.commit_checkpoint(cp);
        assert_eq!(j.entry_count(), 2); // Both entries kept
    }

    #[test]
    fn checkpoint_and_revert() {
        let mut j = StateJournal::new();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "0".into(), old_value: None,
        });
        let cp = j.checkpoint(100).unwrap();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "1".into(), old_value: None,
        });
        let reverted = j.revert_to_checkpoint(cp);
        assert_eq!(j.entry_count(), 1); // Only first entry kept
        assert_eq!(reverted.len(), 1);  // Second was rolled back
    }

    #[test]
    fn nested_checkpoints() {
        let mut j = StateJournal::new();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "0".into(), old_value: None,
        });
        let cp1 = j.checkpoint(0).unwrap();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "1".into(), old_value: None,
        });
        let cp2 = j.checkpoint(0).unwrap();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "2".into(), old_value: None,
        });

        // Revert inner call
        j.revert_to_checkpoint(cp2);
        assert_eq!(j.entry_count(), 2); // slot 0 and 1

        // Revert outer call
        j.revert_to_checkpoint(cp1);
        assert_eq!(j.entry_count(), 1); // only slot 0
    }

    #[test]
    fn revert_all() {
        let mut j = StateJournal::new();
        for i in 0..10 {
            j.record(JournalEntry::StorageWrite {
                contract: "c".into(), slot: format!("{}", i), old_value: None,
            });
        }
        let all = j.revert_all();
        assert_eq!(all.len(), 10);
        assert_eq!(j.entry_count(), 0);
    }

    #[test]
    fn max_depth_enforced() {
        let mut j = StateJournal::new();
        j.max_depth = 3;
        assert!(j.checkpoint(0).is_ok()); // depth 1
        assert!(j.checkpoint(0).is_ok()); // depth 2
        assert!(j.checkpoint(0).is_ok()); // depth 3
        assert!(j.checkpoint(0).is_err()); // depth 4 = error
    }

    #[test]
    fn gas_refund_tracked() {
        let mut j = StateJournal::new();
        j.record(JournalEntry::StorageDelete {
            contract: "c".into(), slot: "0".into(), old_value: Some("was_here".into()),
        });
        assert_eq!(j.gas_refund(), 2_400);
    }

    #[test]
    fn logs_filtered() {
        let mut j = StateJournal::new();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "0".into(), old_value: None,
        });
        j.record(JournalEntry::LogEmitted {
            contract: "c".into(), topics: vec![], data: vec![1, 2, 3],
        });
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "1".into(), old_value: None,
        });
        assert_eq!(j.logs().len(), 1);
    }

    #[test]
    fn depth_tracking() {
        let mut j = StateJournal::new();
        assert_eq!(j.current_depth(), 0);
        let cp = j.checkpoint(0).unwrap();
        assert_eq!(j.current_depth(), 1);
        j.commit_checkpoint(cp);
        assert_eq!(j.current_depth(), 0);
    }

    #[test]
    fn revert_removes_target_checkpoint() {
        let mut j = StateJournal::new();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "0".into(), old_value: None,
        });
        let cp = j.checkpoint(0).unwrap();
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "1".into(), old_value: None,
        });

        // Revert the nested call — the failed savepoint is removed
        j.revert_to_checkpoint(cp);
        assert_eq!(j.entry_count(), 1); // only slot 0

        // The reverted checkpoint must be removed after rollback
        assert_eq!(j.checkpoint_count(), 0, "reverted checkpoint must be removed after rollback");
    }

    #[test]
    fn revert_removes_target_and_deeper_checkpoints() {
        let mut j = StateJournal::new();
        let cp0 = j.checkpoint(0).unwrap(); // depth 0 → 1
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "0".into(), old_value: None,
        });
        let cp1 = j.checkpoint(0).unwrap(); // depth 1 → 2
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "1".into(), old_value: None,
        });
        let _cp2 = j.checkpoint(0).unwrap(); // depth 2 → 3
        j.record(JournalEntry::StorageWrite {
            contract: "c".into(), slot: "2".into(), old_value: None,
        });

        // Revert to cp1 — should remove cp1 and cp2, keep only cp0
        j.revert_to_checkpoint(cp1);
        assert_eq!(j.checkpoint_count(), 1, "only cp0 must remain");
        assert_eq!(j.entry_count(), 1); // only slot 0 (before cp1)

        // Revert to cp0 — should remove cp0
        j.revert_to_checkpoint(cp0);
        assert_eq!(j.checkpoint_count(), 0, "no checkpoints must remain");
        assert_eq!(j.entry_count(), 0);
    }
}
