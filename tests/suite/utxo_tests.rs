// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::domain::utxo::utxo_set::UtxoSet;

    #[test]
    fn add_and_get_utxo() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx1:0", 500, "alice");
        let utxo = set.get_utxo_str("tx1:0");
        assert!(utxo.is_some());
        let u = utxo.unwrap();
        assert_eq!(u.amount, 500);
        assert_eq!(u.owner, "alice");
        assert!(!u.spent);
    }

    #[test]
    fn missing_utxo_returns_none() {
        let set = UtxoSet::new_empty();
        assert!(set.get_utxo_str("nonexistent:0").is_none());
    }

    #[test]
    fn spend_marks_utxo_as_spent() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx2:0", 100, "bob");
        set.spend_utxo_str("tx2:0").unwrap();
        let utxo = set.get_utxo_str("tx2:0").unwrap();
        assert!(utxo.spent, "utxo should be marked as spent");
    }

    #[test]
    fn double_spend_detected_after_first_spend() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx3:0", 200, "carol");
        set.spend_utxo_str("tx3:0").unwrap();

        let utxo = set.get_utxo_str("tx3:0").unwrap();
        assert!(utxo.spent, "Already-spent utxo must be detectable");
    }

    #[test]
    fn balance_sum_excludes_spent() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx4:0", 300, "dave");
        set.add_test_utxo("tx4:1", 200, "dave");
        set.spend_utxo_str("tx4:0").unwrap();
        let balance = set.get_balance("dave");
        assert_eq!(balance, 200, "Balance should exclude spent utxos");
    }
}
