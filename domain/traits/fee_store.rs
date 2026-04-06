// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

/// Abstract fee storage.
///
/// domain/ defines this trait; infrastructure/ implements it.
/// This breaks the domain → infrastructure dependency for fee persistence.
pub trait FeeStore: Send + Sync {
    fn store_fee(&self, txid: &str, fee: u64);
    fn get_fee(&self, txid: &str) -> Option<u64>;
}
