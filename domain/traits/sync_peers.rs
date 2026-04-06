// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

/// Abstract peer listing for sync operations.
///
/// domain/ defines this trait; service/network implements it.
/// This breaks the engine → service dependency in dag_sync.
pub trait SyncPeers: Send + Sync {
    /// Return addresses of all known peers.
    fn get_peers(&self) -> Vec<String>;
}
