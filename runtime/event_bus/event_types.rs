// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub enum EventType {
    BlockAdded,
    BlockRejected,
    TransactionAdded,
    TransactionRejected,
    PeerConnected,
    PeerDisconnected,
    MiningStarted,
    BlockMined,
    SyncStarted,
    SyncCompleted,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
