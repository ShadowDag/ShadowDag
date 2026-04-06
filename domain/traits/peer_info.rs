// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

/// Abstract peer information.
///
/// domain/ defines this trait; service/network implements it.
/// This breaks any domain → service/network dependency.
pub trait PeerInfo: Send + Sync {
    fn peer_id(&self) -> &str;
    fn address(&self) -> &str;
    fn is_banned(&self) -> bool;
}
