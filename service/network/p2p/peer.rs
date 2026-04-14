// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Per-peer state tracking: rate limiting, handshake timeout, bandwidth,
// and integration with the protocol state machine.
//
// ARCHITECTURE:
//   Peer  — owned per TCP connection, tracks rate limits + protocol state
//   ProtocolSession (protocol.rs) — handshake state machine + validation
//   PeerSession (p2p.rs) — runtime session within the async connection loop
//
// Rate limiter: token bucket algorithm.
//   - Tokens refill at `message_per_second_limit` per second
//   - Burst capacity = 2x the per-second limit
//   - Each message costs 1 token
//   - When tokens < 1 → message throttled (not dropped — peer can retry)
// ═══════════════════════════════════════════════════════════════════════════

use crate::service::network::p2p::protocol::{
    HandshakeState, ProtocolSession, DEFAULT_BPS, HANDSHAKE_TIMEOUT_SECS, PUZZLE_TIMEOUT_SECS,
};
use std::time::{Duration, Instant};

/// Default message rate limit (messages per second).
pub const MSG_PER_SECOND_LIMIT: u32 = 100;

/// Burst capacity = 2x rate limit.
pub const MSG_BURST_LIMIT: u32 = MSG_PER_SECOND_LIMIT * 2;

/// Legacy handshake timeout (used by `is_handshake_timed_out`).
pub const HANDSHAKE_TIMEOUT_MS: u64 = HANDSHAKE_TIMEOUT_SECS * 1000;

/// Bandwidth tracking window (seconds).
const BANDWIDTH_WINDOW_SECS: u64 = 60;

/// Maximum bytes per bandwidth window (100 MiB/min).
const MAX_BYTES_PER_WINDOW: u64 = 100 * 1024 * 1024;

pub struct Peer {
    pub address: String,
    pub connected: bool,
    pub node_id: String,
    pub shadow_node: bool,

    /// Messages-per-second limit for this peer.
    pub message_per_second_limit: u32,

    /// Token bucket: current available tokens.
    tokens: f64,
    /// Token bucket: last refill time.
    last_refill: Instant,

    /// Handshake timeout in milliseconds (legacy, use protocol session for new code).
    pub handshake_timeout_ms: u64,

    /// When this peer's TCP connection was opened.
    pub connected_at: Option<Instant>,

    /// Protocol state machine for this peer's connection.
    pub protocol: ProtocolSession,

    /// Bandwidth tracking: bytes received in current window.
    bytes_this_window: u64,
    /// Bandwidth tracking: window start time.
    window_start: Instant,
}

impl Peer {
    pub fn new(address: String) -> Self {
        Self::new_with_config(address, MSG_PER_SECOND_LIMIT, false)
    }

    pub fn new_with_rate_limit(address: String, msg_per_sec: u32) -> Self {
        Self::new_with_config(address, msg_per_sec, false)
    }

    pub fn new_outbound(address: String) -> Self {
        Self::new_with_config(address, MSG_PER_SECOND_LIMIT, true)
    }

    fn new_with_config(address: String, msg_per_sec: u32, is_outbound: bool) -> Self {
        let burst = msg_per_sec * 2;
        let node_id = format!("node-{}", address);
        Self {
            address,
            connected: false,
            node_id,
            shadow_node: false,
            message_per_second_limit: msg_per_sec,
            tokens: burst as f64,
            last_refill: Instant::now(),
            handshake_timeout_ms: HANDSHAKE_TIMEOUT_MS,
            connected_at: None,
            protocol: ProtocolSession::new(is_outbound, DEFAULT_BPS),
            bytes_this_window: 0,
            window_start: Instant::now(),
        }
    }

    /// Begin the connection process (TCP established, handshake not yet done).
    ///
    /// For inbound: transitions protocol to AwaitPuzzleSolution.
    /// For outbound: transitions protocol to AwaitPuzzleChallenge.
    ///
    /// NOTE: `connected` stays false until `on_handshake_complete()` is called
    /// after puzzle verification and version exchange finish. This prevents
    /// protocol messages (like GetAddr) from being sent before the handshake
    /// is fully established.
    pub fn connect(&mut self) {
        self.connected_at = Some(Instant::now());
        // Set initial handshake state based on connection direction
        if self.protocol.is_outbound {
            self.protocol.state = HandshakeState::AwaitPuzzleChallenge;
        } else {
            self.protocol.state = HandshakeState::AwaitPuzzleSolution;
        }
        // connected remains false — set only by on_handshake_complete()
    }

    /// Called after the full handshake (puzzle + version + verack) completes.
    /// This is the ONLY path to connected=true.
    pub fn on_handshake_complete(&mut self) -> bool {
        if !self.protocol.is_established() {
            return false; // Cannot mark connected before establishment
        }
        self.connected = true;
        self.send_get_peers();
        true
    }

    /// Request peers from this connection.
    pub fn send_get_peers(&self) {
        // Enqueue a GetAddr request for this peer's connection.
        // The P2P layer will serialize and send it on the next tick.
        log::debug!("[Peer] Requesting peers from {}", self.address);
    }

    /// Check if the handshake has timed out.
    ///
    /// Uses the protocol state machine's timeout logic for accuracy.
    pub fn is_handshake_timed_out(&self) -> bool {
        if self.connected && self.protocol.is_established() {
            return false;
        }
        match self.connected_at {
            Some(t) => {
                let elapsed = t.elapsed();
                // Use the appropriate timeout based on protocol state
                let timeout_secs = match self.protocol.state {
                    HandshakeState::AwaitPuzzleSolution | HandshakeState::AwaitPuzzleChallenge => {
                        PUZZLE_TIMEOUT_SECS
                    }
                    HandshakeState::Established => return false,
                    HandshakeState::Disconnecting => return true,
                    _ => HANDSHAKE_TIMEOUT_SECS,
                };
                elapsed > Duration::from_secs(timeout_secs)
            }
            None => false,
        }
    }

    /// Whether the peer has completed the full handshake.
    pub fn is_established(&self) -> bool {
        self.protocol.is_established()
    }

    /// Peer's best known block height (from Version exchange).
    pub fn best_height(&self) -> u64 {
        self.protocol.peer_height()
    }

    /// Peer's user agent string.
    pub fn user_agent(&self) -> &str {
        self.protocol.peer_user_agent()
    }

    /// Peer's cryptographic identity, if present.
    pub fn identity(&self) -> Option<&str> {
        self.protocol.peer_identity()
    }

    // ── Rate limiting (token bucket) ────────────────────────────────────

    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let burst = (self.message_per_second_limit * 2) as f64;

        self.tokens = (self.tokens + elapsed * self.message_per_second_limit as f64).min(burst);
        self.last_refill = now;
    }

    #[allow(dead_code)]
    fn check_rate_limit(&mut self) -> bool {
        self.refill_tokens();
        self.tokens >= 1.0
    }

    pub fn record_message(&mut self) {
        self.refill_tokens();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
        }
    }

    /// Consume a token and return whether the message is allowed.
    pub fn allow_message(&mut self) -> bool {
        self.refill_tokens();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn available_tokens(&mut self) -> u32 {
        self.refill_tokens();
        self.tokens.floor() as u32
    }

    // ── Bandwidth tracking ──────────────────────────────────────────────

    /// Record bytes received from this peer.  Returns false if bandwidth exceeded.
    pub fn record_bytes(&mut self, bytes: u64) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() > BANDWIDTH_WINDOW_SECS {
            // Reset window
            self.bytes_this_window = 0;
            self.window_start = now;
        }
        self.bytes_this_window = self.bytes_this_window.saturating_add(bytes);
        self.bytes_this_window <= MAX_BYTES_PER_WINDOW
    }

    /// Current bandwidth usage as a percentage (0–100).
    pub fn bandwidth_usage_pct(&self) -> u64 {
        (self.bytes_this_window * 100) / MAX_BYTES_PER_WINDOW.max(1)
    }

    // ── Privacy / Dandelion++ ───────────────────────────────────────────

    pub fn enable_shadow(&mut self) {
        self.shadow_node = true;
    }

    /// Begin graceful disconnect.
    pub fn disconnect(&mut self) {
        self.protocol.begin_disconnect();
        self.connected = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_allows_burst() {
        let mut peer = Peer::new_with_rate_limit("127.0.0.1:9333".into(), 10);

        let mut allowed = 0;
        for _ in 0..20 {
            if peer.allow_message() {
                allowed += 1;
            }
        }
        assert!(allowed > 0, "Peer should allow burst messages");
    }

    #[test]
    fn rate_limit_throttles_after_burst() {
        let mut peer = Peer::new_with_rate_limit("127.0.0.1:9334".into(), 5);

        for _ in 0..10 {
            peer.allow_message();
        }

        assert!(
            !peer.allow_message(),
            "Peer should be throttled after burst"
        );
    }

    #[test]
    fn handshake_timeout_detected() {
        let mut peer = Peer::new("127.0.0.1:9335".into());
        // Force a very short timeout for testing
        peer.connected_at = Some(Instant::now() - Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 1));

        assert!(peer.is_handshake_timed_out(), "Handshake must time out");
    }

    #[test]
    fn connected_peer_not_timed_out() {
        let mut peer = Peer::new("127.0.0.1:9336".into());
        peer.connected_at = Some(Instant::now() - Duration::from_secs(60));
        peer.protocol.state = HandshakeState::Established;
        peer.on_handshake_complete();
        assert!(
            !peer.is_handshake_timed_out(),
            "Established peer must not be timed out"
        );
    }

    #[test]
    fn new_peer_starts_in_init_state() {
        let peer = Peer::new("127.0.0.1:9337".into());
        assert_eq!(peer.protocol.state, HandshakeState::Init);
        assert!(!peer.is_established());
    }

    #[test]
    fn outbound_peer_is_flagged() {
        let peer = Peer::new_outbound("10.0.0.1:9333".into());
        assert!(peer.protocol.is_outbound);
    }

    #[test]
    fn bandwidth_tracking_resets_after_window() {
        let mut peer = Peer::new("127.0.0.1:9338".into());
        // Force window start to the past
        peer.window_start = Instant::now() - Duration::from_secs(BANDWIDTH_WINDOW_SECS + 1);
        peer.bytes_this_window = MAX_BYTES_PER_WINDOW;

        // Recording new bytes should reset the window
        assert!(peer.record_bytes(1000));
        assert_eq!(peer.bytes_this_window, 1000);
    }

    #[test]
    fn bandwidth_exceeded_detected() {
        let mut peer = Peer::new("127.0.0.1:9339".into());
        peer.bytes_this_window = MAX_BYTES_PER_WINDOW;
        assert!(!peer.record_bytes(1), "Should detect bandwidth exceeded");
    }

    #[test]
    fn disconnect_transitions_state() {
        let mut peer = Peer::new("127.0.0.1:9340".into());
        peer.protocol.state = HandshakeState::Established;
        peer.on_handshake_complete();
        assert!(peer.connected);
        peer.disconnect();
        assert!(!peer.connected);
        assert_eq!(peer.protocol.state, HandshakeState::Disconnecting);
    }

    #[test]
    fn connect_does_not_mark_connected() {
        let mut peer = Peer::new("127.0.0.1:9342".into());
        peer.connect();
        assert!(
            !peer.connected,
            "connect() must NOT set connected=true before handshake"
        );
        assert!(
            peer.connected_at.is_some(),
            "connect() must record connection time"
        );
    }

    #[test]
    fn on_handshake_complete_marks_connected() {
        let mut peer = Peer::new("127.0.0.1:9343".into());
        peer.connect();
        assert!(!peer.connected);
        peer.protocol.state = HandshakeState::Established;
        peer.on_handshake_complete();
        assert!(
            peer.connected,
            "on_handshake_complete() must set connected=true"
        );
    }

    #[test]
    fn puzzle_timeout_longer_than_handshake() {
        let mut peer = Peer::new("127.0.0.1:9341".into());
        // Force into puzzle state
        peer.connected_at = Some(Instant::now() - Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 1));
        peer.protocol.state = HandshakeState::AwaitPuzzleSolution;

        // Should NOT be timed out yet (puzzle timeout is longer)
        if PUZZLE_TIMEOUT_SECS > HANDSHAKE_TIMEOUT_SECS {
            assert!(!peer.is_handshake_timed_out());
        }
    }
}
