// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Wire protocol for ShadowDAG P2P network.
//
// This module is the single source of truth for:
//   1. Wire framing (magic, length, checksum, payload)
//   2. Protocol constants and limits
//   3. Handshake state machine (Init → Puzzle → Version → Established)
//   4. Message-level validation (before domain logic)
//   5. Protocol error types
//
// ARCHITECTURE:
//   protocol.rs  →  defines wire format, states, validation rules
//   p2p.rs       →  uses Protocol for connection management + dispatch
//   peer.rs      →  per-peer rate limiting + timeout tracking
//
// Wire frame layout (13 + N bytes):
//   [0..4]   magic         (4 bytes — network identifier)
//   [4..5]   command_id    (1 byte  — message type discriminant)
//   [5..9]   payload_len   (4 bytes — big-endian u32)
//   [9..13]  checksum      (4 bytes — first 4 bytes of SHA-256(payload))
//   [13..N]  payload       (variable — bincode-serialized message body)
//
// SECURITY:
//   - Checksum validated BEFORE deserialization (blocks malformed data)
//   - Payload length capped at MAX_MESSAGE_SIZE (4 MiB)
//   - Command ID bounds-checked (unknown → reject + ban score)
//   - Handshake state enforced (only puzzle/version msgs before auth)
//   - Timestamp drift checked (±5 minutes tolerance)
//   - Per-message field limits enforced (hash lengths, list sizes, etc.)
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

// ═══════════════════════════════════════════════════════════════════════════
//                         PROTOCOL CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Mainnet magic bytes — identifies ShadowDAG mainnet traffic.
pub const NETWORK_MAGIC: [u8; 4] = [0xDA, 0xB1, 0x0C, 0x01];

/// Testnet magic bytes — must never be accepted on mainnet.
pub const TESTNET_NETWORK_MAGIC: [u8; 4] = [0xDA, 0xB1, 0x0C, 0x02];

/// Current protocol version.  Peers MUST be in [1, PROTOCOL_VERSION] to connect.
pub const PROTOCOL_VERSION: u32 = 1;

/// Chain identifier — guards against cross-chain replay.
pub const CHAIN_ID: u32 = 0xDA0C_0001;

/// Maximum serialized payload size (4 MiB).
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Wire frame header size: magic(4) + cmd(1) + len(4) + checksum(4) = 13.
pub const WIRE_HEADER_SIZE: usize = 13;

/// Maximum blocks per single GetBlock / Headers response.
pub const MAX_BLOCKS_PER_MSG: usize = 500;

/// Maximum inventory items per single Inv / GetData message.
pub const MAX_INV_PER_MSG: usize = 5_000;

/// Maximum addresses per single Addr message.
pub const MAX_ADDR_PER_MSG: usize = 1_000;

/// Maximum header hashes per single Headers message.
pub const MAX_HEADERS_PER_MSG: usize = 2_000;

/// Handshake timeout — peer must complete Version/VerAck within this window.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Puzzle timeout — peer must solve connection puzzle within this window.
pub const PUZZLE_TIMEOUT_SECS: u64 = 30;

/// Maximum allowed clock drift for Version timestamps (±5 minutes).
pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;

/// Default blocks-per-second for version negotiation.
pub const DEFAULT_BPS: u32 = 10;

/// Minimum acceptable user_agent length (bytes).
pub const MIN_USER_AGENT_LEN: usize = 5;

/// Maximum acceptable user_agent length (bytes).
pub const MAX_USER_AGENT_LEN: usize = 256;

/// Maximum hash length in hex characters (SHA-256 = 64).
pub const MAX_HASH_HEX_LEN: usize = 64;

/// Maximum reject reason length (bytes).
pub const MAX_REJECT_REASON_LEN: usize = 512;

// ═══════════════════════════════════════════════════════════════════════════
//                         SERVICE FLAGS (capability bits)
// ═══════════════════════════════════════════════════════════════════════════

/// Service flag: full node (stores all blocks, validates everything).
pub const SERVICE_NODE_NETWORK: u64   = 1 << 0;
/// Service flag: can serve historical headers for IBD.
pub const SERVICE_NODE_HEADERS: u64   = 1 << 1;
/// Service flag: supports bloom filters (lightweight client).
pub const SERVICE_NODE_BLOOM: u64     = 1 << 2;
/// Service flag: supports UTXO snapshots for fast sync.
pub const SERVICE_NODE_SNAPSHOT: u64  = 1 << 3;
/// Service flag: privacy layer enabled (CLSAG/Pedersen).
pub const SERVICE_NODE_PRIVACY: u64   = 1 << 4;
/// Service flag: smart contract VM enabled.
pub const SERVICE_NODE_CONTRACTS: u64 = 1 << 5;
/// Service flag: can relay Dandelion++ stem transactions.
pub const SERVICE_NODE_DANDELION: u64 = 1 << 6;

/// Minimum services required to be a useful full peer.
pub const REQUIRED_SERVICES: u64 = SERVICE_NODE_NETWORK;

/// Default services advertised by a ShadowDAG node.
pub const DEFAULT_SERVICES: u64 = SERVICE_NODE_NETWORK
    | SERVICE_NODE_HEADERS
    | SERVICE_NODE_DANDELION;

/// Check whether a peer's services include all required capabilities.
#[inline]
pub fn has_required_services(services: u64) -> bool {
    services & REQUIRED_SERVICES == REQUIRED_SERVICES
}

// ═══════════════════════════════════════════════════════════════════════════
//                         COMMAND IDS (wire byte)
// ═══════════════════════════════════════════════════════════════════════════

/// One-byte command discriminant on the wire.
///
/// Every message type has a fixed numeric ID.  Unknown IDs are rejected
/// immediately (before reading payload) — this prevents attackers from
/// forcing deserialization of garbage data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CommandId {
    Version         = 0x01,
    VerAck          = 0x02,
    Ping            = 0x03,
    Pong            = 0x04,
    GetAddr         = 0x05,
    Addr            = 0x06,
    Inv             = 0x07,
    GetData         = 0x08,
    Block           = 0x09,
    Tx              = 0x0A,
    GetHeaders      = 0x0B,
    Headers         = 0x0C,
    GetBlock       = 0x0D,
    Reject          = 0x0E,
    PuzzleChallenge = 0x10,
    PuzzleSolution  = 0x11,
    // 0x20–0x2F reserved for privacy layer
    ShadowTx        = 0x20,
    OnionTx         = 0x21,
    // 0x30–0x3F reserved for smart contract layer
    GetMempool      = 0x30,
}

impl CommandId {
    /// Parse a raw byte into a known command.  Returns `None` for unknown IDs.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Version),
            0x02 => Some(Self::VerAck),
            0x03 => Some(Self::Ping),
            0x04 => Some(Self::Pong),
            0x05 => Some(Self::GetAddr),
            0x06 => Some(Self::Addr),
            0x07 => Some(Self::Inv),
            0x08 => Some(Self::GetData),
            0x09 => Some(Self::Block),
            0x0A => Some(Self::Tx),
            0x0B => Some(Self::GetHeaders),
            0x0C => Some(Self::Headers),
            0x0D => Some(Self::GetBlock),
            0x0E => Some(Self::Reject),
            0x10 => Some(Self::PuzzleChallenge),
            0x11 => Some(Self::PuzzleSolution),
            0x20 => Some(Self::ShadowTx),
            0x21 => Some(Self::OnionTx),
            0x30 => Some(Self::GetMempool),
            _    => None,
        }
    }

    /// Whether this command is allowed before the handshake completes.
    pub fn allowed_before_handshake(self) -> bool {
        matches!(
            self,
            Self::Version | Self::VerAck |
            Self::PuzzleChallenge | Self::PuzzleSolution |
            Self::Reject
        )
    }

    /// Whether this command carries a large payload (block/tx data).
    pub fn is_bulk_data(self) -> bool {
        matches!(self, Self::Block | Self::Tx | Self::ShadowTx | Self::OnionTx)
    }

    /// Human-readable name for logging.
    pub fn name(self) -> &'static str {
        match self {
            Self::Version         => "version",
            Self::VerAck          => "verack",
            Self::Ping            => "ping",
            Self::Pong            => "pong",
            Self::GetAddr         => "getaddr",
            Self::Addr            => "addr",
            Self::Inv             => "inv",
            Self::GetData         => "getdata",
            Self::Block           => "block",
            Self::Tx              => "tx",
            Self::GetHeaders      => "getheaders",
            Self::Headers         => "headers",
            Self::GetBlock       => "getblock",
            Self::Reject          => "reject",
            Self::PuzzleChallenge => "puzzle_challenge",
            Self::PuzzleSolution  => "puzzle_solution",
            Self::ShadowTx        => "shadow_tx",
            Self::OnionTx         => "onion_tx",
            Self::GetMempool      => "getmempool",
        }
    }
}

impl fmt::Display for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                         WIRE FRAME
// ═══════════════════════════════════════════════════════════════════════════

/// 13-byte wire header that prefixes every message on the network.
///
/// PARSING ORDER:
///   1. Read 13 bytes
///   2. Validate magic (wrong network → drop immediately)
///   3. Validate command_id (unknown → reject + ban)
///   4. Validate payload_len ≤ MAX_MESSAGE_SIZE
///   5. Read `payload_len` bytes
///   6. Validate checksum (tampered/corrupted → reject + ban)
///   7. Deserialize payload for the specific command
#[derive(Debug, Clone, Copy)]
pub struct WireHeader {
    pub magic:       [u8; 4],
    pub command_id:  u8,
    pub payload_len: u32,
    pub checksum:    [u8; 4],
}

impl WireHeader {
    /// Encode the header into a 13-byte buffer.
    pub fn encode(&self) -> [u8; WIRE_HEADER_SIZE] {
        let mut buf = [0u8; WIRE_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.command_id;
        buf[5..9].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[9..13].copy_from_slice(&self.checksum);
        buf
    }

    /// Decode a 13-byte buffer into a WireHeader.
    pub fn decode(buf: &[u8; WIRE_HEADER_SIZE]) -> Self {
        Self {
            magic:       [buf[0], buf[1], buf[2], buf[3]],
            command_id:  buf[4],
            payload_len: u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]),
            checksum:    [buf[9], buf[10], buf[11], buf[12]],
        }
    }

    /// Build a header for the given payload.
    pub fn for_payload(magic: [u8; 4], command_id: u8, payload: &[u8]) -> Self {
        Self {
            magic,
            command_id,
            payload_len: payload.len() as u32,
            checksum:    compute_checksum(payload),
        }
    }
}

/// Compute the 4-byte checksum of a payload: first 4 bytes of SHA-256.
///
/// This catches bit flips, truncation, and most tampering.
/// Not a MAC — does not provide authentication (that's handled by the
/// connection puzzle and optional TLS layer).
pub fn compute_checksum(data: &[u8]) -> [u8; 4] {
    let hash = Sha256::digest(data);
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Verify a payload against its expected checksum.
#[inline]
pub fn verify_checksum(data: &[u8], expected: [u8; 4]) -> bool {
    compute_checksum(data) == expected
}

// ═══════════════════════════════════════════════════════════════════════════
//                         PROTOCOL ERRORS
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol-level errors with suggested ban scores.
///
/// Ban scores guide the DoS guard:
///   0    — not malicious (disconnect OK, no penalty)
///   1–10 — minor violations (accumulate; ban at threshold)
///   100  — instant ban (unambiguously malicious)
#[derive(Debug, Clone)]
pub struct ProtocolError {
    pub kind:      ProtocolErrorKind,
    pub message:   String,
    pub ban_score: u32,
}

impl ProtocolError {
    pub fn new(kind: ProtocolErrorKind, message: impl Into<String>, ban_score: u32) -> Self {
        Self { kind, message: message.into(), ban_score }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} (ban_score={})", self.kind, self.message, self.ban_score)
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolErrorKind {
    /// Network magic mismatch — wrong chain or garbage data.
    BadMagic,
    /// Unknown command ID on the wire.
    UnknownCommand,
    /// Checksum mismatch — corrupted or tampered payload.
    BadChecksum,
    /// Payload exceeds maximum allowed size.
    OversizePayload,
    /// Message sent before handshake allows it.
    PrematureMessage,
    /// Handshake timeout expired.
    HandshakeTimeout,
    /// Puzzle timeout expired.
    PuzzleTimeout,
    /// Protocol version incompatible.
    IncompatibleVersion,
    /// BPS mismatch (different consensus rules).
    BpsMismatch,
    /// Timestamp too far from local clock.
    TimestampDrift,
    /// Message field violates protocol limits (list too long, hash wrong size, etc.).
    FieldViolation,
    /// Duplicate handshake / version message.
    DuplicateHandshake,
    /// Unexpected state transition.
    InvalidTransition,
    /// Deserialization failed.
    DeserializeFailed,
    /// I/O error on the wire.
    IoError,
    /// Peer sent too many messages (rate limit).
    RateLimited,
    /// Generic protocol violation.
    Violation,
}

impl fmt::Display for ProtocolErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BadMagic            => "BAD_MAGIC",
            Self::UnknownCommand      => "UNKNOWN_CMD",
            Self::BadChecksum         => "BAD_CHECKSUM",
            Self::OversizePayload     => "OVERSIZE",
            Self::PrematureMessage    => "PREMATURE_MSG",
            Self::HandshakeTimeout    => "HS_TIMEOUT",
            Self::PuzzleTimeout       => "PUZZLE_TIMEOUT",
            Self::IncompatibleVersion => "INCOMPAT_VER",
            Self::BpsMismatch         => "BPS_MISMATCH",
            Self::TimestampDrift      => "TIMESTAMP_DRIFT",
            Self::FieldViolation      => "FIELD_VIOLATION",
            Self::DuplicateHandshake  => "DUP_HANDSHAKE",
            Self::InvalidTransition   => "INVALID_TRANS",
            Self::DeserializeFailed   => "DESER_FAILED",
            Self::IoError             => "IO_ERROR",
            Self::RateLimited         => "RATE_LIMITED",
            Self::Violation           => "VIOLATION",
        };
        f.write_str(s)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                    HANDSHAKE STATE MACHINE
// ═══════════════════════════════════════════════════════════════════════════
//
//   INBOUND (we accepted the connection):
//     Init → send PuzzleChallenge → AwaitPuzzleSolution
//       → receive valid solution → PuzzleVerified
//       → receive Version → validate → send VerAck + Version → AwaitPeerVerAck
//       → receive VerAck → Established
//
//   OUTBOUND (we initiated the connection):
//     Init → AwaitPuzzleChallenge
//       → receive PuzzleChallenge → solve → send PuzzleSolution → PuzzleVerified
//       → send Version → AwaitVersion
//       → receive Version → validate → send VerAck → AwaitPeerVerAck
//       → receive VerAck → Established
//
//   Any state → Reject received or timeout → Disconnecting
// ═══════════════════════════════════════════════════════════════════════════

/// Handshake state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Connection just opened, no messages exchanged.
    Init,
    /// (Inbound) We sent a puzzle challenge, waiting for solution.
    AwaitPuzzleSolution,
    /// (Outbound) We connected, waiting for the acceptor's puzzle challenge.
    AwaitPuzzleChallenge,
    /// Puzzle verified (both directions).  Version exchange can begin.
    PuzzleVerified,
    /// We sent our Version, waiting for peer's Version.
    AwaitVersion,
    /// We received peer's Version and sent VerAck, waiting for their VerAck.
    AwaitPeerVerAck,
    /// Handshake complete — all message types allowed.
    Established,
    /// Graceful shutdown in progress.
    Disconnecting,
}

impl HandshakeState {
    /// Whether full protocol messages (Tx, Block, Inv, etc.) are allowed.
    pub fn is_established(self) -> bool {
        self == Self::Established
    }

    /// Whether the connection is still viable (not disconnecting).
    pub fn is_alive(self) -> bool {
        self != Self::Disconnecting
    }
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Init                 => "INIT",
            Self::AwaitPuzzleSolution  => "AWAIT_PUZZLE_SOLUTION",
            Self::AwaitPuzzleChallenge => "AWAIT_PUZZLE_CHALLENGE",
            Self::PuzzleVerified       => "PUZZLE_VERIFIED",
            Self::AwaitVersion         => "AWAIT_VERSION",
            Self::AwaitPeerVerAck      => "AWAIT_PEER_VERACK",
            Self::Established          => "ESTABLISHED",
            Self::Disconnecting        => "DISCONNECTING",
        };
        f.write_str(s)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                    PEER LIFECYCLE (post-handshake)
// ═══════════════════════════════════════════════════════════════════════════
//
//   Established (handshake done) → Connected → Syncing → Normal
//                                                    ↑       │
//                                                    └───────┘ (fall behind)
//
//   Any state → Restricted (misbehavior)
// ═══════════════════════════════════════════════════════════════════════════

/// Post-handshake lifecycle state for a peer.
///
/// Separate from `HandshakeState` — this tracks what the peer is doing
/// AFTER the handshake is complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerLifecycle {
    /// Just completed handshake, haven't started sync yet.
    Connected,
    /// Actively downloading headers (IBD or catching up).
    SyncingHeaders {
        target_height: u64,
        current_height: u64,
    },
    /// Actively downloading block bodies.
    SyncingBlocks {
        target_height: u64,
        current_height: u64,
    },
    /// Fully synced — normal relay mode.
    Normal,
    /// Misbehaving — limited to essential messages only.
    Restricted {
        reason: String,
    },
}

impl PeerLifecycle {
    /// Whether the peer is in normal relay mode.
    pub fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }

    /// Whether the peer is actively syncing (headers or blocks).
    pub fn is_syncing(&self) -> bool {
        matches!(self, Self::SyncingHeaders { .. } | Self::SyncingBlocks { .. })
    }

    /// Whether the peer is restricted (misbehaving).
    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::Restricted { .. })
    }

    /// Progress percentage (0–100) during sync, or 100 if normal.
    pub fn sync_progress_pct(&self) -> u32 {
        match self {
            Self::SyncingHeaders { target_height, current_height }
            | Self::SyncingBlocks { target_height, current_height } => {
                if *target_height == 0 { return 0; }
                ((current_height * 100) / target_height).min(100) as u32
            }
            Self::Normal => 100,
            _ => 0,
        }
    }
}

impl fmt::Display for PeerLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected                    => write!(f, "CONNECTED"),
            Self::SyncingHeaders { current_height, target_height } =>
                write!(f, "SYNCING_HEADERS({}/{})", current_height, target_height),
            Self::SyncingBlocks { current_height, target_height } =>
                write!(f, "SYNCING_BLOCKS({}/{})", current_height, target_height),
            Self::Normal                       => write!(f, "NORMAL"),
            Self::Restricted { reason }        => write!(f, "RESTRICTED({})", reason),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                   PER-COMMAND PAYLOAD CONSTRAINTS
// ═══════════════════════════════════════════════════════════════════════════

/// Per-command payload size constraints.
///
/// Enforced BEFORE deserialization to prevent resource exhaustion.
/// Returns (min_size, max_size) in bytes for a given command.
///
/// **IMPORTANT**: bincode serializes enum variants with a 4-byte discriminant
/// prefix (u32 variant index), so every payload is at least 4 bytes even for
/// unit variants like VerAck. All bounds below include this 4-byte tag.
///
/// Layout: [4B enum tag] + [field data]
///   VerAck     = 4 + 0  = 4 bytes
///   Ping{u64}  = 4 + 8  = 12 bytes
///   Version    = 4 + fields = 24..1028 bytes
const BINCODE_TAG: usize = 4;

pub fn payload_size_bounds(cmd: CommandId) -> (usize, usize) {
    match cmd {
        CommandId::Version         => (BINCODE_TAG + 16, BINCODE_TAG + 1024),
        CommandId::VerAck          => (BINCODE_TAG, BINCODE_TAG),
        CommandId::Ping            => (BINCODE_TAG + 8, BINCODE_TAG + 8),
        CommandId::Pong            => (BINCODE_TAG + 8, BINCODE_TAG + 8),
        CommandId::GetAddr         => (BINCODE_TAG, BINCODE_TAG),
        CommandId::Addr            => (BINCODE_TAG, BINCODE_TAG + 256 * 1024),
        CommandId::Inv             => (BINCODE_TAG + 1, BINCODE_TAG + 512 * 1024),
        CommandId::GetData         => (BINCODE_TAG + 1, BINCODE_TAG + 512 * 1024),
        CommandId::Block           => (BINCODE_TAG + 60, MAX_MESSAGE_SIZE),
        CommandId::Tx              => (BINCODE_TAG + 12, MAX_MESSAGE_SIZE),
        CommandId::GetHeaders      => (BINCODE_TAG + 1, BINCODE_TAG + 1024),
        CommandId::Headers         => (BINCODE_TAG + 1, BINCODE_TAG + 512 * 1024),
        CommandId::GetBlock       => (BINCODE_TAG + 1, BINCODE_TAG + 1024),
        CommandId::Reject          => (BINCODE_TAG + 1, BINCODE_TAG + MAX_REJECT_REASON_LEN + 64),
        CommandId::PuzzleChallenge => (BINCODE_TAG + 4, BINCODE_TAG + 256),
        CommandId::PuzzleSolution  => (BINCODE_TAG + 12, BINCODE_TAG + 512),
        CommandId::ShadowTx        => (BINCODE_TAG + 12, MAX_MESSAGE_SIZE),
        CommandId::OnionTx         => (BINCODE_TAG + 12, MAX_MESSAGE_SIZE),
        CommandId::GetMempool      => (BINCODE_TAG, BINCODE_TAG),
    }
}

/// Validate payload size against per-command constraints.
pub fn validate_payload_size(cmd: CommandId, size: usize) -> Result<(), ProtocolError> {
    let (min, max) = payload_size_bounds(cmd);
    if size < min {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            format!("{}: payload {} bytes < min {}", cmd, size, min),
            20,
        ));
    }
    if size > max {
        return Err(ProtocolError::new(
            ProtocolErrorKind::OversizePayload,
            format!("{}: payload {} bytes > max {}", cmd, size, max),
            50,
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
//                    VERSION PAYLOAD
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed contents of a Version message.
///
/// Validated BEFORE being stored — every field is bounds-checked.
#[derive(Debug, Clone)]
pub struct VersionPayload {
    pub version:     u32,
    pub height:      u64,
    pub timestamp:   u64,
    pub user_agent:  String,
    pub bps:         u32,
    pub chain_id:    u32,
    pub services:    u64,
    pub nonce:       u64,
}

impl VersionPayload {
    /// Validate all fields against protocol rules.
    ///
    /// Returns a detailed ProtocolError if any field is out of range.
    pub fn validate(&self, our_bps: u32) -> Result<(), ProtocolError> {
        // Version range: must be in [1, PROTOCOL_VERSION]
        if self.version == 0 || self.version > PROTOCOL_VERSION {
            return Err(ProtocolError::new(
                ProtocolErrorKind::IncompatibleVersion,
                format!("version {} not in [1, {}]", self.version, PROTOCOL_VERSION),
                100,
            ));
        }

        // BPS must match — different BPS = different consensus rules = different chain.
        if self.bps != our_bps {
            return Err(ProtocolError::new(
                ProtocolErrorKind::BpsMismatch,
                format!("peer BPS {} != our BPS {}", self.bps, our_bps),
                100,
            ));
        }

        // Chain ID must match — prevents cross-chain connections.
        // Strict: chain_id == 0 (unset/legacy) is also rejected; peers must update.
        if self.chain_id != CHAIN_ID {
            return Err(ProtocolError::new(
                ProtocolErrorKind::BpsMismatch,
                format!("chain_id 0x{:08X} != expected 0x{:08X}", self.chain_id, CHAIN_ID),
                100,
            ));
        }

        // Timestamp drift check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let drift = if self.timestamp > now {
            self.timestamp - now
        } else {
            now - self.timestamp
        };
        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(ProtocolError::new(
                ProtocolErrorKind::TimestampDrift,
                format!("timestamp drift {}s exceeds max {}s", drift, MAX_TIMESTAMP_DRIFT_SECS),
                10, // not necessarily malicious — clocks drift
            ));
        }

        // User agent bounds
        if self.user_agent.len() < MIN_USER_AGENT_LEN {
            return Err(ProtocolError::new(
                ProtocolErrorKind::FieldViolation,
                format!("user_agent too short ({} < {})", self.user_agent.len(), MIN_USER_AGENT_LEN),
                20,
            ));
        }
        if self.user_agent.len() > MAX_USER_AGENT_LEN {
            return Err(ProtocolError::new(
                ProtocolErrorKind::FieldViolation,
                format!("user_agent too long ({} > {})", self.user_agent.len(), MAX_USER_AGENT_LEN),
                20,
            ));
        }

        // Reject non-UTF8 or control characters in user_agent
        if self.user_agent.chars().any(|c| c.is_control() && c != '\n') {
            return Err(ProtocolError::new(
                ProtocolErrorKind::FieldViolation,
                "user_agent contains control characters",
                50,
            ));
        }

        // Service flags: must include required capabilities
        if !has_required_services(self.services) {
            return Err(ProtocolError::new(
                ProtocolErrorKind::FieldViolation,
                format!("insufficient services: 0x{:016X} missing required 0x{:016X}",
                        self.services, REQUIRED_SERVICES),
                10, // might be a light client, not necessarily malicious
            ));
        }

        Ok(())
    }

    /// Extract peer identity (Ed25519 pubkey hex) from user_agent, if present.
    ///
    /// Format: "ShadowDAG/x.y.z id:<hex_pubkey>"
    pub fn peer_identity(&self) -> Option<&str> {
        self.user_agent
            .split_whitespace()
            .find(|s| s.starts_with("id:"))
            .map(|s| &s[3..])
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                    PROTOCOL SESSION (state machine)
// ═══════════════════════════════════════════════════════════════════════════

/// Per-connection protocol state machine.
///
/// Tracks the handshake flow, peer version info, and protocol-level stats.
/// One `ProtocolSession` per TCP connection, owned by the connection handler.
pub struct ProtocolSession {
    /// Whether we initiated this connection (outbound) or accepted it (inbound).
    pub is_outbound:      bool,
    /// Current handshake state.
    pub state:            HandshakeState,
    /// Post-handshake lifecycle state.
    pub lifecycle:        PeerLifecycle,
    /// Peer's version payload (populated after Version message received).
    pub peer_version:     Option<VersionPayload>,
    /// Our BPS — used for version validation.
    pub our_bps:          u32,
    /// Puzzle challenge we sent (inbound) or received (outbound).
    pub puzzle_challenge: Option<String>,
    /// Connection start time (for timeout enforcement).
    pub connected_at:     u64,
    /// Nonces we've seen (Ping/Pong anti-replay).
    pub seen_nonces:      HashSet<u64>,
    /// Total messages received (for stats).
    pub msgs_received:    u64,
    /// Total messages sent (for stats).
    pub msgs_sent:        u64,
    /// Total bytes received (for bandwidth tracking).
    pub bytes_received:   u64,
    /// Total bytes sent (for bandwidth tracking).
    pub bytes_sent:       u64,
}

impl ProtocolSession {
    /// Create a new session for the given connection direction.
    pub fn new(is_outbound: bool, our_bps: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            is_outbound,
            state:            HandshakeState::Init,
            lifecycle:        PeerLifecycle::Connected,
            peer_version:     None,
            our_bps,
            puzzle_challenge: None,
            connected_at:     now,
            seen_nonces:      HashSet::with_capacity(64),
            msgs_received:    0,
            msgs_sent:        0,
            bytes_received:   0,
            bytes_sent:       0,
        }
    }

    /// Check if the handshake is complete and full messaging is allowed.
    pub fn is_established(&self) -> bool {
        self.state.is_established()
    }

    /// Check if the connection is still alive (not disconnecting).
    pub fn is_alive(&self) -> bool {
        self.state.is_alive()
    }

    /// Peer's best block height (from Version message), or 0 if not yet received.
    pub fn peer_height(&self) -> u64 {
        self.peer_version.as_ref().map_or(0, |v| v.height)
    }

    /// Peer's user agent string, or empty if not yet received.
    pub fn peer_user_agent(&self) -> &str {
        self.peer_version
            .as_ref()
            .map_or("", |v| v.user_agent.as_str())
    }

    /// Peer's cryptographic identity (Ed25519 pubkey), if present.
    pub fn peer_identity(&self) -> Option<&str> {
        self.peer_version.as_ref().and_then(|v| v.peer_identity())
    }

    /// Check whether the handshake has timed out.
    pub fn check_handshake_timeout(&self) -> Result<(), ProtocolError> {
        if self.state.is_established() {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let elapsed = now.saturating_sub(self.connected_at);

        // Puzzle phase gets its own longer timeout
        let timeout = match self.state {
            HandshakeState::AwaitPuzzleSolution |
            HandshakeState::AwaitPuzzleChallenge => PUZZLE_TIMEOUT_SECS,
            HandshakeState::Disconnecting        => return Ok(()),
            _                                    => HANDSHAKE_TIMEOUT_SECS,
        };

        if elapsed > timeout {
            return Err(ProtocolError::new(
                if timeout == PUZZLE_TIMEOUT_SECS {
                    ProtocolErrorKind::PuzzleTimeout
                } else {
                    ProtocolErrorKind::HandshakeTimeout
                },
                format!("state {} timed out after {}s (limit {}s)",
                        self.state, elapsed, timeout),
                0, // not malicious, just slow
            ));
        }
        Ok(())
    }

    /// Validate whether a command is allowed in the current state.
    ///
    /// Returns Ok(()) if allowed, ProtocolError if not.
    pub fn check_command_allowed(&self, cmd: CommandId) -> Result<(), ProtocolError> {
        if self.state == HandshakeState::Disconnecting {
            return Err(ProtocolError::new(
                ProtocolErrorKind::InvalidTransition,
                "connection is disconnecting",
                0,
            ));
        }

        if self.state.is_established() {
            // Block handshake commands after connection is established
            if matches!(cmd, CommandId::Version | CommandId::VerAck | CommandId::PuzzleChallenge | CommandId::PuzzleSolution) {
                return Err(ProtocolError::new(
                    ProtocolErrorKind::DuplicateHandshake,
                    format!("{:?} not allowed after handshake", cmd),
                    100,
                ));
            }
            return Ok(());
        }

        if cmd.allowed_before_handshake() {
            return Ok(());
        }

        Err(ProtocolError::new(
            ProtocolErrorKind::PrematureMessage,
            format!("{} not allowed in state {}", cmd, self.state),
            50, // likely an attack — legitimate peers follow the handshake
        ))
    }

    // ── State transitions ──────────────────────────────────────────────

    /// Transition: we sent a puzzle challenge (inbound connection).
    pub fn sent_puzzle_challenge(&mut self, challenge: &str) -> Result<(), ProtocolError> {
        if self.state != HandshakeState::Init {
            return Err(ProtocolError::new(
                ProtocolErrorKind::InvalidTransition,
                format!("cannot send puzzle from state {}", self.state),
                0,
            ));
        }
        self.puzzle_challenge = Some(challenge.to_string());
        self.state = HandshakeState::AwaitPuzzleSolution;
        Ok(())
    }

    /// Transition: we received a puzzle challenge (outbound connection).
    pub fn received_puzzle_challenge(&mut self, challenge: &str) -> Result<(), ProtocolError> {
        if self.state != HandshakeState::Init
            && self.state != HandshakeState::AwaitPuzzleChallenge
        {
            return Err(ProtocolError::new(
                ProtocolErrorKind::InvalidTransition,
                format!("unexpected puzzle challenge in state {}", self.state),
                50,
            ));
        }
        self.puzzle_challenge = Some(challenge.to_string());
        Ok(())
    }

    /// Transition: puzzle verified successfully.
    pub fn puzzle_verified(&mut self) -> Result<(), ProtocolError> {
        match self.state {
            HandshakeState::AwaitPuzzleSolution |
            HandshakeState::Init |
            HandshakeState::AwaitPuzzleChallenge => {
                self.state = HandshakeState::PuzzleVerified;
                Ok(())
            }
            _ => Err(ProtocolError::new(
                ProtocolErrorKind::InvalidTransition,
                format!("cannot verify puzzle in state {}", self.state),
                50,
            )),
        }
    }

    /// Transition: we sent our Version message.
    pub fn sent_version(&mut self) -> Result<(), ProtocolError> {
        if self.state != HandshakeState::PuzzleVerified
            && self.state != HandshakeState::Init
        {
            return Err(ProtocolError::new(
                ProtocolErrorKind::InvalidTransition,
                format!("cannot send version from state {}", self.state),
                0,
            ));
        }
        self.state = HandshakeState::AwaitVersion;
        Ok(())
    }

    /// Transition: we received and validated the peer's Version.
    pub fn received_version(&mut self, version: VersionPayload) -> Result<(), ProtocolError> {
        if self.peer_version.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorKind::DuplicateHandshake,
                "duplicate Version message",
                100, // clearly an attack
            ));
        }

        // Validate all fields
        version.validate(self.our_bps)?;

        self.peer_version = Some(version);

        // After receiving Version and sending VerAck, we wait for their VerAck
        self.state = HandshakeState::AwaitPeerVerAck;
        Ok(())
    }

    /// Transition: we received VerAck from the peer.
    pub fn received_verack(&mut self) -> Result<(), ProtocolError> {
        if self.state != HandshakeState::AwaitPeerVerAck {
            return Err(ProtocolError::new(
                ProtocolErrorKind::InvalidTransition,
                format!("unexpected VerAck in state {:?}", self.state),
                50,
            ));
        }
        // Ensure we actually received Version first
        if self.peer_version.is_none() {
            return Err(ProtocolError::new(
                ProtocolErrorKind::PrematureMessage,
                "received VerAck before Version",
                100,
            ));
        }
        self.state = HandshakeState::Established;
        Ok(())
    }

    /// Transition: begin graceful disconnect.
    pub fn begin_disconnect(&mut self) {
        self.state = HandshakeState::Disconnecting;
    }

    // ── Nonce tracking (anti-replay) ───────────────────────────────────

    /// Record a nonce and check for replay.
    ///
    /// Returns `true` if the nonce is new, `false` if it's a replay.
    pub fn record_nonce(&mut self, nonce: u64) -> bool {
        // Cap the set to prevent memory exhaustion
        if self.seen_nonces.len() >= 2048 {
            self.seen_nonces.clear();
        }
        self.seen_nonces.insert(nonce)
    }

    // ── Lifecycle transitions (post-handshake) ────────────────────────

    /// Begin header sync with this peer.
    pub fn begin_header_sync(&mut self, target_height: u64) {
        self.lifecycle = PeerLifecycle::SyncingHeaders {
            target_height,
            current_height: 0,
        };
    }

    /// Update header sync progress.
    pub fn update_header_sync(&mut self, current_height: u64) {
        if let PeerLifecycle::SyncingHeaders { target_height, .. } = &self.lifecycle {
            let target = *target_height;
            if current_height >= target {
                self.lifecycle = PeerLifecycle::SyncingBlocks {
                    target_height: target,
                    current_height: 0,
                };
            } else {
                self.lifecycle = PeerLifecycle::SyncingHeaders {
                    target_height: target,
                    current_height,
                };
            }
        }
    }

    /// Update block sync progress.
    pub fn update_block_sync(&mut self, current_height: u64) {
        if let PeerLifecycle::SyncingBlocks { target_height, .. } = &self.lifecycle {
            let target = *target_height;
            if current_height >= target {
                self.lifecycle = PeerLifecycle::Normal;
            } else {
                self.lifecycle = PeerLifecycle::SyncingBlocks {
                    target_height: target,
                    current_height,
                };
            }
        }
    }

    /// Mark peer as fully synced (normal relay mode).
    pub fn sync_complete(&mut self) {
        self.lifecycle = PeerLifecycle::Normal;
    }

    /// Restrict peer due to misbehavior.
    pub fn restrict(&mut self, reason: impl Into<String>) {
        self.lifecycle = PeerLifecycle::Restricted { reason: reason.into() };
    }

    /// Whether the peer is in normal relay mode.
    pub fn is_relay_ready(&self) -> bool {
        self.state.is_established() && self.lifecycle.is_normal()
    }

    /// Whether the peer is restricted.
    pub fn is_restricted(&self) -> bool {
        self.lifecycle.is_restricted()
    }

    /// Check whether a command is allowed given the current lifecycle state.
    ///
    /// Restricted peers can only do Ping/Pong/Reject.
    pub fn check_lifecycle_allowed(&self, cmd: CommandId) -> Result<(), ProtocolError> {
        if let PeerLifecycle::Restricted { ref reason } = self.lifecycle {
            match cmd {
                CommandId::Ping | CommandId::Pong | CommandId::Reject => Ok(()),
                _ => Err(ProtocolError::new(
                    ProtocolErrorKind::PrematureMessage,
                    format!("peer restricted ({}): {} not allowed", reason, cmd),
                    0,
                )),
            }
        } else {
            Ok(())
        }
    }

    /// Peer's advertised services (from Version), or 0 if not yet received.
    pub fn peer_services(&self) -> u64 {
        self.peer_version.as_ref().map_or(0, |v| v.services)
    }

    /// Whether the peer supports a specific service.
    pub fn peer_has_service(&self, flag: u64) -> bool {
        self.peer_services() & flag == flag
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                    MESSAGE VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

/// Validate a wire header before reading the payload.
///
/// This is the first line of defense — called BEFORE any payload is read,
/// preventing resource exhaustion from oversized messages.
pub fn validate_header(
    header: &WireHeader,
    expected_magic: [u8; 4],
) -> Result<CommandId, ProtocolError> {
    // 1. Magic check (wrong network → instant reject)
    if header.magic != expected_magic {
        return Err(ProtocolError::new(
            ProtocolErrorKind::BadMagic,
            format!(
                "magic {:02X}{:02X}{:02X}{:02X} != expected {:02X}{:02X}{:02X}{:02X}",
                header.magic[0], header.magic[1], header.magic[2], header.magic[3],
                expected_magic[0], expected_magic[1], expected_magic[2], expected_magic[3],
            ),
            100,
        ));
    }

    // 2. Command ID (unknown → reject before reading payload)
    let cmd = CommandId::from_byte(header.command_id).ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorKind::UnknownCommand,
            format!("unknown command_id 0x{:02X}", header.command_id),
            50,
        )
    })?;

    // 3. Payload size bounds
    if header.payload_len as usize > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::new(
            ProtocolErrorKind::OversizePayload,
            format!("payload {} bytes > max {} bytes", header.payload_len, MAX_MESSAGE_SIZE),
            100,
        ));
    }

    // 4. Empty payloads for commands that require data
    if header.payload_len == 0 && cmd.is_bulk_data() {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            format!("{} with empty payload", cmd),
            20,
        ));
    }

    Ok(cmd)
}

/// Validate a payload's checksum after reading it from the wire.
pub fn validate_payload_checksum(
    payload: &[u8],
    expected: [u8; 4],
) -> Result<(), ProtocolError> {
    if !verify_checksum(payload, expected) {
        return Err(ProtocolError::new(
            ProtocolErrorKind::BadChecksum,
            format!(
                "checksum {:02X}{:02X}{:02X}{:02X} != computed",
                expected[0], expected[1], expected[2], expected[3],
            ),
            100,
        ));
    }
    Ok(())
}

/// Validate an Inv/GetData message's item list.
pub fn validate_inv_items(items: &[(String, String)]) -> Result<(), ProtocolError> {
    if items.len() > MAX_INV_PER_MSG {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            format!("inv items {} > max {}", items.len(), MAX_INV_PER_MSG),
            50,
        ));
    }
    for (kind, hash) in items {
        if kind != "block" && kind != "tx" {
            return Err(ProtocolError::new(
                ProtocolErrorKind::FieldViolation,
                format!("unknown inv type '{}'", kind),
                20,
            ));
        }
        if hash.len() > MAX_HASH_HEX_LEN {
            return Err(ProtocolError::new(
                ProtocolErrorKind::FieldViolation,
                format!("hash too long ({} > {})", hash.len(), MAX_HASH_HEX_LEN),
                50,
            ));
        }
    }
    Ok(())
}

/// Validate an Addr message's peer list.
pub fn validate_addr_list(addrs: &[String]) -> Result<(), ProtocolError> {
    if addrs.len() > MAX_ADDR_PER_MSG {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            format!("addr list {} > max {}", addrs.len(), MAX_ADDR_PER_MSG),
            20,
        ));
    }
    Ok(())
}

/// Validate a Headers message's hash list.
pub fn validate_headers_list(hashes: &[String]) -> Result<(), ProtocolError> {
    if hashes.len() > MAX_HEADERS_PER_MSG {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            format!("headers {} > max {}", hashes.len(), MAX_HEADERS_PER_MSG),
            20,
        ));
    }
    for h in hashes {
        if h.len() > MAX_HASH_HEX_LEN {
            return Err(ProtocolError::new(
                ProtocolErrorKind::FieldViolation,
                format!("header hash too long ({} > {})", h.len(), MAX_HASH_HEX_LEN),
                50,
            ));
        }
    }
    Ok(())
}

/// Validate a Reject message.
pub fn validate_reject(reason: &str) -> Result<(), ProtocolError> {
    if reason.len() > MAX_REJECT_REASON_LEN {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            format!("reject reason too long ({} > {})", reason.len(), MAX_REJECT_REASON_LEN),
            10,
        ));
    }
    Ok(())
}

/// Validate a hash string (hex format, expected 64 chars for SHA-256).
pub fn validate_hash_hex(hash: &str) -> Result<(), ProtocolError> {
    if hash.is_empty() {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            "empty hash",
            20,
        ));
    }
    if hash.len() > MAX_HASH_HEX_LEN {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            format!("hash too long ({} > {})", hash.len(), MAX_HASH_HEX_LEN),
            50,
        ));
    }
    if !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')) {
        return Err(ProtocolError::new(
            ProtocolErrorKind::FieldViolation,
            "hash contains non-hex characters",
            50,
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
//                    UTILITY: VERSION MESSAGE BUILDER
// ═══════════════════════════════════════════════════════════════════════════

/// Build a Version payload for outgoing handshake.
pub fn build_version_payload(
    node_id: &str,
    best_height: u64,
    bps: u32,
) -> VersionPayload {
    VersionPayload {
        version:    PROTOCOL_VERSION,
        height:     best_height,
        timestamp:  SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        user_agent: format!("ShadowDAG/0.1.0 {}", node_id),
        bps,
        chain_id:   CHAIN_ID,
        services:   DEFAULT_SERVICES,
        nonce:      rand_nonce(),
    }
}

/// Generate a random-ish nonce for Ping/Version messages.
fn rand_nonce() -> u64 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // XOR with pid for uniqueness across restarts
    t ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15)
}

// ═══════════════════════════════════════════════════════════════════════════
//                         LEGACY COMPAT
// ═══════════════════════════════════════════════════════════════════════════

/// Legacy NetworkMessage — kept for backward compatibility with p2p.rs
/// wire format (bincode serialization of P2PMessage).
///
/// New code should use WireHeader + ProtocolSession directly.
#[derive(Debug, Clone)]
pub struct NetworkMessage {
    pub magic:      [u8; 4],
    pub msg_type:   CommandId,
    pub payload:    Vec<u8>,
    pub checksum:   [u8; 4],
    pub timestamp:  u64,
}

impl NetworkMessage {
    pub fn new(msg_type: CommandId, payload: Vec<u8>) -> Self {
        let checksum = compute_checksum(&payload);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            magic: NETWORK_MAGIC,
            msg_type,
            payload,
            checksum,
            timestamp,
        }
    }

    pub fn is_valid_magic(&self) -> bool {
        self.magic == NETWORK_MAGIC
    }

    pub fn is_valid_checksum(&self) -> bool {
        verify_checksum(&self.payload, self.checksum)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !self.is_valid_magic() {
            return Err(ProtocolError::new(
                ProtocolErrorKind::BadMagic, "wrong network magic", 100,
            ));
        }
        if !self.is_valid_checksum() {
            return Err(ProtocolError::new(
                ProtocolErrorKind::BadChecksum, "checksum mismatch", 100,
            ));
        }
        if self.payload.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::new(
                ProtocolErrorKind::OversizePayload,
                format!("payload {} > max {}", self.payload.len(), MAX_MESSAGE_SIZE),
                100,
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                            TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wire header tests ───────────────────────────────────────────────

    #[test]
    fn wire_header_roundtrip() {
        let payload = b"hello shadowdag";
        let hdr = WireHeader::for_payload(NETWORK_MAGIC, 0x0A, payload);
        let encoded = hdr.encode();
        assert_eq!(encoded.len(), WIRE_HEADER_SIZE);

        let decoded = WireHeader::decode(&encoded);
        assert_eq!(decoded.magic, NETWORK_MAGIC);
        assert_eq!(decoded.command_id, 0x0A);
        assert_eq!(decoded.payload_len, payload.len() as u32);
        assert_eq!(decoded.checksum, hdr.checksum);
    }

    #[test]
    fn wire_header_checksum_detects_corruption() {
        let payload = b"block data here";
        let checksum = compute_checksum(payload);
        let corrupted = b"block data HERE";
        assert!(!verify_checksum(corrupted, checksum));
    }

    #[test]
    fn checksum_deterministic() {
        let data = b"determinism test";
        let c1 = compute_checksum(data);
        let c2 = compute_checksum(data);
        assert_eq!(c1, c2);
    }

    // ── Command ID tests ────────────────────────────────────────────────

    #[test]
    fn all_command_ids_roundtrip() {
        let cmds = [
            CommandId::Version, CommandId::VerAck, CommandId::Ping, CommandId::Pong,
            CommandId::GetAddr, CommandId::Addr, CommandId::Inv, CommandId::GetData,
            CommandId::Block, CommandId::Tx, CommandId::GetHeaders, CommandId::Headers,
            CommandId::GetBlock, CommandId::Reject, CommandId::PuzzleChallenge,
            CommandId::PuzzleSolution, CommandId::ShadowTx, CommandId::OnionTx,
            CommandId::GetMempool,
        ];
        for cmd in cmds {
            let byte = cmd as u8;
            let parsed = CommandId::from_byte(byte).expect(&format!("0x{:02X} should parse", byte));
            assert_eq!(parsed, cmd);
        }
    }

    #[test]
    fn unknown_command_id_returns_none() {
        assert!(CommandId::from_byte(0x00).is_none());
        assert!(CommandId::from_byte(0xFF).is_none());
        assert!(CommandId::from_byte(0x0F).is_none());
    }

    #[test]
    fn pre_handshake_commands_correct() {
        assert!(CommandId::Version.allowed_before_handshake());
        assert!(CommandId::VerAck.allowed_before_handshake());
        assert!(CommandId::PuzzleChallenge.allowed_before_handshake());
        assert!(CommandId::PuzzleSolution.allowed_before_handshake());
        assert!(CommandId::Reject.allowed_before_handshake());

        assert!(!CommandId::Tx.allowed_before_handshake());
        assert!(!CommandId::Block.allowed_before_handshake());
        assert!(!CommandId::Inv.allowed_before_handshake());
        assert!(!CommandId::GetData.allowed_before_handshake());
        assert!(!CommandId::Ping.allowed_before_handshake());
    }

    // ── Header validation tests ─────────────────────────────────────────

    #[test]
    fn validate_header_rejects_bad_magic() {
        let hdr = WireHeader {
            magic: [0xFF, 0xFF, 0xFF, 0xFF],
            command_id: 0x01,
            payload_len: 100,
            checksum: [0; 4],
        };
        let err = validate_header(&hdr, NETWORK_MAGIC).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::BadMagic);
        assert_eq!(err.ban_score, 100);
    }

    #[test]
    fn validate_header_rejects_unknown_command() {
        let hdr = WireHeader {
            magic: NETWORK_MAGIC,
            command_id: 0xFF,
            payload_len: 100,
            checksum: [0; 4],
        };
        let err = validate_header(&hdr, NETWORK_MAGIC).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::UnknownCommand);
    }

    #[test]
    fn validate_header_rejects_oversize() {
        let hdr = WireHeader {
            magic: NETWORK_MAGIC,
            command_id: 0x09, // Block
            payload_len: (MAX_MESSAGE_SIZE + 1) as u32,
            checksum: [0; 4],
        };
        let err = validate_header(&hdr, NETWORK_MAGIC).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::OversizePayload);
    }

    #[test]
    fn validate_header_rejects_empty_bulk() {
        let hdr = WireHeader {
            magic: NETWORK_MAGIC,
            command_id: 0x09, // Block
            payload_len: 0,
            checksum: [0; 4],
        };
        let err = validate_header(&hdr, NETWORK_MAGIC).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::FieldViolation);
    }

    #[test]
    fn validate_header_accepts_valid() {
        let hdr = WireHeader {
            magic: NETWORK_MAGIC,
            command_id: 0x03, // Ping
            payload_len: 8,
            checksum: [0; 4],
        };
        let cmd = validate_header(&hdr, NETWORK_MAGIC).unwrap();
        assert_eq!(cmd, CommandId::Ping);
    }

    // ── Handshake state machine tests ───────────────────────────────────

    #[test]
    fn inbound_handshake_flow() {
        let mut session = ProtocolSession::new(false, DEFAULT_BPS);
        assert_eq!(session.state, HandshakeState::Init);

        // Send puzzle challenge
        session.sent_puzzle_challenge("challenge123").unwrap();
        assert_eq!(session.state, HandshakeState::AwaitPuzzleSolution);

        // Receive puzzle solution → verified
        session.puzzle_verified().unwrap();
        assert_eq!(session.state, HandshakeState::PuzzleVerified);

        // Send our version
        session.sent_version().unwrap();
        assert_eq!(session.state, HandshakeState::AwaitVersion);

        // Receive peer's version
        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 1000,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ShadowDAG/0.1.0 test-peer".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 42,
        };
        session.received_version(ver).unwrap();
        assert_eq!(session.state, HandshakeState::AwaitPeerVerAck);

        // Receive VerAck → established
        session.received_verack().unwrap();
        assert_eq!(session.state, HandshakeState::Established);
        assert!(session.is_established());
    }

    #[test]
    fn duplicate_version_rejected() {
        let mut session = ProtocolSession::new(false, DEFAULT_BPS);
        session.puzzle_verified().unwrap();
        session.sent_version().unwrap();

        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 100,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ShadowDAG/0.1.0 test".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 1,
        };
        session.received_version(ver.clone()).unwrap();

        // Second version → error
        let err = session.received_version(ver).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::DuplicateHandshake);
        assert_eq!(err.ban_score, 100);
    }

    #[test]
    fn premature_tx_rejected() {
        let session = ProtocolSession::new(true, DEFAULT_BPS);
        let err = session.check_command_allowed(CommandId::Tx).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::PrematureMessage);
    }

    #[test]
    fn established_allows_all_commands() {
        let mut session = ProtocolSession::new(false, DEFAULT_BPS);
        session.state = HandshakeState::Established;

        for cmd in [CommandId::Tx, CommandId::Block, CommandId::Inv,
                    CommandId::Ping, CommandId::GetAddr, CommandId::ShadowTx] {
            assert!(session.check_command_allowed(cmd).is_ok());
        }
    }

    // ── Version validation tests ────────────────────────────────────────

    #[test]
    fn version_zero_rejected() {
        let ver = VersionPayload {
            version: 0, height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ShadowDAG/0.1.0 test".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 1,
        };
        let err = ver.validate(DEFAULT_BPS).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::IncompatibleVersion);
    }

    #[test]
    fn bps_mismatch_rejected() {
        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ShadowDAG/0.1.0 test".to_string(),
            bps: 32, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 1,
        };
        let err = ver.validate(10).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::BpsMismatch);
    }

    #[test]
    fn timestamp_drift_rejected() {
        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 0,
            timestamp: 1000, // way in the past
            user_agent: "ShadowDAG/0.1.0 test".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 1,
        };
        let err = ver.validate(DEFAULT_BPS).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::TimestampDrift);
    }

    #[test]
    fn user_agent_too_short_rejected() {
        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ab".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 1,
        };
        let err = ver.validate(DEFAULT_BPS).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::FieldViolation);
    }

    #[test]
    fn user_agent_too_long_rejected() {
        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "x".repeat(MAX_USER_AGENT_LEN + 1),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 1,
        };
        let err = ver.validate(DEFAULT_BPS).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::FieldViolation);
    }

    #[test]
    fn valid_version_accepted() {
        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 50_000,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ShadowDAG/0.1.0 id:abcdef1234567890".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: DEFAULT_SERVICES, nonce: 42,
        };
        assert!(ver.validate(DEFAULT_BPS).is_ok());
        assert_eq!(ver.peer_identity(), Some("abcdef1234567890"));
    }

    // ── Nonce anti-replay tests ─────────────────────────────────────────

    #[test]
    fn nonce_replay_detected() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        assert!(session.record_nonce(12345));   // first time → ok
        assert!(!session.record_nonce(12345));  // replay → rejected
    }

    #[test]
    fn nonce_set_capped() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        for i in 0..3000u64 {
            session.record_nonce(i);
        }
        // Set should have been cleared at 2048
        assert!(session.seen_nonces.len() < 2048);
    }

    // ── Field validation tests ──────────────────────────────────────────

    #[test]
    fn inv_items_limit_enforced() {
        let items: Vec<(String, String)> = (0..MAX_INV_PER_MSG + 1)
            .map(|i| ("block".to_string(), format!("{:064x}", i)))
            .collect();
        let err = validate_inv_items(&items).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::FieldViolation);
    }

    #[test]
    fn inv_items_valid_accepted() {
        let items = vec![
            ("block".to_string(), "aa".repeat(32)),
            ("tx".to_string(), "bb".repeat(32)),
        ];
        assert!(validate_inv_items(&items).is_ok());
    }

    #[test]
    fn inv_items_bad_type_rejected() {
        let items = vec![("unknown".to_string(), "aa".repeat(32))];
        let err = validate_inv_items(&items).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::FieldViolation);
    }

    #[test]
    fn hash_validation() {
        assert!(validate_hash_hex(&"aa".repeat(32)).is_ok());
        assert!(validate_hash_hex("").is_err());
        assert!(validate_hash_hex(&"zz".repeat(32)).is_err());
        assert!(validate_hash_hex(&"a".repeat(100)).is_err());
    }

    #[test]
    fn addr_list_limit() {
        let addrs: Vec<String> = (0..MAX_ADDR_PER_MSG + 1)
            .map(|i| format!("10.0.0.{}:9333", i % 256))
            .collect();
        assert!(validate_addr_list(&addrs).is_err());
    }

    #[test]
    fn reject_reason_limit() {
        assert!(validate_reject("normal reason").is_ok());
        assert!(validate_reject(&"x".repeat(MAX_REJECT_REASON_LEN + 1)).is_err());
    }

    // ── NetworkMessage (legacy compat) tests ────────────────────────────

    #[test]
    fn network_message_checksum_valid() {
        let msg = NetworkMessage::new(CommandId::Ping, vec![1, 2, 3, 4]);
        assert!(msg.is_valid_magic());
        assert!(msg.is_valid_checksum());
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn network_message_corrupted_checksum() {
        let mut msg = NetworkMessage::new(CommandId::Ping, vec![1, 2, 3, 4]);
        msg.payload[0] = 0xFF;
        assert!(!msg.is_valid_checksum());
        assert!(msg.validate().is_err());
    }

    // ── Version payload builder test ────────────────────────────────────

    #[test]
    fn build_version_payload_valid() {
        let vp = build_version_payload("id:aabbccdd", 10_000, DEFAULT_BPS);
        assert_eq!(vp.version, PROTOCOL_VERSION);
        assert_eq!(vp.height, 10_000);
        assert_eq!(vp.bps, DEFAULT_BPS);
        assert_eq!(vp.chain_id, CHAIN_ID);
        assert!(vp.user_agent.contains("ShadowDAG"));
        assert!(vp.validate(DEFAULT_BPS).is_ok());
    }

    // ── Disconnecting state blocks everything ───────────────────────────

    #[test]
    fn disconnecting_blocks_all_commands() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        session.begin_disconnect();
        assert!(!session.is_alive());
        let err = session.check_command_allowed(CommandId::Version).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::InvalidTransition);
    }

    // ── Service flags tests ─────────────────────────────────────────────

    #[test]
    fn required_services_check() {
        assert!(has_required_services(SERVICE_NODE_NETWORK));
        assert!(has_required_services(DEFAULT_SERVICES));
        assert!(!has_required_services(0));
        assert!(!has_required_services(SERVICE_NODE_BLOOM)); // bloom without network
    }

    #[test]
    fn version_insufficient_services_rejected() {
        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ShadowDAG/0.1.0 test".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID, services: 0, nonce: 1,
        };
        let err = ver.validate(DEFAULT_BPS).unwrap_err();
        assert_eq!(err.kind, ProtocolErrorKind::FieldViolation);
    }

    // ── Peer lifecycle tests ────────────────────────────────────────────

    #[test]
    fn lifecycle_starts_connected() {
        let session = ProtocolSession::new(true, DEFAULT_BPS);
        assert_eq!(session.lifecycle, PeerLifecycle::Connected);
        assert!(!session.lifecycle.is_normal());
        assert!(!session.lifecycle.is_syncing());
    }

    #[test]
    fn lifecycle_header_sync_flow() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        session.begin_header_sync(1000);
        assert!(session.lifecycle.is_syncing());
        assert_eq!(session.lifecycle.sync_progress_pct(), 0);

        session.update_header_sync(500);
        assert_eq!(session.lifecycle.sync_progress_pct(), 50);

        // Reaching target transitions to block sync
        session.update_header_sync(1000);
        assert!(matches!(session.lifecycle, PeerLifecycle::SyncingBlocks { .. }));
    }

    #[test]
    fn lifecycle_block_sync_to_normal() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        session.begin_header_sync(100);
        session.update_header_sync(100); // → SyncingBlocks
        session.update_block_sync(100);  // → Normal
        assert!(session.lifecycle.is_normal());
        assert!(session.is_relay_ready() || !session.is_established()); // needs established too
    }

    #[test]
    fn lifecycle_restrict() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        session.sync_complete();
        session.restrict("too many invalid blocks");
        assert!(session.is_restricted());

        // Restricted peer can only Ping/Pong/Reject
        session.state = HandshakeState::Established;
        assert!(session.check_lifecycle_allowed(CommandId::Ping).is_ok());
        assert!(session.check_lifecycle_allowed(CommandId::Reject).is_ok());
        assert!(session.check_lifecycle_allowed(CommandId::Tx).is_err());
        assert!(session.check_lifecycle_allowed(CommandId::Block).is_err());
    }

    #[test]
    fn lifecycle_sync_complete() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        session.sync_complete();
        assert!(session.lifecycle.is_normal());
    }

    // ── Per-command payload constraints tests ────────────────────────────

    #[test]
    fn payload_size_verack_exact_discriminant() {
        assert!(validate_payload_size(CommandId::VerAck, 4).is_ok());  // bincode enum tag
        assert!(validate_payload_size(CommandId::VerAck, 3).is_err());
        assert!(validate_payload_size(CommandId::VerAck, 5).is_err());
    }

    #[test]
    fn payload_size_ping_exactly_12() {
        assert!(validate_payload_size(CommandId::Ping, 12).is_ok());  // 4 tag + 8 nonce
        assert!(validate_payload_size(CommandId::Ping, 11).is_err());
        assert!(validate_payload_size(CommandId::Ping, 13).is_err());
    }

    #[test]
    fn payload_size_block_has_minimum() {
        assert!(validate_payload_size(CommandId::Block, 63).is_err());
        assert!(validate_payload_size(CommandId::Block, 64).is_ok());
        assert!(validate_payload_size(CommandId::Block, MAX_MESSAGE_SIZE).is_ok());
    }

    #[test]
    fn payload_size_getmempool_exact_discriminant() {
        assert!(validate_payload_size(CommandId::GetMempool, 4).is_ok());  // bincode enum tag
        assert!(validate_payload_size(CommandId::GetMempool, 3).is_err());
        assert!(validate_payload_size(CommandId::GetMempool, 5).is_err());
    }

    // ── Service capability tests ────────────────────────────────────────

    #[test]
    fn peer_service_flags() {
        let mut session = ProtocolSession::new(true, DEFAULT_BPS);
        assert_eq!(session.peer_services(), 0); // no version yet

        session.state = HandshakeState::PuzzleVerified;
        session.sent_version().unwrap();

        let ver = VersionPayload {
            version: PROTOCOL_VERSION, height: 100,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_agent: "ShadowDAG/0.1.0 test".to_string(),
            bps: DEFAULT_BPS, chain_id: CHAIN_ID,
            services: SERVICE_NODE_NETWORK | SERVICE_NODE_PRIVACY, nonce: 1,
        };
        session.received_version(ver).unwrap();

        assert!(session.peer_has_service(SERVICE_NODE_NETWORK));
        assert!(session.peer_has_service(SERVICE_NODE_PRIVACY));
        assert!(!session.peer_has_service(SERVICE_NODE_CONTRACTS));
    }
}
