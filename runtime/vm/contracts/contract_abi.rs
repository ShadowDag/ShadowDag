// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Contract ABI — Application Binary Interface for smart contracts.
//
// Defines the interface of a contract: its functions, parameters,
// return types, and events. Used for encoding/decoding contract calls.
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::errors::VmError;
use crate::slog_error;

/// ABI parameter types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AbiType {
    Uint64,
    Int64,
    Bool,
    String,
    Bytes,
    Address,
    Array(Box<AbiType>),
}

impl AbiType {
    pub fn name(&self) -> &str {
        match self {
            AbiType::Uint64     => "uint64",
            AbiType::Int64      => "int64",
            AbiType::Bool       => "bool",
            AbiType::String     => "string",
            AbiType::Bytes      => "bytes",
            AbiType::Address    => "address",
            AbiType::Array(_)   => "array",
        }
    }

    /// Parse an ABI type name (case-sensitive) into the typed enum.
    ///
    /// Returns `Err(VmError::ContractError)` for any name that is not
    /// in the known set. The previous implementation defaulted unknown
    /// types to `AbiType::Bytes`, which silently changed the meaning
    /// of an interface — a typo like `"uint66"` or an aspirational
    /// type like `"uint256"` would be accepted as `Bytes` and
    /// decoded as a variable-length blob, producing nonsense values
    /// at runtime instead of failing fast at parse time.
    ///
    /// Accepted names (matching the canonical mnemonic AND a short
    /// alias where one historically existed):
    ///
    ///   `uint64` / `uint`, `int64` / `int`, `bool`, `string`,
    ///   `bytes`, `address`
    ///
    /// `Array(_)` is NOT parsed here — it has its own constructor
    /// path because the inner type would need recursive parsing.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, VmError> {
        match s {
            "uint64" | "uint"   => Ok(AbiType::Uint64),
            "int64"  | "int"    => Ok(AbiType::Int64),
            "bool"              => Ok(AbiType::Bool),
            "string"            => Ok(AbiType::String),
            "bytes"             => Ok(AbiType::Bytes),
            "address"           => Ok(AbiType::Address),
            other => Err(VmError::ContractError(format!(
                "unknown ABI type '{}': expected one of \
                 uint64/uint, int64/int, bool, string, bytes, address",
                other
            ))),
        }
    }
}

/// A function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiParam {
    pub name:     String,
    pub abi_type: AbiType,
    pub indexed:  bool, // For events
}

/// A function in the ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiFunction {
    pub name:       String,
    pub inputs:     Vec<AbiParam>,
    pub outputs:    Vec<AbiParam>,
    pub mutability: Mutability,
    /// 4-byte function selector (first 4 bytes of SHA-256 of signature)
    pub selector:   [u8; 4],
}

/// Function mutability
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Mutability {
    /// Reads and writes state
    Mutable,
    /// Only reads state (no gas for storage)
    View,
    /// No state access at all
    Pure,
    /// Receives SDAG value
    Payable,
}

/// An event in the ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiEvent {
    pub name:      String,
    pub params:    Vec<AbiParam>,
    pub anonymous: bool,
}

impl AbiEvent {
    /// Compute the canonical event signature: EventName(type1,type2,...).
    pub fn signature(&self) -> String {
        let params: Vec<String> = self.params.iter()
            .map(|p| p.abi_type.name().to_string())
            .collect();
        format!("{}({})", self.name, params.join(","))
    }
}

/// Decoded event with parameter names and values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedEvent {
    pub name: String,
    pub params: Vec<(String, String)>,
}

/// Complete contract ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAbi {
    pub name:         String,
    pub version:      String,
    pub functions:    Vec<AbiFunction>,
    pub events:       Vec<AbiEvent>,
    pub constructor:  Option<AbiFunction>,
}

impl ContractAbi {
    pub fn new(name: &str) -> Self {
        Self {
            name:        name.to_string(),
            version:     "1.0.0".to_string(),
            functions:   Vec::new(),
            events:      Vec::new(),
            constructor: None,
        }
    }

    /// Add a function to the ABI
    pub fn add_function(&mut self, name: &str, inputs: Vec<AbiParam>, outputs: Vec<AbiParam>, mutability: Mutability) {
        let selector = Self::compute_selector(name, &inputs);
        self.functions.push(AbiFunction {
            name: name.to_string(),
            inputs,
            outputs,
            mutability,
            selector,
        });
    }

    /// Add an event to the ABI
    pub fn add_event(&mut self, name: &str, params: Vec<AbiParam>) {
        self.events.push(AbiEvent {
            name: name.to_string(),
            params,
            anonymous: false,
        });
    }

    /// Compute 4-byte function selector from name + input types.
    ///
    /// Function selectors are intentionally truncated to 4 bytes
    /// (first 4 bytes of `SHA-256("name(type1,type2,…)")`) to keep
    /// call data compact. Events do NOT use this — they use
    /// [`Self::compute_event_topic0`], which keeps the full 32-byte
    /// hash so it can be compared byte-for-byte against the 64-char
    /// hex topics emitted by `event_log::EventCollector`.
    fn compute_selector(name: &str, inputs: &[AbiParam]) -> [u8; 4] {
        let hash = Self::compute_signature_hash(name, inputs);
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Compute the 32-byte event topic0 for an event with the given
    /// name and parameters.
    ///
    /// `event_log::EventCollector::emit` requires every topic to be a
    /// 64-char lowercase hex string (32 bytes). The convention for
    /// topic0 on a non-anonymous event is
    /// `hex(SHA-256("name(type1,type2,…)"))` — the full hash, not the
    /// truncated 4-byte function selector. `decode_event` compares
    /// topic0 against this full value with strict equality.
    fn compute_event_topic0(name: &str, params: &[AbiParam]) -> [u8; 32] {
        Self::compute_signature_hash(name, params).into()
    }

    /// Shared SHA-256 of the canonical signature string
    /// `"name(type1,type2,…)"`. Used by both [`Self::compute_selector`]
    /// (function call data) and [`Self::compute_event_topic0`] (event
    /// topic0) so they cannot drift apart.
    fn compute_signature_hash(name: &str, params: &[AbiParam]) -> [u8; 32] {
        let sig = format!("{}({})", name,
            params.iter().map(|p| p.abi_type.name().to_string()).collect::<Vec<_>>().join(",")
        );
        let mut h = Sha256::new();
        h.update(sig.as_bytes());
        h.finalize().into()
    }

    /// Find a function by its 4-byte selector
    pub fn find_by_selector(&self, selector: &[u8; 4]) -> Option<&AbiFunction> {
        self.functions.iter().find(|f| &f.selector == selector)
    }

    /// Find a function by name
    pub fn find_by_name(&self, name: &str) -> Option<&AbiFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Encode a function call to bytecode-compatible format.
    ///
    /// **Note:** This is a simplified encoding that concatenates the 4-byte
    /// selector with raw argument bytes. It does NOT implement the full
    /// Ethereum ABI encoding spec (no 32-byte padding, no dynamic offsets).
    /// Each argument is validated against its declared ABI type's expected
    /// size. For variable-length types (String, Bytes, Array) any non-empty
    /// value is accepted.
    pub fn encode_call(&self, function_name: &str, args: &[Vec<u8>]) -> Result<Vec<u8>, VmError> {
        let func = self.find_by_name(function_name)
            .ok_or_else(|| VmError::ContractError(format!("Function '{}' not found in ABI", function_name)))?;

        if args.len() != func.inputs.len() {
            return Err(VmError::ContractError(format!("Expected {} args, got {}", func.inputs.len(), args.len())));
        }

        // Validate each argument matches its declared ABI type's expected size
        for (i, (arg, param)) in args.iter().zip(func.inputs.iter()).enumerate() {
            let expected = Self::expected_arg_size(&param.abi_type);
            if let Some(size) = expected {
                if arg.len() != size {
                    return Err(VmError::ContractError(format!(
                        "Argument '{}' (index {}) expected {} bytes for type {}, got {}",
                        param.name, i, size, param.abi_type.name(), arg.len()
                    )));
                }
            }
            // Variable-length types (String, Bytes, Array): any non-empty length is valid
        }

        let mut encoded = Vec::with_capacity(4 + args.iter().map(|a| a.len()).sum::<usize>());
        encoded.extend_from_slice(&func.selector);
        for arg in args {
            encoded.extend_from_slice(arg);
        }
        Ok(encoded)
    }

    /// Return the expected byte size for fixed-size ABI types, or None for
    /// variable-length types.
    fn expected_arg_size(abi_type: &AbiType) -> Option<usize> {
        match abi_type {
            AbiType::Uint64  => Some(8),
            AbiType::Int64   => Some(8),
            AbiType::Bool    => Some(1),
            AbiType::Address => None, // addresses are variable-length strings in ShadowDAG
            AbiType::String  => None,
            AbiType::Bytes   => None,
            AbiType::Array(_) => None,
        }
    }

    /// Decode function selector from call data
    pub fn decode_selector(data: &[u8]) -> Option<[u8; 4]> {
        if data.len() < 4 { return None; }
        Some([data[0], data[1], data[2], data[3]])
    }

    /// Serialize ABI to JSON.
    ///
    /// Returns `Err(VmError::ContractError)` if serialization fails.
    /// The previous implementation swallowed the failure and returned
    /// an empty string (logging the error via `slog_error!`), which
    /// was the exact fail-silent-on-serialize pattern the verifier /
    /// persistence layers have been closing. In particular
    /// `ContractVerifier::save_verification` embeds `abi.to_json()`
    /// into the stored `VerificationMeta.abi_json` — if serialization
    /// had failed, the verifier would have stored a valid JSON record
    /// with `abi_json: ""`, and downstream explorers / decoders would
    /// see a "verified" contract with no ABI at all. Surfacing the
    /// error here means `save_verification` can propagate it as
    /// `StorageError::Serialization` and refuse to persist a
    /// meaningless record.
    pub fn to_json(&self) -> Result<String, VmError> {
        serde_json::to_string_pretty(self).map_err(|e| {
            slog_error!("vm", "abi_to_json_failed", error => &e.to_string());
            VmError::ContractError(format!("ABI serialize failed: {}", e))
        })
    }

    /// Deserialize ABI from JSON
    pub fn from_json(json: &str) -> Result<Self, VmError> {
        serde_json::from_str(json).map_err(|e| VmError::ContractError(format!("ABI parse error: {}", e)))
    }

    /// Decode return data bytes according to a function's output types.
    /// Returns a vector of (name, hex_value) pairs.
    pub fn decode_return(&self, function_name: &str, data: &[u8]) -> Result<Vec<(String, String)>, String> {
        let func = self.find_by_name(function_name)
            .ok_or_else(|| format!("function '{}' not found", function_name))?;

        let mut results = Vec::new();
        let mut offset = 0;

        for param in &func.outputs {
            let size = Self::expected_arg_size(&param.abi_type);
            match size {
                Some(s) => {
                    if offset + s > data.len() {
                        return Err(format!("insufficient return data for param '{}'", param.name));
                    }
                    results.push((param.name.clone(), hex::encode(&data[offset..offset+s])));
                    offset += s;
                }
                None => {
                    // Variable-length: read until end
                    results.push((param.name.clone(), hex::encode(&data[offset..])));
                    break;
                }
            }
        }

        Ok(results)
    }

    /// Decode a log event using the ABI event definition.
    ///
    /// Matches topic0 against the 32-byte event selector with STRICT
    /// equality (after normalizing a leading `0x` and lowercasing the
    /// hex), then decodes parameters using independent cursors:
    /// indexed params are pulled from `topics[1..]` in declaration
    /// order, non-indexed params are pulled from `data` in declaration
    /// order using the same fixed/variable-length rules as
    /// [`Self::decode_return`].
    ///
    /// # Previous bugs this replaces
    ///
    /// 1. **Prefix-collision topic match.** The old matcher used
    ///    `selector.starts_with(topic0) || topic0.starts_with(&selector)`
    ///    against the 4-byte function selector, which accepted:
    ///     * empty `topic0 == ""` (always a prefix) → first event in
    ///       the ABI matched every log;
    ///     * any short topic0 like `"aabb"` against selector
    ///       `"aabbccdd"` → cross-decode across events sharing a
    ///       byte prefix;
    ///     * a long topic0 like `"aabbccdd0011"` against selector
    ///       `"aabbccdd"` → same cross-decode in the other direction.
    ///    Using the full 32-byte topic hash + strict equality closes
    ///    all three.
    ///
    /// 2. **`indexed` flag ignored.** The old decoder used
    ///    `i + 1 < topics.len()` as a proxy for "this param is
    ///    indexed", which is only correct when every indexed param
    ///    comes before every non-indexed param in declaration order.
    ///    For an event declared as
    ///    `Foo(uint64 amount /* non-indexed */, address from /* indexed */)`
    ///    the old code pulled `topics[1]` into `amount` and
    ///    `hex::encode(data)` into `from`, silently swapping the two
    ///    values. The new decoder walks `event.params` and consults
    ///    `param.indexed` on each iteration.
    ///
    /// 3. **Full data blob replicated across non-indexed params.**
    ///    The old non-indexed branch used `hex::encode(data)` for
    ///    every non-indexed param, so two non-indexed params would
    ///    receive the entire data blob each. The new decoder slices
    ///    `data` by `expected_arg_size` exactly like `decode_return`.
    pub fn decode_event(&self, topics: &[String], data: &[u8]) -> Result<DecodedEvent, String> {
        if topics.is_empty() {
            return Err("no topics in log entry".into());
        }

        // Normalize topic0: strip an optional "0x" / "0X" prefix and
        // lowercase the hex. `event_log::EventCollector::emit` already
        // requires 64 ascii-hex chars, but the caller may still pass
        // either form, and `hex::encode` on the event side always
        // produces lowercase without a prefix.
        let topic0_norm = {
            let raw = &topics[0];
            let stripped = raw
                .strip_prefix("0x")
                .or_else(|| raw.strip_prefix("0X"))
                .unwrap_or(raw);
            stripped.to_ascii_lowercase()
        };

        // Strict equality against the full 32-byte event selector.
        // See the compute_event_topic0 doc for why this is NOT the
        // 4-byte function selector.
        let event = self.events.iter()
            .find(|e| {
                let selector = hex::encode(Self::compute_event_topic0(&e.name, &e.params));
                selector == topic0_norm
            })
            .ok_or_else(|| format!("no matching event for topic0 '{}'", topics[0]))?;

        // Independent cursors for topics and data.
        let mut topic_cursor = 1usize; // skip topic0 (event selector)
        let mut data_offset  = 0usize;
        let mut decoded = Vec::with_capacity(event.params.len());

        for param in &event.params {
            let value = if param.indexed {
                // Indexed param → next topic in order.
                if topic_cursor >= topics.len() {
                    return Err(format!(
                        "event '{}' declares indexed param '{}' but log has no \
                         matching topic (topic_cursor={}, topics.len()={})",
                        event.name, param.name, topic_cursor, topics.len()
                    ));
                }
                let v = topics[topic_cursor].clone();
                topic_cursor += 1;
                v
            } else {
                // Non-indexed param → next slice of `data` according
                // to the param type, mirroring decode_return's rules.
                match Self::expected_arg_size(&param.abi_type) {
                    Some(s) => {
                        if data_offset + s > data.len() {
                            return Err(format!(
                                "event '{}' data too short for non-indexed \
                                 param '{}' (need {} bytes at offset {}, \
                                 data.len()={})",
                                event.name, param.name, s, data_offset, data.len()
                            ));
                        }
                        let encoded = hex::encode(&data[data_offset..data_offset + s]);
                        data_offset += s;
                        encoded
                    }
                    None => {
                        // Variable-length non-indexed params eat the
                        // remainder. This matches decode_return and is
                        // why every event should have at most one
                        // trailing variable-length non-indexed param.
                        let encoded = hex::encode(&data[data_offset..]);
                        data_offset = data.len();
                        encoded
                    }
                }
            };
            decoded.push((param.name.clone(), value));
        }

        Ok(DecodedEvent {
            name: event.name.clone(),
            params: decoded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_abi() -> ContractAbi {
        let mut abi = ContractAbi::new("TestToken");
        abi.add_function("transfer",
            vec![
                AbiParam { name: "to".into(), abi_type: AbiType::Address, indexed: false },
                AbiParam { name: "amount".into(), abi_type: AbiType::Uint64, indexed: false },
            ],
            vec![AbiParam { name: "success".into(), abi_type: AbiType::Bool, indexed: false }],
            Mutability::Mutable,
        );
        abi.add_function("balance_of",
            vec![AbiParam { name: "owner".into(), abi_type: AbiType::Address, indexed: false }],
            vec![AbiParam { name: "balance".into(), abi_type: AbiType::Uint64, indexed: false }],
            Mutability::View,
        );
        abi.add_event("Transfer", vec![
            AbiParam { name: "from".into(), abi_type: AbiType::Address, indexed: true },
            AbiParam { name: "to".into(), abi_type: AbiType::Address, indexed: true },
            AbiParam { name: "amount".into(), abi_type: AbiType::Uint64, indexed: false },
        ]);
        abi
    }

    #[test]
    fn abi_creation() {
        let abi = make_abi();
        assert_eq!(abi.functions.len(), 2);
        assert_eq!(abi.events.len(), 1);
    }

    #[test]
    fn selector_deterministic() {
        let abi = make_abi();
        let f1 = abi.find_by_name("transfer").unwrap();
        let f2 = abi.find_by_name("transfer").unwrap();
        assert_eq!(f1.selector, f2.selector);
    }

    #[test]
    fn find_by_selector() {
        let abi = make_abi();
        let transfer = abi.find_by_name("transfer").unwrap();
        let found = abi.find_by_selector(&transfer.selector).unwrap();
        assert_eq!(found.name, "transfer");
    }

    #[test]
    fn different_functions_different_selectors() {
        let abi = make_abi();
        let transfer = abi.find_by_name("transfer").unwrap();
        let balance = abi.find_by_name("balance_of").unwrap();
        assert_ne!(transfer.selector, balance.selector);
    }

    #[test]
    fn encode_call() {
        let abi = make_abi();
        let data = abi.encode_call("transfer", &[
            b"SD1address".to_vec(),
            1000u64.to_be_bytes().to_vec(),
        ]).unwrap();
        assert!(data.len() >= 4);
    }

    #[test]
    fn encode_wrong_args_fails() {
        let abi = make_abi();
        assert!(abi.encode_call("transfer", &[b"only_one".to_vec()]).is_err());
    }

    #[test]
    fn json_roundtrip() {
        let abi = make_abi();
        let json = abi.to_json().expect("to_json must succeed on a well-formed ABI");
        let restored = ContractAbi::from_json(&json).unwrap();
        assert_eq!(restored.name, "TestToken");
        assert_eq!(restored.functions.len(), 2);
        assert_eq!(restored.events.len(), 1);
    }

    #[test]
    fn to_json_returns_result_not_empty_string() {
        // Regression for the fail-silent-on-serialize pattern. The old
        // `to_json` returned `String`, masking any serde failure as an
        // empty string that `save_verification` then stored in the
        // contract DB as `abi_json: ""`. With the new signature, the
        // happy path is an Ok with valid JSON — an empty string is
        // never returned.
        let abi = make_abi();
        let json = abi.to_json().unwrap();
        assert!(!json.is_empty(), "to_json must not return an empty string on success");
        assert!(json.starts_with('{'), "to_json must return JSON object");
    }

    #[test]
    fn decode_selector_from_data() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02];
        let sel = ContractAbi::decode_selector(&data).unwrap();
        assert_eq!(sel, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn abi_type_from_str_resolves_known_types() {
        assert_eq!(AbiType::from_str("uint64").unwrap(), AbiType::Uint64);
        assert_eq!(AbiType::from_str("uint").unwrap(),   AbiType::Uint64);
        assert_eq!(AbiType::from_str("int64").unwrap(),  AbiType::Int64);
        assert_eq!(AbiType::from_str("int").unwrap(),    AbiType::Int64);
        assert_eq!(AbiType::from_str("bool").unwrap(),   AbiType::Bool);
        assert_eq!(AbiType::from_str("string").unwrap(), AbiType::String);
        assert_eq!(AbiType::from_str("bytes").unwrap(),  AbiType::Bytes);
        assert_eq!(AbiType::from_str("address").unwrap(), AbiType::Address);
    }

    #[test]
    fn abi_type_from_str_rejects_unknown_types() {
        // Regression for the silent-default-to-Bytes bug. A typo like
        // "uint66" or an aspirational type like "uint256" must produce
        // an error, not be quietly coerced to Bytes (which would change
        // the encoding semantics of every call that uses it).
        assert!(AbiType::from_str("uint66").is_err());
        assert!(AbiType::from_str("uint256").is_err());
        assert!(AbiType::from_str("UINT64").is_err()); // case-sensitive
        assert!(AbiType::from_str("").is_err());
        assert!(AbiType::from_str("garbage").is_err());

        // The error message must mention the offending name so users
        // can fix the typo, and list the accepted alternatives.
        let err = AbiType::from_str("uint66").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("uint66"), "error must include the offending name, got: {}", msg);
        assert!(msg.contains("uint64"), "error must list the accepted alternatives, got: {}", msg);
    }

    // ─── decode_event regression tests ──────────────────────────────
    //
    // These tests pin the three bugs the decoder used to have:
    //   1. topic0 matched by bidirectional `starts_with`
    //   2. `indexed` flag ignored in favor of positional indexing
    //   3. full `data` blob replicated across every non-indexed param

    /// Build an ABI whose only event has a NON-leading indexed layout:
    ///   NonLeadingIndexed(uint64 amount /* non-indexed */, address from /* indexed */)
    /// This is the exact shape the old decoder silently mis-swapped.
    fn abi_with_non_leading_indexed_event() -> ContractAbi {
        let mut abi = ContractAbi::new("NonLeadingIndexedTest");
        abi.add_event("NonLeadingIndexed", vec![
            AbiParam { name: "amount".into(), abi_type: AbiType::Uint64,  indexed: false },
            AbiParam { name: "from".into(),   abi_type: AbiType::Address, indexed: true  },
        ]);
        abi
    }

    /// Compute the full 32-byte event topic0 for an event in `abi` by
    /// name. Mirrors what `event_log::EventCollector` would emit as
    /// topic0 on a LOG1+ for this event.
    fn event_topic0_hex(abi: &ContractAbi, event_name: &str) -> String {
        let ev = abi.events.iter().find(|e| e.name == event_name).expect("event present");
        hex::encode(ContractAbi::compute_event_topic0(&ev.name, &ev.params))
    }

    #[test]
    fn decode_event_honors_indexed_flag_on_non_leading_layout() {
        // Regression for the positional-indexing bug. The old decoder
        // used `i + 1 < topics.len()` as a proxy for "this param is
        // indexed", which was wrong for a param declared as
        // non-indexed followed by an indexed param.
        let abi = abi_with_non_leading_indexed_event();
        let topic0 = event_topic0_hex(&abi, "NonLeadingIndexed");

        // Real log would carry topic0 + one indexed topic for `from`.
        // Per event_log::EventCollector, each topic is a 64-char hex
        // string — construct a plausible address-shaped topic1.
        let topic1 = "f".repeat(64);

        // `amount` is non-indexed → comes from `data` as 8 BE bytes.
        let amount_bytes: [u8; 8] = 1234u64.to_be_bytes();

        let topics = vec![topic0, topic1.clone()];
        let decoded = abi.decode_event(&topics, &amount_bytes).unwrap();

        assert_eq!(decoded.name, "NonLeadingIndexed");
        assert_eq!(decoded.params.len(), 2);

        // `amount` (declared first, non-indexed) MUST decode from data,
        // not from topics[1]. Old code pulled topics[1] here.
        assert_eq!(decoded.params[0].0, "amount");
        assert_eq!(decoded.params[0].1, hex::encode(amount_bytes));

        // `from` (declared second, indexed) MUST decode from topics[1],
        // not from hex::encode(data). Old code pulled hex::encode(data)
        // here.
        assert_eq!(decoded.params[1].0, "from");
        assert_eq!(decoded.params[1].1, topic1);
    }

    #[test]
    fn decode_event_strict_equality_rejects_prefix_collision() {
        // Regression for the `starts_with` bug. The old matcher
        // accepted empty topic0, short topic0 that is a prefix of a
        // selector, and long topic0 that a selector is a prefix of.
        let abi = abi_with_non_leading_indexed_event();
        let real_topic0 = event_topic0_hex(&abi, "NonLeadingIndexed");
        let amount_bytes: [u8; 8] = 0u64.to_be_bytes();
        let topic1 = "a".repeat(64);

        // (1) empty topic0 → must NOT match anything
        {
            let topics = vec!["".to_string(), topic1.clone()];
            assert!(abi.decode_event(&topics, &amount_bytes).is_err(),
                "empty topic0 must not match any event");
        }

        // (2) short topic0 that is a prefix of the real selector → must NOT match
        {
            let short = real_topic0[..8].to_string();
            let topics = vec![short, topic1.clone()];
            assert!(abi.decode_event(&topics, &amount_bytes).is_err(),
                "byte-prefix of the real selector must not match the event");
        }

        // (3) long topic0 that the real selector is a prefix of → must NOT match
        {
            let long = format!("{}deadbeef", real_topic0);
            let topics = vec![long, topic1.clone()];
            assert!(abi.decode_event(&topics, &amount_bytes).is_err(),
                "super-string of the real selector must not match the event");
        }

        // (4) the real full-length topic0 → matches
        {
            let topics = vec![real_topic0.clone(), topic1];
            let decoded = abi.decode_event(&topics, &amount_bytes).unwrap();
            assert_eq!(decoded.name, "NonLeadingIndexed");
        }
    }

    #[test]
    fn decode_event_accepts_0x_prefixed_topic0() {
        let abi = abi_with_non_leading_indexed_event();
        let topic0 = event_topic0_hex(&abi, "NonLeadingIndexed");
        let amount_bytes: [u8; 8] = 0u64.to_be_bytes();
        let topic1 = "a".repeat(64);

        let topics = vec![format!("0x{}", topic0), topic1];
        let decoded = abi.decode_event(&topics, &amount_bytes).unwrap();
        assert_eq!(decoded.name, "NonLeadingIndexed");
    }

    #[test]
    fn decode_event_splits_data_across_multiple_non_indexed_params() {
        // Regression for the "full data blob duplicated into every
        // non-indexed param" bug. The old decoder wrote
        // `hex::encode(data)` into every non-indexed param, so two
        // non-indexed params both got the entire blob. The new
        // decoder walks `data` by `expected_arg_size` so each
        // fixed-width non-indexed param slices its own segment.
        let mut abi = ContractAbi::new("TwoFixedDataFields");
        abi.add_event("TwoFixed", vec![
            AbiParam { name: "a".into(), abi_type: AbiType::Uint64, indexed: false },
            AbiParam { name: "b".into(), abi_type: AbiType::Uint64, indexed: false },
        ]);

        let topic0 = event_topic0_hex(&abi, "TwoFixed");
        // 16 bytes: first 8 = 1u64, next 8 = 2u64
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(&2u64.to_be_bytes());

        let topics = vec![topic0];
        let decoded = abi.decode_event(&topics, &data).unwrap();
        assert_eq!(decoded.params[0], ("a".into(), hex::encode(1u64.to_be_bytes())));
        assert_eq!(decoded.params[1], ("b".into(), hex::encode(2u64.to_be_bytes())));
    }

    #[test]
    fn decode_event_errors_on_data_too_short() {
        // Fail-loud when the encoded data is shorter than the fixed
        // non-indexed params can consume.
        let mut abi = ContractAbi::new("Short");
        abi.add_event("Short", vec![
            AbiParam { name: "a".into(), abi_type: AbiType::Uint64, indexed: false },
        ]);
        let topic0 = event_topic0_hex(&abi, "Short");

        // 4 bytes — not enough for a uint64 (8 bytes)
        let short_data = vec![0u8; 4];
        let topics = vec![topic0];
        let err = abi.decode_event(&topics, &short_data).unwrap_err();
        assert!(err.contains("data too short"), "got: {}", err);
    }

    #[test]
    fn decode_event_errors_on_missing_indexed_topic() {
        // Event declares an indexed param but the log doesn't include
        // the matching topic.
        let mut abi = ContractAbi::new("MissingTopic");
        abi.add_event("MissingTopic", vec![
            AbiParam { name: "from".into(), abi_type: AbiType::Address, indexed: true },
        ]);
        let topic0 = event_topic0_hex(&abi, "MissingTopic");

        let topics = vec![topic0]; // no topic1 even though `from` is indexed
        let err = abi.decode_event(&topics, &[]).unwrap_err();
        assert!(err.contains("indexed param"), "got: {}", err);
    }
}
