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

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "uint64" | "uint"   => AbiType::Uint64,
            "int64" | "int"     => AbiType::Int64,
            "bool"              => AbiType::Bool,
            "string"            => AbiType::String,
            "bytes"             => AbiType::Bytes,
            "address"           => AbiType::Address,
            _                   => AbiType::Bytes, // Default
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

    /// Compute 4-byte function selector from name + input types
    fn compute_selector(name: &str, inputs: &[AbiParam]) -> [u8; 4] {
        let sig = format!("{}({})", name,
            inputs.iter().map(|p| p.abi_type.name().to_string()).collect::<Vec<_>>().join(",")
        );
        let mut h = Sha256::new();
        h.update(sig.as_bytes());
        let hash = h.finalize();
        [hash[0], hash[1], hash[2], hash[3]]
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
    /// Logs a structured error if serialization fails rather than silently
    /// returning an empty string.
    pub fn to_json(&self) -> String {
        match serde_json::to_string_pretty(self) {
            Ok(s) => s,
            Err(e) => {
                slog_error!("vm", "abi_to_json_failed", error => &e.to_string());
                String::new()
            }
        }
    }

    /// Deserialize ABI from JSON
    pub fn from_json(json: &str) -> Result<Self, VmError> {
        serde_json::from_str(json).map_err(|e| VmError::ContractError(format!("ABI parse error: {}", e)))
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
        let json = abi.to_json();
        let restored = ContractAbi::from_json(&json).unwrap();
        assert_eq!(restored.name, "TestToken");
        assert_eq!(restored.functions.len(), 2);
        assert_eq!(restored.events.len(), 1);
    }

    #[test]
    fn decode_selector_from_data() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02];
        let sel = ContractAbi::decode_selector(&data).unwrap();
        assert_eq!(sel, [0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
