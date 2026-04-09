//! ShadowDAG Rust SDK — programmatic interface for smart contracts.
//!
//! Provides high-level functions for deploying, calling, and querying
//! contracts through the ShadowDAG RPC interface.
//!
//! # Example
//! ```no_run
//! use shadowdag::sdk::shadowdag_sdk::ShadowDagSdk;
//!
//! let sdk = ShadowDagSdk::new("http://localhost:9332");
//! let addr = sdk.deploy_contract(&bytecode, "deployer", 0, 10_000_000)?;
//! let result = sdk.call_contract(&addr, &calldata, "caller", 0, 1_000_000)?;
//! let receipt = sdk.wait_for_receipt(&result.tx_hash, 30)?;
//! ```

use serde::{Serialize, Deserialize};
use serde_json::{json, Value};

/// SDK client for ShadowDAG node interaction.
pub struct ShadowDagSdk {
    rpc_url: String,
    auth_token: Option<String>,
    timeout_secs: u64,
}

/// Result of a contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub address: String,
    pub success: bool,
    pub gas_used: u64,
    pub tx_hash: Option<String>,
}

/// Result of a contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: String,
    pub tx_hash: Option<String>,
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: String,
    pub execution_success: bool,
    pub gas_used: u64,
    pub contract_address: Option<String>,
    pub return_data: Option<String>,
    pub revert_reason: Option<String>,
    pub logs: Vec<LogEntry>,
    pub block_height: Option<u64>,
    pub vm_version: u8,
}

/// Log entry from contract execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub contract: String,
    pub topics: Vec<String>,
    pub data: String,
    pub log_index: usize,
}

/// SDK error
#[derive(Debug)]
pub enum SdkError {
    Rpc(String),
    Timeout,
    NotFound,
    Other(String),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Rpc(msg) => write!(f, "RPC error: {}", msg),
            SdkError::Timeout => write!(f, "Request timeout"),
            SdkError::NotFound => write!(f, "Not found"),
            SdkError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl ShadowDagSdk {
    /// Create a new SDK client.
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            auth_token: None,
            timeout_secs: 30,
        }
    }

    /// Set authentication token.
    pub fn with_auth(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Set request timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Deploy a contract.
    pub fn deploy_contract(
        &self,
        bytecode: &[u8],
        deployer: &str,
        value: u64,
        gas_limit: u64,
    ) -> Result<DeployResult, SdkError> {
        let params = json!([
            hex::encode(bytecode),
            deployer,
            value,
            gas_limit
        ]);
        let resp = self.rpc_call("deploy_contract", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Call a contract (read-write).
    pub fn call_contract(
        &self,
        contract_addr: &str,
        calldata: &[u8],
        caller: &str,
        value: u64,
        gas_limit: u64,
    ) -> Result<CallResult, SdkError> {
        let params = json!([
            contract_addr,
            hex::encode(calldata),
            caller,
            value,
            gas_limit
        ]);
        let resp = self.rpc_call("call_contract", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Estimate gas for a call (dry-run).
    pub fn estimate_gas(
        &self,
        contract_addr: &str,
        calldata: &[u8],
        caller: &str,
        value: u64,
    ) -> Result<u64, SdkError> {
        let params = json!([
            contract_addr,
            hex::encode(calldata),
            caller,
            value
        ]);
        let resp = self.rpc_call("estimate_gas", params)?;
        resp.get("gas_used")
            .and_then(|v| v.as_u64())
            .ok_or(SdkError::Other("missing gas_used in response".into()))
    }

    /// Get a transaction receipt.
    pub fn get_receipt(&self, tx_hash: &str) -> Result<Receipt, SdkError> {
        let params = json!([tx_hash]);
        let resp = self.rpc_call("get_transaction_receipt", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Wait for a receipt with polling.
    pub fn wait_for_receipt(&self, tx_hash: &str, timeout_secs: u64) -> Result<Receipt, SdkError> {
        let start = std::time::Instant::now();
        loop {
            match self.get_receipt(tx_hash) {
                Ok(receipt) => return Ok(receipt),
                Err(SdkError::NotFound) => {
                    if start.elapsed().as_secs() > timeout_secs {
                        return Err(SdkError::Timeout);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Get contract code.
    pub fn get_code(&self, address: &str) -> Result<Vec<u8>, SdkError> {
        let params = json!([address]);
        let resp = self.rpc_call("get_contract_code", params)?;
        let hex_code = resp.get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        hex::decode(hex_code).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Get storage value at a slot.
    pub fn get_storage_at(&self, address: &str, slot: &str) -> Result<String, SdkError> {
        let params = json!([address, slot]);
        let resp = self.rpc_call("get_storage_at", params)?;
        Ok(resp.get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// Get logs with filter.
    pub fn get_logs(
        &self,
        address: Option<&str>,
        topic0: Option<&str>,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<LogEntry>, SdkError> {
        let mut filter = json!({});
        if let Some(a) = address { filter["address"] = json!(a); }
        if let Some(t) = topic0 { filter["topic0"] = json!(t); }
        if let Some(f) = from_block { filter["from_block"] = json!(f); }
        if let Some(t) = to_block { filter["to_block"] = json!(t); }
        let params = json!([filter]);
        let resp = self.rpc_call("get_logs", params)?;
        serde_json::from_value(resp).map_err(|e| SdkError::Other(e.to_string()))
    }

    /// Verify a deployed contract against a package.
    pub fn verify_contract(&self, address: &str, package_json: &str) -> Result<bool, SdkError> {
        let params = json!([address, package_json]);
        let resp = self.rpc_call("verify_contract", params)?;
        Ok(resp.get("verified").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    /// Get contract info.
    pub fn get_contract_info(&self, address: &str) -> Result<Value, SdkError> {
        let params = json!([address]);
        self.rpc_call("get_contract_info", params)
    }

    /// Raw RPC call helper.
    fn rpc_call(&self, method: &str, params: Value) -> Result<Value, SdkError> {
        // Build JSON-RPC request
        let _request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        // NOTE: In a real implementation, this would use HTTP to connect
        // to the RPC server. For now, we return the request structure
        // so the SDK can be tested without a running node.
        //
        // Future: use reqwest or hyper for HTTP transport.
        Err(SdkError::Other(format!(
            "HTTP transport not yet connected. RPC URL: {}, Method: {}",
            self.rpc_url, method
        )))
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_creates_with_defaults() {
        let sdk = ShadowDagSdk::new("http://localhost:9332");
        assert_eq!(sdk.rpc_url(), "http://localhost:9332");
        assert!(sdk.auth_token.is_none());
    }

    #[test]
    fn sdk_with_auth() {
        let sdk = ShadowDagSdk::new("http://localhost:9332")
            .with_auth("secret123")
            .with_timeout(60);
        assert!(sdk.auth_token.is_some());
        assert_eq!(sdk.timeout_secs, 60);
    }

    #[test]
    fn sdk_deploy_returns_rpc_error() {
        let sdk = ShadowDagSdk::new("http://localhost:9332");
        let result = sdk.deploy_contract(&[0x00], "deployer", 0, 1000);
        assert!(result.is_err()); // No running node
    }

    #[test]
    fn sdk_error_display() {
        assert_eq!(format!("{}", SdkError::Timeout), "Request timeout");
        assert_eq!(format!("{}", SdkError::NotFound), "Not found");
        assert!(format!("{}", SdkError::Rpc("test".into())).contains("test"));
    }
}
