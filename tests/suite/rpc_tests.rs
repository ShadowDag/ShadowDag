// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::infrastructure::storage::rocksdb::core::db::NodeDB;
    use crate::service::network::rpc::rpc_server::RpcServer;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db_path() -> String {
        format!(
            "/tmp/test_rpc_ext_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }

    fn make_server() -> RpcServer {
        let path = temp_db_path();
        let node_db = NodeDB::new(&path).unwrap();
        let peers_path = format!("{}_peers", path);
        RpcServer::new_for_network(0, &peers_path, node_db.shared()).unwrap()
    }

    fn rpc_call(server: &mut RpcServer, method: &str, params: Vec<Value>) -> Value {
        let req = json!({
            "jsonrpc": "2.0",
            "method":  method,
            "params":  params,
            "id":      1,
        });
        let resp_str = server.handle(&req.to_string());
        serde_json::from_str(&resp_str).unwrap_or(json!({}))
    }

    #[test]
    fn getblockcount_returns_zero_at_start() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getblockcount", vec![]);
        assert_eq!(resp["result"], json!(0_u64));
        assert!(resp["error"].is_null());
    }

    #[test]
    fn getbestblockhash_empty_at_start() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getbestblockhash", vec![]);
        assert_eq!(resp["result"], json!(""));
    }

    #[test]
    fn unknown_method_returns_error() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "fakemethod", vec![]);
        assert!(resp["error"].is_object());
        assert_eq!(resp["error"]["code"], json!(-32601));
    }

    #[test]
    fn getblock_missing_hash_returns_invalid_params() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getblock", vec![]);
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[test]
    fn getblock_unknown_hash_returns_not_found() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getblock", vec![json!("nonexistent_hash")]);
        assert_eq!(resp["error"]["code"], json!(-5));
    }

    #[test]
    fn getbalance_missing_address_returns_error() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getbalance", vec![]);
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[test]
    fn getpeerinfo_returns_array() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getpeerinfo", vec![]);
        assert!(resp["result"].is_array());
    }

    #[test]
    fn getmempoolinfo_returns_size() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getmempoolinfo", vec![]);
        assert!(resp["result"]["size"].is_number());
        assert_eq!(resp["result"]["max_size"], json!(100_000_u64));
    }

    #[test]
    fn getminerinfo_returns_reward() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getminerinfo", vec![]);
        assert!(resp["result"]["block_reward"].is_number());
    }

    #[test]
    fn getnetworkinfo_returns_version() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "getnetworkinfo", vec![]);
        assert!(resp["result"]["version"].is_string());
        assert_eq!(resp["result"]["best_height"], json!(0_u64));
    }

    #[test]
    fn sendrawtransaction_invalid_json_rejected() {
        let mut server = make_server();
        let resp = rpc_call(&mut server, "sendrawtransaction", vec![json!("not-json")]);
        assert!(resp["error"].is_object());
    }
}
