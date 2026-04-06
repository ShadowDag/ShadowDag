// ═══════════════════════════════════════════════════════════════════════════
//  Utility: Mine the genesis block and print the hardcoded constants
// ═══════════════════════════════════════════════════════════════════════════

use shadowdag::config::genesis::genesis::{
    create_genesis_block, create_genesis_block_for, genesis_info,
};
use shadowdag::config::node::node_config::NetworkMode;

fn main() {
    println!("Mining Mainnet Genesis...");
    let g = create_genesis_block();
    println!("MAINNET NONCE = {}", g.header.nonce);
    println!("MAINNET HASH  = {}", g.header.hash);
    println!("MAINNET MROOT = {}", g.header.merkle_root);
    println!("MAINNET CBTX  = {}", g.body.transactions[0].hash);
    println!();

    println!("{}", genesis_info(&NetworkMode::Mainnet));
    println!();

    println!("Mining Testnet Genesis...");
    let t = create_genesis_block_for(&NetworkMode::Testnet);
    println!("TESTNET NONCE = {}", t.header.nonce);
    println!("TESTNET HASH  = {}", t.header.hash);
    println!();

    println!("Mining Regtest Genesis...");
    let r = create_genesis_block_for(&NetworkMode::Regtest);
    println!("REGTEST NONCE = {}", r.header.nonce);
    println!("REGTEST HASH  = {}", r.header.hash);
}
