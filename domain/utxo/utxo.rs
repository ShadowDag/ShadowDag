// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Utxo {
    pub owner: String,
    pub address: String,
    pub amount: u64,
    pub spent: bool,
}

impl Utxo {
    pub fn new(owner: String, address: String, amount: u64) -> Self {
        Self {
            owner,
            address,
            amount,
            spent: false,
        }
    }

    pub fn spend(&mut self) {
        self.spent = true;
    }

    pub fn is_spent(&self) -> bool {
        self.spent
    }
}
