// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};
use crate::domain::transaction::transaction::Transaction;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
}
