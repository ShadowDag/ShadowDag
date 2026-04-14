// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub struct ColumnFamilies;

impl ColumnFamilies {
    pub const BLOCKS: &'static str = "blocks";
    pub const HEADERS: &'static str = "headers";
    pub const TRANSACTIONS: &'static str = "transactions";
    pub const UTXO: &'static str = "utxo";
    pub const DAG: &'static str = "dag";
    pub const GHOSTDAG: &'static str = "ghostdag";
    pub const METADATA: &'static str = "metadata";

    pub fn all() -> Vec<&'static str> {
        vec![
            Self::BLOCKS,
            Self::HEADERS,
            Self::TRANSACTIONS,
            Self::UTXO,
            Self::DAG,
            Self::GHOSTDAG,
            Self::METADATA,
        ]
    }
}
