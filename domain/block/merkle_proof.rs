// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub hashes: Vec<String>,
    pub index:  usize,
}

impl MerkleProof {
    pub fn new(hashes: Vec<String>, index: usize) -> Self {
        Self { hashes, index }
    }
}
