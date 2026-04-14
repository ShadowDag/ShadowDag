// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Merkle Verifier — uses the exact same Blake2b-256 with personalization
// and LEAF_TAG/BRANCH_TAG domain separation as MerkleTree.

use blake2b_simd::Params;

use crate::domain::block::merkle_proof::MerkleProof;

/// Must match merkle_tree.rs exactly
const LEAF_PERSON: &[u8; 16] = b"ShadowMerkleLeaf";
const BRANCH_PERSON: &[u8; 16] = b"ShadowMerkleBrch";
const LEAF_TAG: u8 = 0x00;
const BRANCH_TAG: u8 = 0x01;

pub struct MerkleVerifier;

impl MerkleVerifier {
    pub fn verify(tx_hash: String, proof: &MerkleProof, merkle_root: String) -> bool {
        let raw = match Self::strict_decode_hash(&tx_hash) {
            Some(bytes) => bytes,
            None => return false,
        };
        let mut current = Self::hash_leaf(&raw);

        let mut index = proof.index;

        for sibling_hex in &proof.hashes {
            let sibling = match Self::strict_decode_hash(sibling_hex) {
                Some(bytes) => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                None => return false,
            };

            current = if index.is_multiple_of(2) {
                // We are left child, sibling is right
                Self::hash_branch(&current, &sibling)
            } else {
                // We are right child, sibling is left
                Self::hash_branch(&sibling, &current)
            };

            index /= 2;
        }

        hex::encode(current) == merkle_root
    }

    /// Hash a leaf node — matches MerkleTree::hash_leaf exactly
    #[inline]
    fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let hash = Params::new()
            .hash_length(32)
            .personal(LEAF_PERSON)
            .to_state()
            .update(&[LEAF_TAG])
            .update(data)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    /// Hash a branch — matches MerkleTree::hash_branch exactly
    #[inline]
    fn hash_branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let hash = Params::new()
            .hash_length(32)
            .personal(BRANCH_PERSON)
            .to_state()
            .update(&[BRANCH_TAG])
            .update(left)
            .update(right)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    /// Decode hex hash to bytes, returning None on invalid input
    #[inline]
    fn strict_decode_hash(hex_str: &str) -> Option<Vec<u8>> {
        crate::domain::types::hash::parse_hash256(hex_str)
            .ok()
            .map(|b| b.to_vec())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::domain::block::merkle_tree::MerkleTree;

    #[test]
    fn verifier_matches_tree_proof() {
        let hashes = vec![
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(32),
            "dd".repeat(32),
        ];
        let root = MerkleTree::calculate_root(hashes.clone());

        // Generate proof from MerkleTree, convert to MerkleProof format
        for i in 0..hashes.len() {
            let proof_pairs = MerkleTree::generate_proof(&hashes, i).unwrap();
            let proof =
                MerkleProof::new(proof_pairs.iter().map(|(h, _)| hex::encode(h)).collect(), i);

            assert!(
                MerkleVerifier::verify(hashes[i].clone(), &proof, root.clone()),
                "Verifier must match tree for index {}",
                i
            );
        }
    }

    #[test]
    fn verifier_rejects_wrong_hash() {
        let hashes = vec!["aa".repeat(32), "bb".repeat(32)];
        let root = MerkleTree::calculate_root(hashes.clone());
        let proof_pairs = MerkleTree::generate_proof(&hashes, 0).unwrap();
        let proof = MerkleProof::new(proof_pairs.iter().map(|(h, _)| hex::encode(h)).collect(), 0);

        assert!(
            !MerkleVerifier::verify("ff".repeat(32), &proof, root),
            "Must reject wrong tx hash"
        );
    }

    #[test]
    fn verifier_rejects_wrong_root() {
        let hashes = vec!["aa".repeat(32), "bb".repeat(32)];
        let proof_pairs = MerkleTree::generate_proof(&hashes, 0).unwrap();
        let proof = MerkleProof::new(proof_pairs.iter().map(|(h, _)| hex::encode(h)).collect(), 0);

        assert!(
            !MerkleVerifier::verify(hashes[0].clone(), &proof, "ff".repeat(32)),
            "Must reject wrong root"
        );
    }

    #[test]
    fn verifier_rejects_malformed_hex() {
        let proof = MerkleProof::new(vec![], 0);
        assert!(!MerkleVerifier::verify(
            "not_valid_hex".to_string(),
            &proof,
            "aa".repeat(32)
        ));
    }
}
