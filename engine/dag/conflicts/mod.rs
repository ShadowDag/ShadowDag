// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq)]
pub enum ConflictStatus {
    Blue,
    Red,
    Pending,
}

#[derive(Debug, Clone)]
pub struct ConflictEntry {
    pub hash: String,
    pub parents: Vec<String>,
    pub status: ConflictStatus,
    pub inputs: Vec<String>,
}

pub struct ConflictResolver {
    entries: HashMap<String, ConflictEntry>,
    spend_map: HashMap<String, HashSet<String>>,
}

impl Default for ConflictResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ConflictResolver {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            spend_map: HashMap::new(),
        }
    }

    pub fn register(&mut self, hash: &str, parents: Vec<String>, inputs: Vec<String>) {
        if self.entries.contains_key(hash) {
            return;
        }

        let hash_str = hash.to_string();

        // إزالة التكرار
        let unique_inputs: HashSet<String> = inputs.iter().cloned().collect();

        if unique_inputs.is_empty() {
            self.entries.insert(
                hash_str.clone(),
                ConflictEntry {
                    hash: hash_str,
                    parents,
                    status: ConflictStatus::Pending,
                    inputs,
                },
            );
            return;
        }

        for input in &unique_inputs {
            self.spend_map
                .entry(input.clone())
                .or_default()
                .insert(hash_str.clone());
        }

        self.entries.insert(
            hash_str.clone(),
            ConflictEntry {
                hash: hash_str,
                parents,
                status: ConflictStatus::Pending,
                inputs,
            },
        );
    }

    // 💣 clustering
    pub fn find_conflicts(&self) -> Vec<Vec<String>> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut result = Vec::new();

        for blocks in self.spend_map.values() {
            for block in blocks {
                if visited.contains(block) {
                    continue;
                }

                let mut stack = vec![block.clone()];
                let mut cluster: HashSet<String> = HashSet::new();

                while let Some(b) = stack.pop() {
                    if !cluster.insert(b.clone()) {
                        continue;
                    }

                    let entry = match self.entries.get(&b) {
                        Some(e) => e,
                        None => continue,
                    };

                    for input in &entry.inputs {
                        if let Some(spenders) = self.spend_map.get(input) {
                            for s in spenders {
                                if !cluster.contains(s) {
                                    stack.push(s.clone());
                                }
                            }
                        }
                    }
                }

                if cluster.len() <= 1 {
                    continue;
                }

                visited.extend(cluster.iter().cloned());

                let mut v: Vec<String> = cluster.into_iter().collect();
                v.sort();
                result.push(v);
            }
        }

        result
    }

    pub fn has_conflict(&self, hash: &str) -> bool {
        let entry = match self.entries.get(hash) {
            Some(e) => e,
            None => return false,
        };

        entry.inputs.iter().any(|input| {
            self.spend_map
                .get(input)
                .is_some_and(|spenders| spenders.len() > 1)
        })
    }

    pub fn resolve_cluster(
        &mut self,
        cluster: &[String],
        blue_scores: &HashMap<String, u64>,
    ) -> Option<String> {
        if cluster.is_empty() {
            return None;
        }

        let mut best_hash: Option<String> = None;
        let mut best_score: u64 = 0;

        for h in cluster {
            if !self.entries.contains_key(h) {
                continue;
            }

            let score = *blue_scores.get(h).unwrap_or(&0);

            match &best_hash {
                Some(current_best) => {
                    // نجيب score الحالي مرة وحدة
                    let current_score = best_score;

                    if score > current_score || (score == current_score && h > current_best) {
                        best_hash = Some(h.clone());
                        best_score = score;
                    }
                }
                None => {
                    best_hash = Some(h.clone());
                    best_score = score;
                }
            }
        }

        let winner = best_hash?;

        for h in cluster {
            if let Some(e) = self.entries.get_mut(h) {
                e.status = if *h == winner {
                    ConflictStatus::Blue
                } else {
                    ConflictStatus::Red
                };
            }
        }

        Some(winner)
    }

    pub fn resolve_pair(
        &mut self,
        hash_a: &str,
        hash_b: &str,
        blue_score_a: u64,
        blue_score_b: u64,
    ) -> String {
        let winner = if blue_score_a >= blue_score_b {
            hash_a
        } else {
            hash_b
        };
        let loser = if winner == hash_a { hash_b } else { hash_a };

        if let Some(e) = self.entries.get_mut(winner) {
            e.status = ConflictStatus::Blue;
        }
        if let Some(e) = self.entries.get_mut(loser) {
            e.status = ConflictStatus::Red;
        }

        winner.to_string()
    }

    pub fn status(&self, hash: &str) -> Option<&ConflictStatus> {
        self.entries.get(hash).map(|e| &e.status)
    }

    pub fn is_blue(&self, hash: &str) -> bool {
        self.entries
            .get(hash)
            .map(|e| e.status == ConflictStatus::Blue)
            .unwrap_or(false)
    }

    pub fn is_red(&self, hash: &str) -> bool {
        self.entries
            .get(hash)
            .map(|e| e.status == ConflictStatus::Red)
            .unwrap_or(false)
    }

    pub fn blue_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.status == ConflictStatus::Blue)
            .count()
    }

    pub fn red_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.status == ConflictStatus::Red)
            .count()
    }

    pub fn pending_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.status == ConflictStatus::Pending)
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_merged_cluster() {
        let mut res = ConflictResolver::new();

        res.register("b1", vec![], vec!["u1".into()]);
        res.register("b2", vec![], vec!["u1".into(), "u2".into()]);
        res.register("b3", vec![], vec!["u2".into()]);

        let clusters = res.find_conflicts();

        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].len(), 3);
    }

    #[test]
    fn resolve_cluster_correctly() {
        let mut res = ConflictResolver::new();

        res.register("b1", vec![], vec!["u".into()]);
        res.register("b2", vec![], vec!["u".into()]);
        res.register("b3", vec![], vec!["u".into()]);

        let cluster = res.find_conflicts().pop().unwrap();

        let mut scores = HashMap::new();
        scores.insert("b1".into(), 5);
        scores.insert("b2".into(), 10);
        scores.insert("b3".into(), 7);

        let winner = res.resolve_cluster(&cluster, &scores).unwrap();

        assert_eq!(winner, "b2");
    }
}
