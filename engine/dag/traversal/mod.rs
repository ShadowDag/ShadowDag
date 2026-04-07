// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};

use crate::errors::DagError;

pub const MAX_TRAVERSAL_DEPTH: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub enum TraversalOrder {
    BreadthFirst,
    DepthFirst,
    TopologicalSort,
}

#[derive(Debug, Clone)]
pub struct DagNode {
    pub hash: String,
    pub parents: Vec<String>,
    pub height: u64,
}

pub struct DagTraversal {
    nodes: HashMap<String, DagNode>,
    children: HashMap<String, HashSet<String>>,
    pub tips: HashSet<String>,
}

impl Default for DagTraversal {
    fn default() -> Self {
        Self::new()
    }
}

impl DagTraversal {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
            tips: HashSet::new(),
        }
    }

    // ─────────────────────────────────────────
    // ADD NODE
    // ─────────────────────────────────────────
    pub fn add_node(&mut self, node: DagNode) {
        let hash = node.hash.clone();

        if self.nodes.contains_key(&hash) {
            return;
        }

        for p in &node.parents {
            self.children
                .entry(p.clone())
                .or_default()
                .insert(hash.clone());

            self.tips.remove(p);
        }

        self.nodes.insert(hash.clone(), node);

        if self.children.get(&hash).is_none_or(|c| c.is_empty()) {
            self.tips.insert(hash);
        } else {
            self.tips.remove(&hash);
        }
    }

    // ─────────────────────────────────────────
    // REMOVE NODE
    // ─────────────────────────────────────────
    pub fn remove_node(&mut self, hash: &str) {
        if let Some(node) = self.nodes.remove(hash) {
            self.tips.remove(hash);

            for p in &node.parents {
                if let Some(children) = self.children.get_mut(p) {
                    children.remove(hash);

                    if children.is_empty() {
                        self.children.remove(p);

                        if self.nodes.contains_key(p)
                            && self.children.get(p).is_none_or(|c| c.is_empty())
                        {
                            self.tips.insert(p.clone());
                        }
                    }
                }
            }
        }

        if let Some(kids) = self.children.remove(hash) {
            for child in kids {
                if let Some(child_node) = self.nodes.get_mut(&child) {
                    child_node.parents.retain(|p| p != hash);

                    if self.children.get(&child).is_none_or(|c| c.is_empty()) {
                        self.tips.insert(child.clone());
                    }
                }
            }
        }
    }

    // ─────────────────────────────────────────
    // ANCESTORS
    // ─────────────────────────────────────────
    pub fn ancestors(&self, hash: &str, order: TraversalOrder) -> Vec<String> {
        if !self.nodes.contains_key(hash) {
            return Vec::new();
        }

        match order {
            TraversalOrder::BreadthFirst => self.bfs(hash),
            TraversalOrder::DepthFirst => self.dfs(hash),
            TraversalOrder::TopologicalSort => {
                match self.topo(hash) {
                    Ok(mut r) => {
                        r.retain(|h| h != hash);
                        r
                    }
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    fn bfs(&self, start: &str) -> Vec<String> {
        let mut result = Vec::with_capacity(64);
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(start.to_string());

        while let Some(h) = queue.pop_front() {
            if !visited.insert(h.clone()) || result.len() >= MAX_TRAVERSAL_DEPTH {
                continue;
            }

            if h != start {
                result.push(h.clone());
            }

            if let Some(node) = self.nodes.get(&h) {
                queue.extend(node.parents.iter().cloned());
            }
        }

        result
    }

    fn dfs(&self, start: &str) -> Vec<String> {
        let mut result = Vec::with_capacity(64);
        let mut visited = HashSet::new();
        let mut stack = vec![start.to_string()];

        while let Some(h) = stack.pop() {
            if !visited.insert(h.clone()) || result.len() >= MAX_TRAVERSAL_DEPTH {
                continue;
            }

            if h != start {
                result.push(h.clone());
            }

            if let Some(node) = self.nodes.get(&h) {
                stack.extend(node.parents.iter().cloned());
            }
        }

        result
    }

    // ─────────────────────────────────────────
    // TOPO SORT (DETERMINISTIC)
    // ─────────────────────────────────────────
    fn topo(&self, start: &str) -> Result<Vec<String>, DagError> {
        let mut in_degree = HashMap::new();
        let mut queue = VecDeque::new();
        let mut all = HashSet::new();

        self.collect(start, &mut all);

        for n in &all {
            if let Some(node) = self.nodes.get(n) {
                let deg = node.parents.iter().filter(|p| all.contains(*p)).count();
                in_degree.insert(n.clone(), deg);
            }
        }

        let mut zero_nodes: Vec<_> = in_degree
            .iter()
            .filter(|(_, &v)| v == 0)
            .map(|(k, _)| k.clone())
            .collect();

        zero_nodes.sort();
        queue.extend(zero_nodes);

        let mut result = Vec::with_capacity(all.len());

        while let Some(h) = queue.pop_front() {
            result.push(h.clone());

            if let Some(kids) = self.children.get(&h) {
                let mut sorted: Vec<_> = kids.iter().cloned().collect();
                sorted.sort();

                for k in sorted {
                    if !all.contains(&k) {
                        continue;
                    }

                    if let Some(d) = in_degree.get_mut(&k) {
                        *d -= 1;
                        if *d == 0 {
                            queue.push_back(k);
                        }
                    }
                }
            }
        }

        if result.len() != all.len() {
            return Err(DagError::Other(format!(
                "topological sort incomplete: {} of {} nodes (possible cycle or corruption)",
                result.len(), all.len()
            )));
        }

        Ok(result)
    }

    fn collect(&self, start: &str, visited: &mut HashSet<String>) {
        let mut stack = vec![start.to_string()];

        while let Some(h) = stack.pop() {
            if visited.insert(h.clone()) {
                if let Some(node) = self.nodes.get(&h) {
                    stack.extend(node.parents.iter().cloned());
                }
            }
        }
    }

    // ─────────────────────────────────────────
    // DESCENDANTS
    // ─────────────────────────────────────────
    pub fn descendants(&self, hash: &str) -> Vec<String> {
        let mut result = Vec::with_capacity(64);
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(hash.to_string());

        while let Some(h) = queue.pop_front() {
            if !visited.insert(h.clone()) {
                continue;
            }

            if h != hash {
                result.push(h.clone());
            }

            if let Some(kids) = self.children.get(&h) {
                queue.extend(kids.iter().cloned());
            }
        }

        result
    }

    // ─────────────────────────────────────────
    // LCA (FIXED)
    // ─────────────────────────────────────────
    pub fn lca(&self, a: &str, b: &str) -> Option<String> {
        let mut visited_a = HashSet::new();
        let mut stack = vec![a.to_string()];

        while let Some(h) = stack.pop() {
            if visited_a.insert(h.clone()) {
                if let Some(node) = self.nodes.get(&h) {
                    stack.extend(node.parents.iter().cloned());
                }
            }
        }

        let mut best = None;
        let mut best_height = 0;

        let mut stack = vec![b.to_string()];
        let mut visited_b = HashSet::new();

        while let Some(h) = stack.pop() {
            if !visited_b.insert(h.clone()) {
                continue;
            }

            if visited_a.contains(&h) {
                if let Some(node) = self.nodes.get(&h) {
                    if node.height >= best_height {
                        best_height = node.height;
                        best = Some(h.clone());
                    }
                }
            }

            if let Some(node) = self.nodes.get(&h) {
                stack.extend(node.parents.iter().cloned());
            }
        }

        best
    }

    // ─────────────────────────────────────────
    // UTILS
    // ─────────────────────────────────────────
    pub fn get_node(&self, hash: &str) -> Option<&DagNode> {
        self.nodes.get(hash)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn tip_count(&self) -> usize {
        self.tips.len()
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.nodes.contains_key(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(hash: &str, parents: &[&str]) -> DagNode {
        DagNode {
            hash:    hash.to_string(),
            parents: parents.iter().map(|s| s.to_string()).collect(),
            height:  0,
        }
    }

    fn build_chain() -> DagTraversal {
        let mut dag = DagTraversal::new();
        dag.add_node(node("genesis", &[]));
        dag.add_node(node("b1", &["genesis"]));
        dag.add_node(node("b2", &["b1"]));
        dag.add_node(node("b3", &["b2"]));
        dag
    }

    #[test]
    fn ancestors_bfs_finds_all() {
        let dag = build_chain();
        let anc = dag.ancestors("b3", TraversalOrder::BreadthFirst);
        assert!(anc.contains(&"b2".to_string()));
        assert!(anc.contains(&"b1".to_string()));
        assert!(anc.contains(&"genesis".to_string()));
    }

    #[test]
    fn descendants_finds_children() {
        let dag = build_chain();
        let desc = dag.descendants("genesis");
        assert!(desc.contains(&"b1".to_string()));
        assert!(desc.contains(&"b2".to_string()));
    }

    #[test]
    fn tips_updated_on_add() {
        let dag = build_chain();
        assert!(dag.tips.contains("b3"));
        assert!(!dag.tips.contains("genesis"));
    }

    #[test]
    fn lca_of_branches() {
        let mut dag = DagTraversal::new();
        dag.add_node(node("root", &[]));
        dag.add_node(node("left", &["root"]));
        dag.add_node(node("right", &["root"]));
        let common = dag.lca("left", "right");
        assert_eq!(common, Some("root".to_string()));
    }

    #[test]
    fn node_count_correct() {
        let dag = build_chain();
        assert_eq!(dag.node_count(), 4);
    }
}
