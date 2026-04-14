// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, PartialEq)]
pub enum NodeRole {
    FullNode,
    LightNode,
    ShadowNode,
}

impl NodeRole {
    pub fn description(&self) -> &'static str {
        match self {
            NodeRole::FullNode => "Full Node — stores all data",
            NodeRole::LightNode => "Light Node — mobile & lightweight",
            NodeRole::ShadowNode => "Shadow Node — hides transaction origin",
        }
    }
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}
