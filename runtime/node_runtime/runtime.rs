// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::runtime::node_runtime::runtime_manager::RuntimeManager;

pub struct Runtime {
    manager: RuntimeManager,

}

impl Runtime {
    pub fn new(manager: RuntimeManager) -> Self {
        Self { manager }

    }

    pub fn set_value(&self, key: &str, value: &str) {
        self.manager.set_state(key, value);

    }

    pub fn get_value(&self, key: &str) -> Option<String> {
        self.manager.get_state(key)

    }

}
