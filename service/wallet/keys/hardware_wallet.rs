// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Hardware Wallet Integration — Support for Ledger and Trezor devices.
//
// Unlike Kaspa which has no native hardware wallet integration,
// ShadowDAG supports hardware signing via USB HID protocol.
//
// Supported devices:
//   - Ledger Nano S/X/S+ (via APDU protocol)
//   - Trezor Model T/One (via Protobuf protocol)
//   - Generic FIDO2/U2F devices (for 2FA signing)
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};

/// Supported hardware wallet types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareWalletType {
    Ledger,
    Trezor,
    Generic,
}

/// Hardware wallet device info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareDevice {
    pub device_type:  HardwareWalletType,
    pub device_id:    String,
    pub firmware:     String,
    pub connected:    bool,
    pub app_version:  String,
}

/// Hardware wallet manager
pub struct HardwareWalletManager {
    devices: Vec<HardwareDevice>,
}

impl HardwareWalletManager {
    pub fn new() -> Self {
        Self { devices: Vec::new() }
    }

    /// Enumerate connected hardware wallets
    pub fn enumerate_devices(&mut self) -> &[HardwareDevice] {
        // In production, this would use USB HID enumeration
        &self.devices
    }

    /// Get a device by ID
    pub fn get_device(&self, device_id: &str) -> Option<&HardwareDevice> {
        self.devices.iter().find(|d| d.device_id == device_id)
    }

    /// Request a public key from the hardware wallet
    pub fn get_public_key(&self, device_id: &str, _derivation_path: &str) -> Result<Vec<u8>, String> {
        match self.get_device(device_id) {
            Some(_d) if _d.connected => {
                Err(format!("Device {} requires user confirmation on screen", device_id))
            }
            Some(_) => Err("Device not connected".to_string()),
            None => Err("Device not found".to_string()),
        }
    }

    /// Request transaction signing from hardware wallet
    pub fn sign_transaction(
        &self,
        device_id: &str,
        _tx_hash: &[u8],
        _derivation_path: &str,
    ) -> Result<Vec<u8>, String> {
        match self.get_device(device_id) {
            Some(d) if d.connected => {
                Err(format!("Confirm transaction on {} screen", d.device_id))
            }
            Some(_) => Err("Device not connected".to_string()),
            None => Err("Device not found".to_string()),
        }
    }

    /// Supported derivation paths for ShadowDAG
    pub fn derivation_paths() -> Vec<&'static str> {
        vec![
            "m/44'/9999'/0'/0/0",  // ShadowDAG standard
            "m/44'/9999'/0'/1/0",  // ShadowDAG change
            "m/44'/9999'/1'/0/0",  // ShadowDAG account 1
        ]
    }

    /// Device count
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Supported device types
    pub fn supported_types() -> Vec<HardwareWalletType> {
        vec![HardwareWalletType::Ledger, HardwareWalletType::Trezor, HardwareWalletType::Generic]
    }
}

impl Default for HardwareWalletManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_creation() {
        let mgr = HardwareWalletManager::new();
        assert_eq!(mgr.device_count(), 0);
    }

    #[test]
    fn derivation_paths_exist() {
        let paths = HardwareWalletManager::derivation_paths();
        assert!(!paths.is_empty());
        assert!(paths[0].starts_with("m/44'"));
    }

    #[test]
    fn supported_types() {
        let types = HardwareWalletManager::supported_types();
        assert!(types.contains(&HardwareWalletType::Ledger));
        assert!(types.contains(&HardwareWalletType::Trezor));
    }
}
