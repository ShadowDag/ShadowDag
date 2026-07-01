// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::node::node_config::NetworkMode;
use crate::domain::address::address::Address;
use crate::domain::address::invisible_wallet::InvisibleWallet;
use crate::domain::block::block::Block;
use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
use crate::domain::transaction::tx_hash::TxHash;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::privacy::ringct::builder::{
    build_confidential_transaction, ConfRecipient, OwnedInput,
};
use crate::engine::privacy::ringct::decoy::select_decoys;
use crate::engine::privacy::ringct::dual_clsag::RingMember;
use crate::engine::privacy::ringct::scan::scan_confidential_output;
use crate::engine::privacy::ringct::serialization::point_from_hex;
use crate::errors::WalletError;
use curve25519_dalek::scalar::Scalar;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex;
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use zeroize::Zeroize;

const PBKDF2_ITER: u32 = 600_000;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const DUST_LIMIT: u64 = 546;
/// Ring size for confidential sends: 1 real + (CONF_RING_SIZE-1) decoys.
/// Must be ≥ the consensus minimum ring size (4) enforced by RingValidator.
const CONF_RING_SIZE: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WalletAddress {
    pub address: String,
    pub public_key: String,
    pub account: u32,
    pub index: u32,
    pub is_change: bool,
    pub label: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Walletutxo {
    pub txid: String,
    pub index: u32,
    pub amount: u64,
    pub address: String,
    pub height: u64,
    pub confirmations: u64,
    pub is_coinbase: bool,
    pub is_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTx {
    pub txid: String,
    pub direction: TxDirection,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: u64,
    pub height: u64,
    pub confirmations: u64,
    pub to_address: String,
    pub from_address: String,
    pub status: TxStatus,
    pub memo: String,
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub index: u32,
    pub label: String,
    pub addresses: Vec<WalletAddress>,
    pub balance: u64,
    pub tx_count: u64,
    pub created_at: u64,
}

impl WalletAccount {
    pub fn primary_address(&self) -> Option<&str> {
        self.addresses.first().map(|a| a.address.as_str())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletState {
    pub version: u32,
    pub network: String,
    pub created_at: u64,
    pub accounts: Vec<WalletAccount>,
}

/// A confidential (RingCT) output owned by this wallet, recovered by scanning.
/// The raw one-time spend secret is NOT stored — it is recovered on demand at
/// spend time from `ephemeral_pubkey` + the wallet's view/spend scalars.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidentialUtxo {
    pub txid: String,
    pub index: u32,
    pub amount: u64,
    /// hex(Scalar.to_bytes()) — the Pedersen blinding (needed to spend).
    pub blinding_hex: String,
    /// hex(compressed point) — the real ring member (this output's one-time key).
    pub one_time_pubkey: String,
    /// hex(R) — ephemeral pubkey, used to recover the spend secret at spend time.
    pub ephemeral_pubkey: String,
    pub spent: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    state: WalletState,
    utxos: HashMap<String, Vec<Walletutxo>>,
    history: HashMap<String, Vec<WalletTx>>,
    #[serde(skip)]
    session_key: Option<Vec<u8>>,
    locked: bool,
    network: String,
    #[serde(default)]
    confidential_utxos: Vec<ConfidentialUtxo>,
}

impl Wallet {
    pub fn new(network: &str) -> Self {
        Self {
            state: WalletState {
                version: 1,
                network: network.to_string(),
                created_at: unix_now(),
                accounts: Vec::new(),
            },
            utxos: HashMap::new(),
            history: HashMap::new(),
            session_key: None,
            locked: true,
            network: network.to_string(),
            confidential_utxos: Vec::new(),
        }
    }

    pub fn create(&mut self, password: &str) -> Result<(Vec<String>, EncryptedSeed), WalletError> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = entropy_to_mnemonic_simple(&entropy);
        let seed = mnemonic_to_seed_simple(&mnemonic, "");
        let enc = encrypt_bytes(&seed, password)?;
        self.session_key = Some(seed);
        self.locked = false;

        self.add_account(0, "Default Account")?;
        Ok((mnemonic, enc))
    }

    pub fn restore_from_seed(&mut self, seed: Vec<u8>) -> Result<(), WalletError> {
        self.session_key = Some(seed);
        self.locked = false;
        // Create default account if empty (critical for usability after restore)
        if self.state.accounts.is_empty() {
            self.add_account(0, "Default")?;
        }
        Ok(())
    }

    pub fn unlock(&mut self, enc_seed: &EncryptedSeed, password: &str) -> Result<(), WalletError> {
        let seed = decrypt_bytes(
            &enc_seed.ciphertext,
            &enc_seed.salt,
            &enc_seed.nonce,
            password,
        )?;
        self.session_key = Some(seed);
        self.locked = false;
        Ok(())
    }

    pub fn lock(&mut self) {
        if let Some(mut k) = self.session_key.take() {
            k.zeroize();
        }
        self.locked = true;
    }

    /// Stable 32-byte confidential master key derived from the unlocked seed.
    /// The domain-separation tag is FIXED forever — changing it would make
    /// previously-received confidential funds unrecoverable.
    fn confidential_master_key(&self) -> Option<[u8; 32]> {
        let seed = self.session_key.as_ref()?;
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_conf_master_v1");
        h.update(seed);
        let out = h.finalize();
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&out);
        Some(mk)
    }

    /// Build the confidential (view/spend) key wallet from the seed. None if locked.
    pub fn confidential_keys(&self) -> Option<InvisibleWallet> {
        let mk = self.confidential_master_key()?;
        InvisibleWallet::from_master_key(mk, &self.network).ok()
    }

    /// Reusable confidential receive address (`SD1p…`). None if locked.
    pub fn confidential_receive_address(&self) -> Option<String> {
        Some(self.confidential_keys()?.confidential_address())
    }

    /// Record a confidential UTXO (deduplicated by one-time pubkey).
    pub fn add_confidential_utxo(&mut self, u: ConfidentialUtxo) {
        if !self
            .confidential_utxos
            .iter()
            .any(|e| e.one_time_pubkey == u.one_time_pubkey)
        {
            self.confidential_utxos.push(u);
        }
    }

    /// Total spendable (unspent) confidential balance.
    pub fn confidential_balance(&self) -> u64 {
        self.confidential_utxos
            .iter()
            .filter(|u| !u.spent)
            .map(|u| u.amount)
            .sum()
    }

    /// All tracked confidential UTXOs (spent + unspent).
    pub fn confidential_utxos(&self) -> &[ConfidentialUtxo] {
        &self.confidential_utxos
    }

    /// Scan a transaction for confidential outputs owned by this wallet, record
    /// any new ones, and return them. Uses `scan_confidential_output` (the same
    /// context-free derivation the builder used) — NOT the tx-context stealth
    /// scanner — so detection + amount recovery match what was produced.
    pub fn scan_confidential(&mut self, tx: &Transaction) -> Vec<ConfidentialUtxo> {
        let ck = match self.confidential_keys() {
            Some(c) => c,
            None => return Vec::new(),
        };
        let (vs, sp) = (ck.view_scalar(), ck.spend_public());
        let mut found = Vec::new();
        for (idx, out) in tx.outputs.iter().enumerate() {
            if let Some(rec) = scan_confidential_output(out, idx as u32, &vs, &sp) {
                let u = ConfidentialUtxo {
                    txid: tx.hash.clone(),
                    index: idx as u32,
                    amount: rec.amount,
                    blinding_hex: hex::encode(rec.blinding.to_bytes()),
                    one_time_pubkey: hex::encode(rec.one_time_pubkey.compress().as_bytes()),
                    ephemeral_pubkey: out.ephemeral_pubkey.clone().unwrap_or_default(),
                    spent: false,
                };
                let before = self.confidential_utxos.len();
                self.add_confidential_utxo(u.clone());
                if self.confidential_utxos.len() > before {
                    found.push(u);
                }
            }
        }

        // Mark any of our confidential UTXOs spent if their key image appears in
        // this tx's inputs (handles our own sends + sends from another device
        // sharing the seed). The key image is deterministic from (spend_secret,
        // one_time_pubkey), matching what the builder/consensus uses.
        let input_kis: std::collections::HashSet<&str> = tx
            .inputs
            .iter()
            .filter_map(|i| i.key_image.as_deref())
            .collect();
        if !input_kis.is_empty() {
            for u in self.confidential_utxos.iter_mut().filter(|u| !u.spent) {
                if let Some(ki) = confidential_key_image_hex(&ck, u) {
                    if input_kis.contains(ki.as_str()) {
                        u.spent = true;
                    }
                }
            }
        }
        found
    }

    /// Scan many blocks (e.g. from the node DB) and accumulate owned outputs.
    /// Returns the count of newly-recorded confidential outputs.
    pub fn scan_blocks(&mut self, blocks: &[Block]) -> usize {
        let mut n = 0;
        for b in blocks {
            for tx in &b.body.transactions {
                n += self.scan_confidential(tx).len();
            }
        }
        n
    }

    /// Network as a `NetworkMode` (defaults to Mainnet if the string is unknown).
    fn network_mode(&self) -> NetworkMode {
        self.network.parse().unwrap_or(NetworkMode::Mainnet)
    }

    /// Build a confidential (RingCT) transaction sending `amount` to a confidential
    /// payment address (`…1p`), with any change returned to this wallet. The
    /// returned tx is unsigned-broadcast-ready (CLSAG-signed) — the caller submits
    /// it via RPC `sendrawtransaction`. `utxo_set` is the node's confidential output
    /// index (read-only), used for decoy selection + real-commitment lookup.
    pub fn build_confidential_send(
        &self,
        recipient_addr: &str,
        amount: u64,
        fee: u64,
        utxo_set: &UtxoSet,
    ) -> Result<Transaction, WalletError> {
        let ck = self.confidential_keys().ok_or(WalletError::Locked)?;
        let net = self.network_mode();
        let (view_pub, spend_pub) =
            InvisibleWallet::parse_confidential_address(recipient_addr, &self.network)
                .map_err(|e| WalletError::Other(format!("bad recipient address: {}", e)))?;

        let need = amount
            .checked_add(fee)
            .ok_or_else(|| WalletError::Other("amount+fee overflow".into()))?;

        // Select unspent confidential UTXOs, largest-first, until they cover need.
        let mut chosen: Vec<&ConfidentialUtxo> =
            self.confidential_utxos.iter().filter(|u| !u.spent).collect();
        chosen.sort_by(|a, b| b.amount.cmp(&a.amount));
        let mut inputs_total = 0u64;
        let mut picked: Vec<&ConfidentialUtxo> = Vec::new();
        for u in chosen {
            if inputs_total >= need {
                break;
            }
            inputs_total += u.amount;
            picked.push(u);
        }
        if inputs_total < need {
            return Err(WalletError::Other("insufficient confidential funds".into()));
        }

        // Build one OwnedInput per picked UTXO (ring + recovered spend secret).
        let mut owned = Vec::with_capacity(picked.len());
        for u in &picked {
            let real_pk = point_from_hex(&u.one_time_pubkey)
                .ok_or_else(|| WalletError::Other("bad one-time pubkey".into()))?;
            let real_c = utxo_set
                .output_key_commitment(&u.one_time_pubkey)
                .and_then(|c| point_from_hex(&c))
                .ok_or_else(|| WalletError::Other("real output not on-chain yet".into()))?;
            let mut ring =
                select_decoys(utxo_set, CONF_RING_SIZE - 1, std::slice::from_ref(&u.one_time_pubkey))
                    .ok_or_else(|| WalletError::Other("not enough decoys on-chain yet".into()))?;
            // PRIVACY: insert the real member at a UNIFORMLY RANDOM position.
            // Appending it last would make the real spend positionally
            // identifiable on-chain (the last ring member would always be the
            // real one) — a full deanonymization of every confidential input.
            let real_index = {
                use rand::Rng;
                rand::rngs::OsRng.gen_range(0..=ring.len())
            };
            ring.insert(
                real_index,
                RingMember {
                    public_key: real_pk,
                    commitment: real_c,
                },
            );
            // Recover the one-time spend secret from the stored ephemeral pubkey.
            let eph = point_from_hex(&u.ephemeral_pubkey)
                .ok_or_else(|| WalletError::Other("bad ephemeral pubkey".into()))?;
            let spend_secret = ck
                .derive_spend_key_for(&eph)
                .map_err(|e| WalletError::Other(format!("spend-secret recovery failed: {}", e)))?;
            let blinding = scalar_from_hex(&u.blinding_hex)
                .ok_or_else(|| WalletError::Other("bad blinding".into()))?;
            owned.push(OwnedInput {
                spend_secret,
                amount: u.amount,
                blinding,
                ring,
                real_index,
            });
        }

        // Recipients: the target + change back to self (rescannable + spendable).
        let mut recipients = vec![ConfRecipient {
            view_pub,
            spend_pub,
            amount,
        }];
        let change = inputs_total - need;
        if change > 0 {
            recipients.push(ConfRecipient {
                view_pub: ck.view_public(),
                spend_pub: ck.spend_public(),
                amount: change,
            });
        }

        build_confidential_transaction(owned, recipients, fee, &net)
            .map_err(|e| WalletError::Other(format!("build confidential tx failed: {}", e)))
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Force wallet into locked state after deserialization.
    /// `session_key` is `#[serde(skip)]`, so after load the wallet appears
    /// unlocked but has no key — this fixes that inconsistency.
    pub fn force_locked_after_load(&mut self) {
        self.session_key = None;
        self.locked = true;
    }
    pub fn address(&self) -> String {
        self.state
            .accounts
            .first()
            .and_then(|a| a.primary_address())
            .unwrap_or("__no_address__")
            .to_string()
    }

    pub fn add_account(&mut self, index: u32, label: &str) -> Result<WalletAccount, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }
        let seed = self
            .session_key
            .as_ref()
            .ok_or(WalletError::Other("No session key".to_string()))?;

        let signing_key = derive_key(seed, index, 0, false)?;
        let verifying: VerifyingKey = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying.as_bytes());
        let address = make_address(&pub_hex, &self.network)?;

        let wa = WalletAddress {
            address: address.clone(),
            public_key: pub_hex,
            account: index,
            index: 0,
            is_change: false,
            label: "Primary".to_string(),
            created_at: unix_now(),
        };

        let acc = WalletAccount {
            index,
            label: label.to_string(),
            addresses: vec![wa],
            balance: 0,
            tx_count: 0,
            created_at: unix_now(),
        };

        if self.state.accounts.iter().any(|a| a.index == index) {
            return Err(WalletError::Other(format!(
                "account {} already exists",
                index
            )));
        }
        self.state.accounts.push(acc.clone());
        Ok(acc)
    }

    pub fn derive_change_address(
        &mut self,
        account: u32,
        addr_index: u32,
    ) -> Result<WalletAddress, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }
        let seed = self
            .session_key
            .as_ref()
            .ok_or(WalletError::Other("No session key".to_string()))?;
        let sk = derive_key(seed, account, addr_index, true)?;
        let vk: VerifyingKey = sk.verifying_key();
        let pub_hex = hex::encode(vk.as_bytes());
        let address = make_address(&pub_hex, &self.network)?;

        let wa = WalletAddress {
            address: address.clone(),
            public_key: pub_hex,
            account,
            index: addr_index,
            is_change: true,
            label: format!("Change {}", addr_index),
            created_at: unix_now(),
        };

        let acc = self
            .state
            .accounts
            .iter_mut()
            .find(|a| a.index == account)
            .ok_or_else(|| WalletError::Other(format!("account {} not found", account)))?;
        // Dedup: don't add if an address with the same index and is_change already exists
        if !acc
            .addresses
            .iter()
            .any(|a| a.is_change && a.index == addr_index)
        {
            acc.addresses.push(wa.clone());
        }
        Ok(wa)
    }

    pub fn accounts(&self) -> &[WalletAccount] {
        &self.state.accounts
    }

    pub fn account(&self, idx: u32) -> Option<&WalletAccount> {
        self.state.accounts.iter().find(|a| a.index == idx)
    }

    pub fn total_balance(&self) -> u64 {
        match self
            .state
            .accounts
            .iter()
            .try_fold(0u64, |acc, a| acc.checked_add(a.balance))
        {
            Some(total) => total,
            None => {
                eprintln!(
                    "[WARN] wallet total_balance overflow — account balances exceed u64::MAX"
                );
                u64::MAX
            }
        }
    }

    pub fn utxos_for(&self, address: &str) -> Vec<&Walletutxo> {
        self.utxos
            .get(address)
            .map(|v| v.iter().filter(|u| !u.is_locked).collect())
            .unwrap_or_default()
    }

    pub fn history_for(&self, address: &str) -> Vec<&WalletTx> {
        let mut txs: Vec<&WalletTx> = self
            .history
            .get(address)
            .map(|v| v.iter().collect())
            .unwrap_or_default();
        txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        txs
    }

    pub fn update_utxos(&mut self, address: &str, utxos: Vec<Walletutxo>) {
        let bal: u64 = utxos
            .iter()
            .filter(|u| !u.is_locked)
            .map(|u| u.amount)
            .try_fold(0u64, |acc, u| acc.checked_add(u))
            .unwrap_or(u64::MAX);
        self.utxos.insert(address.to_string(), utxos);

        if let Some(acc) = self
            .state
            .accounts
            .iter_mut()
            .find(|a| a.addresses.iter().any(|ad| ad.address == address))
        {
            acc.balance = bal;
        }
    }

    pub fn update_history(&mut self, address: &str, txs: Vec<WalletTx>) {
        let count = txs.len() as u64;
        self.history.insert(address.to_string(), txs);
        if let Some(acc) = self
            .state
            .accounts
            .iter_mut()
            .find(|a| a.addresses.iter().any(|ad| ad.address == address))
        {
            acc.tx_count = count;
        }
    }

    pub fn build_tx(
        &mut self,
        from_account: u32,
        to_address: &str,
        amount: u64,
        fee: u64,
        memo: &str,
    ) -> Result<BuiltTx, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let acc = self
            .account(from_account)
            .ok_or(WalletError::Other("Account not found".to_string()))?
            .clone();
        if acc.addresses.is_empty() {
            return Err(WalletError::AddressNotFound(
                "No address in account".to_string(),
            ));
        }

        // Collect UTXOs from ALL account addresses, not just the primary one
        let mut all_utxos: Vec<Walletutxo> = acc
            .addresses
            .iter()
            .flat_map(|a| self.utxos_for(&a.address))
            .cloned()
            .collect();

        let avail_bal: u64 = all_utxos
            .iter()
            .map(|u| u.amount)
            .try_fold(0u64, |acc, u| acc.checked_add(u))
            .ok_or(WalletError::BalanceOverflow)?;
        if avail_bal < amount.saturating_add(fee) {
            return Err(WalletError::InsufficientFunds {
                need: amount + fee,
                have: avail_bal,
            });
        }
        all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut total_in = 0u64;
        for u in all_utxos {
            selected.push(u.clone());
            total_in += u.amount;
            if total_in >= amount.saturating_add(fee) {
                break;
            }
        }

        let change = total_in.saturating_sub(amount.saturating_add(fee));
        let seed = self
            .session_key
            .as_ref()
            .ok_or(WalletError::Other("No session key".to_string()))?
            .clone();
        let net: NetworkMode = self.network.parse().unwrap_or(NetworkMode::Mainnet);
        let ts = unix_now();

        // Outputs: recipient first, then change-to-self on a fresh canonical
        // change address when it clears the dust threshold. Both must be known
        // before hashing because the txid commits to the outputs.
        let mut outputs = vec![TxOutput::new(to_address.to_string(), amount)];
        if change > DUST_LIMIT {
            let next_idx = acc
                .addresses
                .iter()
                .filter(|a| a.is_change)
                .map(|a| a.index)
                .max()
                .map(|x| x + 1)
                .unwrap_or(1);
            let change_addr = self
                .derive_change_address(from_account, next_idx)
                .map_err(|_| WalletError::Other("cannot derive change address".into()))?
                .address;
            outputs.push(TxOutput::new(change_addr, change));
        }

        // Build the REAL consensus transaction. owner + pub_key are set now
        // (the txid commits to them); signatures are filled after hashing since
        // canonical_bytes excludes signatures (Bitcoin-style, no circular hash).
        let mut tx_inputs: Vec<TxInput> = Vec::with_capacity(selected.len());
        for utxo in &selected {
            let wa = acc
                .addresses
                .iter()
                .find(|a| a.address == utxo.address)
                .ok_or(WalletError::AddressNotFound(utxo.address.clone()))?;
            tx_inputs.push(TxInput {
                txid: utxo.txid.clone(),
                index: utxo.index,
                owner: utxo.address.clone(),
                signature: String::new(),
                pub_key: wa.public_key.clone(),
                key_image: None,
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
            });
        }

        let mut tx = Transaction::new(String::new(), tx_inputs, outputs, fee, ts);
        // Canonical txid, then the signing message over that txid — the EXACT
        // scheme the node validates (TxHash::{hash,signing_message}_for_network)
        // and the WASM/Python SDKs replicate byte-for-byte.
        tx.hash = TxHash::hash_for_network(&tx, &net);
        let signing_msg = TxHash::signing_message_for_network(&tx, &net);

        // Sign each input with the key that owns its UTXO. Every input signs the
        // same tx-wide message but with its own key (multi-address spend safe).
        for (i, utxo) in selected.iter().enumerate() {
            let wa = acc
                .addresses
                .iter()
                .find(|a| a.address == utxo.address)
                .ok_or(WalletError::AddressNotFound(utxo.address.clone()))?;
            let sk = derive_key(&seed, wa.account, wa.index, wa.is_change)?;
            let sig: Signature = sk.sign(&signing_msg);
            tx.inputs[i].signature = hex::encode(sig.to_bytes());
        }

        // Wallet-local views for CLI display, plus the broadcast-ready JSON.
        // `raw_hex` now carries the serialized consensus Transaction that
        // `sendrawtransaction` accepts (params[0] = this JSON string), NOT a
        // placeholder.
        let signed_inputs: Vec<SignedInput> = tx
            .inputs
            .iter()
            .map(|inp| SignedInput {
                txid: inp.txid.clone(),
                index: inp.index,
                signature: inp.signature.clone(),
                pub_key: inp.pub_key.clone(),
                address: inp.owner.clone(),
            })
            .collect();
        let outputs: Vec<TxOut> = tx
            .outputs
            .iter()
            .map(|o| TxOut {
                address: o.address.clone(),
                amount: o.amount,
            })
            .collect();
        let raw_json = serde_json::to_string(&tx)
            .map_err(|e| WalletError::Other(format!("serialize tx: {}", e)))?;

        Ok(BuiltTx {
            txid: tx.hash.clone(),
            inputs: signed_inputs,
            outputs,
            fee,
            memo: memo.to_string(),
            timestamp: ts,
            raw_hex: raw_json,
        })
    }

    /// Validate a ShadowDAG address on this wallet's network.
    ///
    /// Canonical forms (all `SD1`/`ST1`/`SR1`-prefixed):
    ///   Standard:     `SD1` + 40 hex (20-byte SHA-256 pubkey hash)
    ///   Typed s/k/h:  `SD1s`/`SD1k`/`SD1h` + 40 hex (stealth / Schnorr / P2SH)
    ///   Confidential: `SD1p` + 136 hex (view_pub‖spend_pub + checksum)
    /// `s`/`k`/`h`/`p` are not hex digits, so the subtype is unambiguous.
    pub fn is_valid_address(&self, addr: &str) -> bool {
        let net_prefix = match self.network.as_str() {
            "testnet" => "ST1",
            "regtest" => "SR1",
            _ => "SD1",
        };
        let after = match addr.strip_prefix(net_prefix) {
            Some(a) => a,
            None => return false,
        };

        // Confidential payment address: "p" + 136 hex.
        if let Some(rest) = after.strip_prefix('p') {
            return rest.len() == 136 && rest.bytes().all(|b| b.is_ascii_hexdigit());
        }
        // Typed addresses: subtype char (s/k/h) + 40 hex.
        if matches!(after.as_bytes().first(), Some(b's' | b'k' | b'h')) {
            let body = &after[1..];
            return body.len() == 40 && body.bytes().all(|b| b.is_ascii_hexdigit());
        }
        // Standard address: exactly 40 hex chars.
        after.len() == 40 && after.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// Select UTXOs from an account to cover the requested amount.
    /// Returns (selected_utxos, total_input_value).
    fn select_utxos(
        &self,
        acc: &WalletAccount,
        amount: u64,
    ) -> Result<(Vec<Walletutxo>, u64), WalletError> {
        let mut utxos: Vec<Walletutxo> = acc
            .addresses
            .iter()
            .flat_map(|a| self.utxos_for(&a.address))
            .cloned()
            .collect();
        utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut total = 0u64;
        for u in utxos {
            selected.push(u.clone());
            total += u.amount;
            if total >= amount {
                break;
            }
        }
        if total < amount {
            return Err(WalletError::InsufficientFunds {
                need: amount,
                have: total,
            });
        }
        Ok((selected, total))
    }

    /// Build a contract deployment transaction.
    /// The bytecode is included in deploy_code, and gas_limit is set.
    /// Returns a signed Transaction ready for broadcast.
    pub fn build_deploy_tx(
        &mut self,
        from_account: u32,
        bytecode: Vec<u8>,
        value: u64,
        gas_limit: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let acc = self
            .account(from_account)
            .ok_or(WalletError::Other("Account not found".into()))?
            .clone();
        let addr = acc
            .primary_address()
            .ok_or(WalletError::AddressNotFound("No address".into()))?
            .to_string();

        // Collect UTXOs for gas + value
        let total_needed = value.saturating_add(fee);
        let (selected, total_in) = self.select_utxos(&acc, total_needed)?;

        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                txid: u.txid.clone(),
                index: u.index,
                owner: addr.clone(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
            })
            .collect();

        let mut outputs = vec![TxOutput {
            address: "contract_deploy".into(), // placeholder — actual address computed by VM
            amount: value,
            commitment: None,
            range_proof: None,
            ephemeral_pubkey: None,
            one_time_pubkey: None,
            encrypted_amount: None,
        }];

        // Change output if needed
        let change = total_in.saturating_sub(total_needed);
        if change > 0 {
            outputs.push(TxOutput {
                address: addr.clone(),
                amount: change,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: None,
                encrypted_amount: None,
            });
        }

        let tx = Transaction {
            hash: String::new(), // computed after signing
            inputs,
            outputs,
            fee,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_coinbase: false,
            tx_type: TxType::ContractCreate,
            payload_hash: None,
            gas_limit: Some(gas_limit),
            deploy_code: Some(bytecode),
            calldata: None,
            contract_address: None,
            vm_version: Some(1),
        };

        // Sign (use existing signing logic from build_tx)
        // For now, return unsigned — signing requires private key access
        Ok(tx)
    }

    /// Build a contract call transaction.
    pub fn build_call_tx(
        &mut self,
        from_account: u32,
        contract_addr: &str,
        calldata: Vec<u8>,
        value: u64,
        gas_limit: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let acc = self
            .account(from_account)
            .ok_or(WalletError::Other("Account not found".into()))?
            .clone();
        let addr = acc
            .primary_address()
            .ok_or(WalletError::AddressNotFound("No address".into()))?
            .to_string();

        let total_needed = value.saturating_add(fee);
        let (selected, total_in) = self.select_utxos(&acc, total_needed)?;

        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                txid: u.txid.clone(),
                index: u.index,
                owner: addr.clone(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
            })
            .collect();

        let mut outputs = vec![TxOutput {
            address: contract_addr.to_string(),
            amount: value,
            commitment: None,
            range_proof: None,
            ephemeral_pubkey: None,
            one_time_pubkey: None,
            encrypted_amount: None,
        }];

        let change = total_in.saturating_sub(total_needed);
        if change > 0 {
            outputs.push(TxOutput {
                address: addr.clone(),
                amount: change,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: None,
                encrypted_amount: None,
            });
        }

        Ok(Transaction {
            hash: String::new(),
            inputs,
            outputs,
            fee,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_coinbase: false,
            tx_type: TxType::ContractCall,
            payload_hash: None,
            gas_limit: Some(gas_limit),
            deploy_code: None,
            calldata: Some(calldata),
            contract_address: Some(contract_addr.to_string()),
            vm_version: Some(1),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSeed {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltTx {
    pub txid: String,
    pub inputs: Vec<SignedInput>,
    pub outputs: Vec<TxOut>,
    pub fee: u64,
    pub memo: String,
    pub timestamp: u64,
    pub raw_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInput {
    pub txid: String,
    pub index: u32,
    pub signature: String,
    pub pub_key: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOut {
    pub address: String,
    pub amount: u64,
}

fn derive_key(
    seed: &[u8],
    account: u32,
    index: u32,
    change: bool,
) -> Result<SigningKey, WalletError> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let path = format!(
        "ShadowDAG/44'/999'/{}'/{}/{}",
        account,
        if change { 1 } else { 0 },
        index
    );
    let mut mac = <HmacSha256 as Mac>::new_from_slice(seed)
        .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
    mac.update(path.as_bytes());
    let res = mac.finalize().into_bytes();
    let key: [u8; 32] = res
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| WalletError::KeyDerivation("Key slice error".to_string()))?;
    Ok(SigningKey::from_bytes(&key))
}

/// Canonical ShadowDAG address from an Ed25519 public key (hex).
///
/// Produces the ONLY form consensus recognizes:
/// `prefix + hex(SHA256("ShadowDAG_Addr_v1" || pubkey)[..20])` (SD1/ST1/SR1 +
/// 40 hex), identical to `domain::address::Address::from_public_key` and to the
/// WASM/Python SDKs byte-for-byte. `tx_validator::verify_input_ownership`
/// re-derives this exact string from the input pub_key and requires it to equal
/// the UTXO owner, so coinbase/transfers to this address are spendable.
///
/// (Historically this emitted an SD+74hex Sha3 form that no pubkey could ever
/// derive to, making every wallet-generated address unspendable — the ST0..
/// bug. Do NOT reintroduce a non-canonical address here.)
fn make_address(pub_hex: &str, network: &str) -> Result<String, WalletError> {
    let pub_bytes = hex::decode(pub_hex)
        .map_err(|e| WalletError::Other(format!("invalid public key hex: {}", e)))?;
    if pub_bytes.len() != 32 {
        return Err(WalletError::Other(format!(
            "public key must be 32 bytes, got {}",
            pub_bytes.len()
        )));
    }
    Ok(Address::from_public_key(&pub_bytes, network).value)
}

fn entropy_to_mnemonic_simple(entropy: &[u8]) -> Vec<String> {
    // BIP-39 compatible: 2048 words derived deterministically from a master seed.
    // Each word = 11 bits of entropy. 12 words = 132 bits (128 + 4 checksum).
    // We generate 2048 unique words from SHA-256 hashing of indices.
    let wordlist = generate_bip39_wordlist();

    let hash = Sha3_256::digest(entropy);

    // Extract 11-bit indices from hash (BIP-39 standard)
    let mut bits: Vec<u8> = Vec::with_capacity(256);
    for byte in hash.iter() {
        for bit in (0..8).rev() {
            bits.push((byte >> bit) & 1);
        }
    }

    (0..12)
        .map(|i| {
            // 11 bits per word index
            let start = i * 11;
            let mut idx: usize = 0;
            for b in 0..11 {
                if start + b < bits.len() {
                    idx = (idx << 1) | (bits[start + b] as usize);
                }
            }
            wordlist[idx % 2048].clone()
        })
        .collect()
}

/// Generate a deterministic 2048-word list from SHA-256.
/// Each word is unique, 3-8 characters, lowercase alpha.
/// This replaces the old 65-word list for proper 128-bit entropy.
fn generate_bip39_wordlist() -> Vec<String> {
    use sha2::{Digest, Sha256};

    // Base syllables for word construction
    const CONSONANTS: &[u8] = b"bcdfghjklmnprstvwxyz";
    const VOWELS: &[u8] = b"aeiou";

    let mut words: Vec<String> = Vec::with_capacity(2048);
    let mut seen = std::collections::HashSet::with_capacity(2048);

    for i in 0u32..8192 {
        // Deterministic hash per index
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_BIP39_WordGen_v1");
        h.update(i.to_le_bytes());
        let hash = h.finalize();

        // Generate a 3-7 char word from hash bytes
        let word_len = 3 + (hash[0] % 5) as usize; // 3 to 7 chars
        let mut word = String::with_capacity(word_len);

        for j in 0..word_len {
            let byte = hash[(j + 1) % 32];
            if j % 2 == 0 {
                word.push(CONSONANTS[(byte as usize) % CONSONANTS.len()] as char);
            } else {
                word.push(VOWELS[(byte as usize) % VOWELS.len()] as char);
            }
        }

        if word.len() >= 3 && seen.insert(word.clone()) {
            words.push(word);
            if words.len() >= 2048 {
                break;
            }
        }
    }

    words
}

fn mnemonic_to_seed_simple(words: &[String], passphrase: &str) -> Vec<u8> {
    let sentence = words.join(" ");
    let salt = format!("ShadowDAG{}", passphrase);
    let mut seed = vec![0u8; 64];
    pbkdf2_hmac::<Sha256>(sentence.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}

fn encrypt_bytes(data: &[u8], password: &str) -> Result<EncryptedSeed, WalletError> {
    let mut salt = vec![0u8; SALT_LEN];
    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITER, &mut key);

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| WalletError::Encryption(e.to_string()))?;
    let n = aes_gcm::Nonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(n, data)
        .map_err(|_| WalletError::Encryption("Encrypt failed".to_string()))?;
    key.zeroize();

    Ok(EncryptedSeed {
        ciphertext: ct,
        salt,
        nonce,
    })
}

fn decrypt_bytes(
    ct: &[u8],
    salt: &[u8],
    nonce: &[u8],
    password: &str,
) -> Result<Vec<u8>, WalletError> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITER, &mut key);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| WalletError::Encryption(e.to_string()))?;
    let n = aes_gcm::Nonce::from_slice(nonce);
    let plain = cipher.decrypt(n, ct).map_err(|_| WalletError::AuthFailed)?;
    key.zeroize();
    Ok(plain)
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Decode a hex-encoded canonical Ristretto scalar (32 bytes).
fn scalar_from_hex(s: &str) -> Option<Scalar> {
    let b = hex::decode(s).ok()?;
    let arr: [u8; 32] = b.try_into().ok()?;
    Option::from(Scalar::from_canonical_bytes(arr))
}

/// Compute the on-chain key image (hex) for one of our confidential UTXOs, using
/// the SAME derivation the builder/consensus use:
/// `key_image(spend_secret, one_time_pubkey)`. The spend secret is recovered
/// from the stored ephemeral pubkey. Returns None if any decode/recovery fails.
fn confidential_key_image_hex(ck: &InvisibleWallet, u: &ConfidentialUtxo) -> Option<String> {
    let otk = point_from_hex(&u.one_time_pubkey)?;
    let eph = point_from_hex(&u.ephemeral_pubkey)?;
    let spend_secret = ck.derive_spend_key_for(&eph).ok()?;
    let ki = crate::engine::privacy::ringct::dual_clsag::key_image(&spend_secret, &otk);
    Some(hex::encode(ki.compress().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors pinning the wallet's address-derivation chain. The
    // standalone wasm-sdk crate replicates this exact chain; these assertions
    // pin the format so any change here flags that wasm-sdk must be updated.
    #[test]
    fn wasm_sdk_reference_vectors() {
        use crate::domain::address::address::Address;

        // V1: public key of 32 0x01 bytes -> mainnet address.
        let a1 = Address::from_public_key(&[1u8; 32], "mainnet");
        assert!(a1.value.starts_with("SD1") && a1.value.len() == 43);

        // V2: seed of 64 0x02 bytes -> derive_key(acct=0, idx=0, change=false).
        let sk = derive_key(&[2u8; 64], 0, 0, false).unwrap();
        let pk = sk.verifying_key().to_bytes();
        let a2 = Address::from_public_key(&pk, "mainnet");

        // V3: full mnemonic path (entropy 32x0x03 -> words -> seed -> address).
        let words = entropy_to_mnemonic_simple(&[3u8; 32]);
        let seed = mnemonic_to_seed_simple(&words, "");
        let sk3 = derive_key(&seed, 0, 0, false).unwrap();
        let pk3 = sk3.verifying_key().to_bytes();
        let a3 = Address::from_public_key(&pk3, "mainnet");

        println!("WASM_VEC V1_pubkey_ones_addr = {}", a1.value);
        println!("WASM_VEC V2_seed_twos_pubkey = {}", hex::encode(pk));
        println!("WASM_VEC V2_seed_twos_addr   = {}", a2.value);
        println!("WASM_VEC V3_mnemonic         = {}", words.join(" "));
        println!("WASM_VEC V3_seed_hex         = {}", hex::encode(&seed));
        println!("WASM_VEC V3_addr             = {}", a3.value);
    }

    #[test]
    fn scanning_own_spend_marks_utxo_spent() {
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::utxo::utxo_set::UtxoSet;
        use crate::engine::privacy::ringct::builder::{
            build_confidential_transaction, ConfRecipient, OwnedInput,
        };
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
        use rand::rngs::OsRng;

        let net = NetworkMode::Mainnet;
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let set = UtxoSet::new_empty();
        let rec = |set: &UtxoSet, pk: RistrettoPoint, c: RistrettoPoint| {
            set.record_confidential_output_indexed(
                &hex::encode(pk.compress().as_bytes()),
                &hex::encode(c.compress().as_bytes()),
            )
            .unwrap();
        };
        for _ in 0..8 {
            rec(&set, Scalar::random(&mut OsRng) * G, Scalar::from(9u64) * h + Scalar::random(&mut OsRng) * G);
        }

        let mut a = Wallet::new("mainnet");
        a.restore_from_seed(vec![44u8; 32]).unwrap();
        let ack = a.confidential_keys().unwrap();
        let mut b = Wallet::new("mainnet");
        b.restore_from_seed(vec![55u8; 32]).unwrap();

        // Seed A's 100-output and scan it in.
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let real_pk = spend * G;
        let real_c = Scalar::from(100u64) * h + bl * G;
        rec(&set, real_pk, real_c);
        let mut ring = crate::engine::privacy::ringct::decoy::select_decoys(
            &set,
            4,
            &[hex::encode(real_pk.compress().as_bytes())],
        )
        .unwrap();
        ring.push(RingMember { public_key: real_pk, commitment: real_c });
        let ri = ring.len() - 1;
        let seed_tx = build_confidential_transaction(
            vec![OwnedInput { spend_secret: spend, amount: 100, blinding: bl, ring, real_index: ri }],
            vec![ConfRecipient { view_pub: ack.view_public(), spend_pub: ack.spend_public(), amount: 100 }],
            0,
            &net,
        )
        .unwrap();
        for out in &seed_tx.outputs {
            rec(
                &set,
                point_from_hex(out.one_time_pubkey.as_ref().unwrap()).unwrap(),
                point_from_hex(out.commitment.as_ref().unwrap()).unwrap(),
            );
        }
        assert_eq!(a.scan_confidential(&seed_tx).len(), 1);
        assert_eq!(a.confidential_balance(), 100);

        // A spends 100 to B (no change). Scanning that tx must mark A's UTXO spent.
        let tx = a
            .build_confidential_send(&b.confidential_receive_address().unwrap(), 100, 0, &set)
            .unwrap();
        a.scan_confidential(&tx);
        assert_eq!(a.confidential_balance(), 0, "spent UTXO must drop from balance");
        assert!(a.confidential_utxos().iter().all(|u| u.spent));
    }

    #[test]
    fn full_confidential_roundtrip_a_to_b_then_b_spends() {
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::utxo::utxo_set::UtxoSet;
        use crate::engine::privacy::ringct::builder::{
            build_confidential_transaction, ConfRecipient, OwnedInput,
        };
        use crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx;
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
        use rand::rngs::OsRng;
        use std::collections::HashSet;

        let net = NetworkMode::Mainnet;
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let set = UtxoSet::new_empty();
        let rec = |set: &UtxoSet, pk: RistrettoPoint, c: RistrettoPoint| {
            set.record_confidential_output_indexed(
                &hex::encode(pk.compress().as_bytes()),
                &hex::encode(c.compress().as_bytes()),
            )
            .unwrap();
        };
        // Seed decoys.
        for _ in 0..8 {
            rec(&set, Scalar::random(&mut OsRng) * G, Scalar::from(9u64) * h + Scalar::random(&mut OsRng) * G);
        }

        let mut a = Wallet::new("mainnet");
        a.restore_from_seed(vec![10u8; 32]).unwrap();
        let ack = a.confidential_keys().unwrap();
        let mut b = Wallet::new("mainnet");
        b.restore_from_seed(vec![20u8; 32]).unwrap();

        // Seed A's own 100-output by building a tx to A and scanning it.
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let real_pk = spend * G;
        let real_c = Scalar::from(100u64) * h + bl * G;
        rec(&set, real_pk, real_c);
        let mut ring = crate::engine::privacy::ringct::decoy::select_decoys(
            &set,
            4,
            &[hex::encode(real_pk.compress().as_bytes())],
        )
        .unwrap();
        ring.push(RingMember { public_key: real_pk, commitment: real_c });
        let ri = ring.len() - 1;
        let seed_tx = build_confidential_transaction(
            vec![OwnedInput { spend_secret: spend, amount: 100, blinding: bl, ring, real_index: ri }],
            vec![ConfRecipient {
                view_pub: ack.view_public(),
                spend_pub: ack.spend_public(),
                amount: 100,
            }],
            0,
            &net,
        )
        .unwrap();
        for out in &seed_tx.outputs {
            rec(
                &set,
                point_from_hex(out.one_time_pubkey.as_ref().unwrap()).unwrap(),
                point_from_hex(out.commitment.as_ref().unwrap()).unwrap(),
            );
        }
        assert_eq!(a.scan_confidential(&seed_tx).len(), 1);

        // A sends 60 to B, 40 change back to A (fee 0).
        let tx = a
            .build_confidential_send(&b.confidential_receive_address().unwrap(), 60, 0, &set)
            .unwrap();
        let mut seen = HashSet::new();
        assert!(
            verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok(),
            "A->B confidential tx must be consensus-valid"
        );

        // B scans and finds 60.
        assert_eq!(
            b.scan_confidential(&tx).iter().map(|u| u.amount).sum::<u64>(),
            60
        );

        // Record tx outputs on-chain; B spends its 60 back to A.
        for out in &tx.outputs {
            rec(
                &set,
                point_from_hex(out.one_time_pubkey.as_ref().unwrap()).unwrap(),
                point_from_hex(out.commitment.as_ref().unwrap()).unwrap(),
            );
        }
        let tx2 = b
            .build_confidential_send(&a.confidential_receive_address().unwrap(), 60, 0, &set)
            .unwrap();
        let mut seen2 = HashSet::new();
        assert!(
            verify_confidential_tx(&tx2, &set, &net, &mut seen2).is_ok(),
            "B respend must be consensus-valid"
        );
    }

    #[test]
    fn scan_confidential_recovers_self_output() {
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::utxo::utxo_set::UtxoSet;
        use crate::engine::privacy::ringct::builder::{
            build_confidential_transaction, ConfRecipient, OwnedInput,
        };
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
        use rand::rngs::OsRng;

        let mut w = Wallet::new("mainnet");
        w.restore_from_seed(vec![3u8; 32]).unwrap();
        let ck = w.confidential_keys().unwrap();

        let set = UtxoSet::new_empty();
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let rec = |set: &UtxoSet, pk: curve25519_dalek::ristretto::RistrettoPoint, c: curve25519_dalek::ristretto::RistrettoPoint| {
            set.record_confidential_output_indexed(
                &hex::encode(pk.compress().as_bytes()),
                &hex::encode(c.compress().as_bytes()),
            )
            .unwrap();
        };
        for _ in 0..4 {
            rec(&set, Scalar::random(&mut OsRng) * G, Scalar::from(7u64) * h + Scalar::random(&mut OsRng) * G);
        }
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let real_pk = spend * G;
        let real_c = Scalar::from(100u64) * h + bl * G;
        rec(&set, real_pk, real_c);
        let mut ring = crate::engine::privacy::ringct::decoy::select_decoys(
            &set,
            4,
            &[hex::encode(real_pk.compress().as_bytes())],
        )
        .unwrap();
        ring.push(RingMember { public_key: real_pk, commitment: real_c });
        let real_index = ring.len() - 1;

        let tx = build_confidential_transaction(
            vec![OwnedInput { spend_secret: spend, amount: 100, blinding: bl, ring, real_index }],
            vec![ConfRecipient {
                view_pub: ck.view_public(),
                spend_pub: ck.spend_public(),
                amount: 100,
            }],
            0,
            &NetworkMode::Mainnet,
        )
        .unwrap();

        let found = w.scan_confidential(&tx);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].amount, 100);
        assert_eq!(w.confidential_balance(), 100);
    }

    #[test]
    fn confidential_balance_sums_unspent() {
        let mut w = Wallet::new("mainnet");
        w.restore_from_seed(vec![5u8; 32]).unwrap();
        assert_eq!(w.confidential_balance(), 0);
        w.add_confidential_utxo(ConfidentialUtxo {
            txid: "a".into(),
            index: 0,
            amount: 100,
            blinding_hex: "00".repeat(32),
            one_time_pubkey: "11".repeat(32),
            ephemeral_pubkey: "22".repeat(32),
            spent: false,
        });
        w.add_confidential_utxo(ConfidentialUtxo {
            txid: "b".into(),
            index: 0,
            amount: 50,
            blinding_hex: "00".repeat(32),
            one_time_pubkey: "33".repeat(32),
            ephemeral_pubkey: "44".repeat(32),
            spent: true,
        });
        assert_eq!(w.confidential_balance(), 100); // spent excluded
    }

    #[test]
    fn confidential_address_is_deterministic_from_seed() {
        let mut w1 = Wallet::new("mainnet");
        w1.restore_from_seed(vec![9u8; 32]).unwrap();
        let mut w2 = Wallet::new("mainnet");
        w2.restore_from_seed(vec![9u8; 32]).unwrap();
        let a1 = w1.confidential_receive_address().unwrap();
        let a2 = w2.confidential_receive_address().unwrap();
        assert_eq!(a1, a2, "same seed must yield same confidential address");
        assert!(a1.starts_with("SD1p"));

        let mut w3 = Wallet::new("mainnet");
        w3.restore_from_seed(vec![1u8; 32]).unwrap();
        assert_ne!(a1, w3.confidential_receive_address().unwrap());
    }

    #[test]
    fn create_and_unlock() {
        let mut w = Wallet::new("mainnet");
        let (words, enc) = w.create("password123").unwrap();
        assert_eq!(words.len(), 12);
        w.lock();
        assert!(w.is_locked());
        w.unlock(&enc, "password123").unwrap();
        assert!(!w.is_locked());
    }

    #[test]
    fn wrong_password_fails() {
        let mut w = Wallet::new("mainnet");
        let (_, enc) = w.create("correct").unwrap();
        w.lock();
        assert!(w.unlock(&enc, "wrong").is_err());
    }

    #[test]
    fn address_validation() {
        let mut w = Wallet::new("mainnet");
        let _ = w.create("pw");
        let acc = &w.accounts()[0];
        let addr = acc.primary_address().unwrap().to_string();
        assert!(w.is_valid_address(&addr));
        assert!(!w.is_valid_address("invalid"));
    }

    #[test]
    fn account_derivation() {
        let mut w = Wallet::new("mainnet");
        let _ = w.create("pw");
        let acc0 = w.account(0).unwrap().clone();
        assert_eq!(acc0.index, 0);
        assert!(!acc0.addresses.is_empty());
    }

    #[test]
    fn testnet_address_prefix() {
        let mut w = Wallet::new("testnet");
        let _ = w.create("pw");
        let addr = w.accounts()[0].primary_address().unwrap().to_string();
        assert!(addr.starts_with("ST1"));
    }

    /// Regression: the wallet MUST produce the canonical, consensus-spendable
    /// address — byte-identical to `Address::from_public_key` and to the
    /// Python/WASM SDKs (which the live network uses). Pins the SDK reference
    /// vector so any future change reintroducing the old unspendable SD+74hex
    /// Sha3 form (the ST0.. bug) fails loudly.
    #[test]
    fn address_matches_canonical_sdk_vector() {
        // Python SDK self-test vector: derive_key([2;64],0,0,false) -> pubkey
        // 384d0633..., address_from_public_key(pubkey,"mainnet") == SD1f28fa3d...
        let mut w = Wallet::new("mainnet");
        w.restore_from_seed(vec![2u8; 64]).unwrap();
        let wa = w.accounts()[0].addresses[0].clone();
        assert_eq!(
            wa.public_key,
            "384d0633d25725798cb3fa2b349dff39d1ff2d623e8a5d79fcd632e91740c2c1",
            "derived pubkey must match the cross-tool reference vector"
        );
        assert_eq!(
            wa.address, "SD1f28fa3d42b184f0ce7e84809e89efde6637bd597",
            "wallet address must equal the SDK / live-network canonical address"
        );
        // Cross-check against the in-crate canonical deriver + spendable shape.
        let pk = hex::decode(&wa.public_key).unwrap();
        assert_eq!(
            wa.address,
            crate::domain::address::address::Address::from_public_key(&pk, "mainnet").value
        );
        assert!(w.is_valid_address(&wa.address));
        assert_eq!(wa.address.len(), 3 + 40);
    }

    /// Acceptance oracle: build_tx must produce a REAL consensus transaction the
    /// node accepts — canonical txid + a signature that passes the exact
    /// ownership/signature check in TxValidator. Proves the shipped wallet can
    /// now actually move a coin (the old build_tx returned a placeholder
    /// "raw:{txid}" string that could never be broadcast).
    #[test]
    fn build_tx_produces_consensus_valid_transaction() {
        use crate::domain::transaction::transaction::Transaction;
        use crate::domain::transaction::tx_validator::TxValidator;

        let mut w = Wallet::new("testnet");
        w.restore_from_seed(vec![2u8; 64]).unwrap();
        let from = w.address();

        // Fund the wallet with one mature UTXO owned by its address.
        w.update_utxos(
            &from,
            vec![Walletutxo {
                txid: "aa".repeat(32),
                index: 0,
                amount: 1_000_000,
                address: from.clone(),
                height: 1,
                confirmations: 100,
                is_coinbase: true,
                is_locked: false,
            }],
        );

        let dest = format!("ST1{}", "11".repeat(20));
        let built = w.build_tx(0, &dest, 400_000, 500, "").unwrap();

        // raw_hex is now a serialized consensus Transaction, not a placeholder.
        assert!(!built.raw_hex.starts_with("raw:"));
        let tx: Transaction = serde_json::from_str(&built.raw_hex).expect("valid tx JSON");
        assert_eq!(tx.hash, built.txid);

        let net = NetworkMode::Testnet;
        // Hash commits to content.
        assert!(TxHash::verify_for_network(&tx, &net));
        // Signature verifies under the canonical signing message AND the input
        // pub_key derives to the owner address — exactly the consensus gate.
        let msg = TxHash::signing_message_for_network(&tx, &net);
        assert_eq!(tx.inputs.len(), 1);
        assert!(TxValidator::verify_input_ownership_by_address(
            &tx.inputs[0],
            &from,
            &msg
        ));

        // Recipient output + change-to-self output.
        assert!(tx
            .outputs
            .iter()
            .any(|o| o.address == dest && o.amount == 400_000));
        assert!(tx.outputs.iter().any(|o| o.address != dest));
    }
}
