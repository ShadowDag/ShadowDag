// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// SRC-20 Token Standard — ShadowDAG's equivalent of ERC-20.
//
// A fungible token standard that runs on ShadowVM. Supports:
//   - Token creation with name, symbol, decimals, total supply
//   - Transfer between addresses
//   - Approve + TransferFrom (allowance pattern)
//   - Balance queries
//   - Mint / Burn (owner only)
//   - Privacy-enhanced: supports confidential balances (optional)
//
// This is a native Rust implementation (not bytecode). In production,
// tokens would be deployed as ShadowVM bytecode contracts. This serves
// as both the reference implementation and the built-in token engine.
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::address::address::prefix_from_address;
use crate::errors::VmError;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Token transfer event
#[derive(Debug, Clone)]
pub struct TransferEvent {
    pub from: String,
    pub to: String,
    pub amount: u64,
}

/// Approval event
#[derive(Debug, Clone)]
pub struct ApprovalEvent {
    pub owner: String,
    pub spender: String,
    pub amount: u64,
}

/// Token metadata
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub owner: String,
    pub contract_addr: String,
    pub mintable: bool,
    pub burnable: bool,
}

/// SRC-20 Token Contract
pub struct SRC20Token {
    pub info: TokenInfo,
    balances: BTreeMap<String, u64>,
    allowances: BTreeMap<String, BTreeMap<String, u64>>, // owner -> spender -> amount
    events: Vec<TransferEvent>,
    approval_events: Vec<ApprovalEvent>,
    paused: bool,
}

impl SRC20Token {
    /// Deploy a new token.
    ///
    /// The `owner` must carry a recognized ShadowDAG network prefix
    /// (`SD1` / `ST1` / `SR1`); otherwise this returns
    /// `Err(VmError::ContractError)`. The token's deterministic
    /// contract address inherits the same network prefix, so a
    /// testnet owner produces a `ST1t…` token, a regtest owner
    /// produces a `SR1t…` token, and a mainnet owner produces a
    /// `SD1t…` token — matching the rest of the network-aware
    /// contract-address pipeline in contract_deployer / executor /
    /// wasm / script_runner.
    ///
    /// The previous signature was `-> Self` (infallible) and the
    /// contract address was hardcoded to `SD1t{…}`, so the SRC-20
    /// reference implementation could only ever produce
    /// mainnet-tagged tokens even when deployed on testnet or
    /// regtest. That was the last mainnet-bias hole in the VM.
    pub fn new(
        name: &str,
        symbol: &str,
        decimals: u8,
        initial_supply: u64,
        owner: &str,
    ) -> Result<Self, VmError> {
        let contract_addr = Self::compute_address(name, symbol, owner)?;

        let mut balances = BTreeMap::new();
        balances.insert(owner.to_string(), initial_supply);

        let mut token = Self {
            info: TokenInfo {
                name: name.to_string(),
                symbol: symbol.to_string(),
                decimals,
                total_supply: initial_supply,
                owner: owner.to_string(),
                contract_addr,
                mintable: true,
                burnable: true,
            },
            balances,
            allowances: BTreeMap::new(),
            events: Vec::new(),
            approval_events: Vec::new(),
            paused: false,
        };

        token.events.push(TransferEvent {
            from: "0x0".to_string(), // Mint from zero address
            to: owner.to_string(),
            amount: initial_supply,
        });

        Ok(token)
    }

    // ── ERC-20 Standard Functions ────────────────────────────────

    /// Get token name
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// Get token symbol
    pub fn symbol(&self) -> &str {
        &self.info.symbol
    }

    /// Get decimals
    pub fn decimals(&self) -> u8 {
        self.info.decimals
    }

    /// Get total supply
    pub fn total_supply(&self) -> u64 {
        self.info.total_supply
    }

    /// Get balance of an address
    pub fn balance_of(&self, address: &str) -> u64 {
        *self.balances.get(address).unwrap_or(&0)
    }

    /// Transfer tokens from caller to recipient
    pub fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<(), VmError> {
        if self.paused {
            return Err(VmError::ContractError("Token is paused".to_string()));
        }
        if from == to {
            return Err(VmError::ContractError(
                "Cannot transfer to self".to_string(),
            ));
        }
        if amount == 0 {
            return Err(VmError::ContractError("Amount must be > 0".to_string()));
        }

        let from_balance = self.balance_of(from);
        if from_balance < amount {
            return Err(VmError::ContractError(format!(
                "Insufficient balance: {} has {} but needs {}",
                from, from_balance, amount
            )));
        }

        // Safe math
        let new_from = from_balance
            .checked_sub(amount)
            .ok_or(VmError::ContractError("Underflow".to_string()))?;
        let to_balance = self.balance_of(to);
        let new_to = to_balance
            .checked_add(amount)
            .ok_or(VmError::ContractError("Overflow".to_string()))?;

        self.balances.insert(from.to_string(), new_from);
        self.balances.insert(to.to_string(), new_to);

        self.events.push(TransferEvent {
            from: from.to_string(),
            to: to.to_string(),
            amount,
        });

        Ok(())
    }

    /// Approve spender to transfer up to `amount` from owner
    pub fn approve(&mut self, owner: &str, spender: &str, amount: u64) -> Result<(), VmError> {
        if owner == spender {
            return Err(VmError::ContractError("Cannot approve self".to_string()));
        }

        self.allowances
            .entry(owner.to_string())
            .or_default()
            .insert(spender.to_string(), amount);

        self.approval_events.push(ApprovalEvent {
            owner: owner.to_string(),
            spender: spender.to_string(),
            amount,
        });

        Ok(())
    }

    /// Get the allowance for a spender
    pub fn allowance(&self, owner: &str, spender: &str) -> u64 {
        self.allowances
            .get(owner)
            .and_then(|m| m.get(spender))
            .copied()
            .unwrap_or(0)
    }

    /// Transfer tokens on behalf of the owner (requires approval)
    pub fn transfer_from(
        &mut self,
        spender: &str,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<(), VmError> {
        let allowed = self.allowance(from, spender);
        if allowed < amount {
            return Err(VmError::ContractError(format!(
                "Allowance exceeded: {} approved {} but trying {}",
                from, allowed, amount
            )));
        }

        // Execute the transfer
        self.transfer(from, to, amount)?;

        // Reduce allowance
        let new_allowance = allowed.saturating_sub(amount);
        self.allowances
            .entry(from.to_string())
            .or_default()
            .insert(spender.to_string(), new_allowance);

        Ok(())
    }

    // ── Extended Functions (beyond ERC-20) ───────────────────────

    /// Mint new tokens (owner only)
    pub fn mint(&mut self, caller: &str, to: &str, amount: u64) -> Result<(), VmError> {
        if caller != self.info.owner {
            return Err(VmError::ContractError("Only owner can mint".to_string()));
        }
        if !self.info.mintable {
            return Err(VmError::ContractError("Token is not mintable".to_string()));
        }

        let new_supply = self
            .info
            .total_supply
            .checked_add(amount)
            .ok_or(VmError::ContractError("Supply overflow".to_string()))?;
        let new_balance = self
            .balance_of(to)
            .checked_add(amount)
            .ok_or(VmError::ContractError("Balance overflow".to_string()))?;

        self.info.total_supply = new_supply;
        self.balances.insert(to.to_string(), new_balance);

        self.events.push(TransferEvent {
            from: "0x0".to_string(),
            to: to.to_string(),
            amount,
        });

        Ok(())
    }

    /// Burn tokens (from caller's own balance).
    ///
    /// Fails closed on supply-underflow: the old implementation used
    /// `self.info.total_supply.saturating_sub(amount)`, which silently
    /// clipped `total_supply` to `0` if the aggregate balance had
    /// drifted below the reported supply for any reason. That turned
    /// an accounting invariant break — i.e. "this token's books don't
    /// balance" — into a normal successful burn, hiding the bug from
    /// everyone. The new code uses `checked_sub` and returns an
    /// explicit `ContractError("supply invariant broken …")` so the
    /// caller sees the corruption instead of burning over it.
    pub fn burn(&mut self, caller: &str, amount: u64) -> Result<(), VmError> {
        if !self.info.burnable {
            return Err(VmError::ContractError("Token is not burnable".to_string()));
        }

        let balance = self.balance_of(caller);
        if balance < amount {
            return Err(VmError::ContractError(format!(
                "Cannot burn {} — only has {}",
                amount, balance
            )));
        }

        // Checked supply subtraction. If this underflows, the token's
        // internal bookkeeping is broken (individual balances add up to
        // MORE than the recorded total_supply), which is a bug the
        // token contract should surface, not silently swallow.
        let new_supply = self.info.total_supply.checked_sub(amount).ok_or_else(|| {
            VmError::ContractError(format!(
                "supply invariant broken: cannot burn {} because total_supply \
                 ({}) is smaller than the caller's balance ({}). This indicates \
                 the internal accounting has drifted and the token is in an \
                 inconsistent state — the burn is refused so the corruption \
                 is not compounded.",
                amount, self.info.total_supply, balance
            ))
        })?;

        self.balances.insert(caller.to_string(), balance - amount);
        self.info.total_supply = new_supply;

        self.events.push(TransferEvent {
            from: caller.to_string(),
            to: "0x0".to_string(),
            amount,
        });

        Ok(())
    }

    /// Pause all transfers (owner only, emergency)
    pub fn pause(&mut self, caller: &str) -> Result<(), VmError> {
        if caller != self.info.owner {
            return Err(VmError::ContractError("Only owner can pause".to_string()));
        }
        self.paused = true;
        Ok(())
    }

    /// Unpause transfers
    pub fn unpause(&mut self, caller: &str) -> Result<(), VmError> {
        if caller != self.info.owner {
            return Err(VmError::ContractError("Only owner can unpause".to_string()));
        }
        self.paused = false;
        Ok(())
    }

    /// Transfer ownership to `new_owner`.
    ///
    /// Refuses an empty `new_owner` string — a zero-length owner
    /// would permanently break every future owner check because
    /// `caller != self.info.owner` can never be satisfied by a
    /// non-empty caller, yet `self.info.owner == ""` also makes
    /// `caller == self.info.owner` accidentally true for callers
    /// who themselves happen to pass an empty string. The result
    /// is a token whose `mint`/`pause`/`burn` authorization model
    /// is in an unresolvable state. Reject the transition up front.
    ///
    /// Also refuses transferring ownership to the current owner,
    /// which is a no-op that should surface as an error so the
    /// caller knows the transaction accomplished nothing.
    pub fn transfer_ownership(&mut self, caller: &str, new_owner: &str) -> Result<(), VmError> {
        if caller != self.info.owner {
            return Err(VmError::ContractError(
                "Only owner can transfer ownership".to_string(),
            ));
        }
        if new_owner.is_empty() {
            return Err(VmError::ContractError(
                "Cannot transfer ownership to an empty address — owner checks \
                 would become ambiguous and the token's authorization model \
                 would be unresolvable"
                    .to_string(),
            ));
        }
        if new_owner == self.info.owner {
            return Err(VmError::ContractError(
                "new_owner is identical to current owner — refusing no-op transfer".to_string(),
            ));
        }
        self.info.owner = new_owner.to_string();
        Ok(())
    }

    /// Get all transfer events
    pub fn events(&self) -> &[TransferEvent] {
        &self.events
    }

    /// Get holder count
    pub fn holder_count(&self) -> usize {
        self.balances.values().filter(|&&b| b > 0).count()
    }

    /// Get top holders
    pub fn top_holders(&self, limit: usize) -> Vec<(String, u64)> {
        let mut holders: Vec<_> = self
            .balances
            .iter()
            .filter(|(_, &b)| b > 0)
            .map(|(a, &b)| (a.clone(), b))
            .collect();
        holders.sort_by(|a, b| b.1.cmp(&a.1));
        holders.truncate(limit);
        holders
    }

    /// Compute the deterministic token contract address for
    /// `(name, symbol, owner)`.
    ///
    /// The address format is `{net_prefix}t{20_bytes_hex}`, where
    /// `net_prefix` is the 3-character on-chain prefix of the
    /// owner's network (`SD1` / `ST1` / `SR1`). The previous
    /// implementation hardcoded `"SD1t"`, which tagged every SRC-20
    /// token as mainnet regardless of where it was actually
    /// deployed.
    ///
    /// Returns `Err(VmError::ContractError)` if `owner` does not
    /// carry a recognized ShadowDAG prefix — a non-ShadowDAG string
    /// cannot have its network determined, and silently defaulting
    /// to mainnet is exactly the bug this commit is closing.
    fn compute_address(name: &str, symbol: &str, owner: &str) -> Result<String, VmError> {
        let net_prefix = prefix_from_address(owner).ok_or_else(|| {
            VmError::ContractError(format!(
                "token owner '{}' has unknown network prefix (expected SD1/ST1/SR1) \
                 — SRC-20 reference implementation cannot mint a token for a deployer \
                 whose network cannot be determined",
                owner
            ))
        })?;
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_SRC20_v1");
        h.update(name.as_bytes());
        h.update(symbol.as_bytes());
        h.update(owner.as_bytes());
        Ok(format!(
            "{}t{}",
            net_prefix,
            hex::encode(&h.finalize()[..20])
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                            TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn create_token() -> SRC20Token {
        SRC20Token::new("ShadowToken", "STKN", 8, 1_000_000, "SD1owner")
            .expect("SD1owner has a valid mainnet prefix")
    }

    #[test]
    fn token_creation() {
        let token = create_token();
        assert_eq!(token.name(), "ShadowToken");
        assert_eq!(token.symbol(), "STKN");
        assert_eq!(token.decimals(), 8);
        assert_eq!(token.total_supply(), 1_000_000);
        assert_eq!(token.balance_of("SD1owner"), 1_000_000);
        assert!(token.info.contract_addr.starts_with("SD1t"));
    }

    #[test]
    fn transfer_success() {
        let mut token = create_token();
        token.transfer("SD1owner", "SD1alice", 500).unwrap();
        assert_eq!(token.balance_of("SD1owner"), 999_500);
        assert_eq!(token.balance_of("SD1alice"), 500);
    }

    #[test]
    fn transfer_insufficient_fails() {
        let mut token = create_token();
        assert!(token.transfer("SD1owner", "SD1alice", 2_000_000).is_err());
    }

    #[test]
    fn transfer_zero_fails() {
        let mut token = create_token();
        assert!(token.transfer("SD1owner", "SD1alice", 0).is_err());
    }

    #[test]
    fn transfer_to_self_fails() {
        let mut token = create_token();
        assert!(token.transfer("SD1owner", "SD1owner", 100).is_err());
    }

    #[test]
    fn approve_and_transfer_from() {
        let mut token = create_token();
        token.approve("SD1owner", "SD1spender", 300).unwrap();
        assert_eq!(token.allowance("SD1owner", "SD1spender"), 300);

        token
            .transfer_from("SD1spender", "SD1owner", "SD1bob", 200)
            .unwrap();
        assert_eq!(token.balance_of("SD1bob"), 200);
        assert_eq!(token.allowance("SD1owner", "SD1spender"), 100);
    }

    #[test]
    fn transfer_from_exceeds_allowance() {
        let mut token = create_token();
        token.approve("SD1owner", "SD1spender", 100).unwrap();
        assert!(token
            .transfer_from("SD1spender", "SD1owner", "SD1bob", 500)
            .is_err());
    }

    #[test]
    fn mint_by_owner() {
        let mut token = create_token();
        token.mint("SD1owner", "SD1alice", 500).unwrap();
        assert_eq!(token.balance_of("SD1alice"), 500);
        assert_eq!(token.total_supply(), 1_000_500);
    }

    #[test]
    fn mint_by_non_owner_fails() {
        let mut token = create_token();
        assert!(token.mint("SD1hacker", "SD1hacker", 999).is_err());
    }

    #[test]
    fn burn_tokens() {
        let mut token = create_token();
        token.burn("SD1owner", 200).unwrap();
        assert_eq!(token.balance_of("SD1owner"), 999_800);
        assert_eq!(token.total_supply(), 999_800);
    }

    #[test]
    fn burn_more_than_balance_fails() {
        let mut token = create_token();
        assert!(token.burn("SD1owner", 2_000_000).is_err());
    }

    #[test]
    fn burn_fails_closed_when_supply_invariant_broken() {
        // Regression for the saturating_sub masking bug. Stage an
        // artificial invariant break by driving total_supply below
        // the caller's balance (would normally never happen, but
        // does indicate the token's books are corrupted). The old
        // burn would silently saturate total_supply to 0 and hide
        // the corruption; the new burn must refuse with an explicit
        // "supply invariant broken" error.
        let mut token = create_token();
        // Force the invariant break: balance is 1_000_000 but we
        // pretend the recorded supply is only 500.
        token.info.total_supply = 500;

        // Burn 1000: passes the balance check (balance >= 1000) but
        // would underflow total_supply (500 - 1000). Old code would
        // set total_supply = 0 silently; new code must Err.
        let result = token.burn("SD1owner", 1000);
        assert!(result.is_err(), "burn must refuse when supply < amount");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("supply invariant broken"),
            "error must describe the invariant break, got: {}",
            msg
        );
        // Crucially, the token state must be UNCHANGED by the failed
        // burn — no partial debit, no partial supply change.
        assert_eq!(
            token.balance_of("SD1owner"),
            1_000_000,
            "failed burn must not debit the caller"
        );
        assert_eq!(
            token.info.total_supply, 500,
            "failed burn must not mutate total_supply"
        );
    }

    #[test]
    fn pause_blocks_transfers() {
        let mut token = create_token();
        token.pause("SD1owner").unwrap();
        assert!(token.transfer("SD1owner", "SD1alice", 100).is_err());
        token.unpause("SD1owner").unwrap();
        token.transfer("SD1owner", "SD1alice", 100).unwrap();
    }

    #[test]
    fn transfer_ownership_rejects_empty_new_owner() {
        // Regression for the "owner = empty string" bug. An empty
        // new_owner makes every future caller == owner check
        // ambiguous, so the transition must be refused.
        let mut token = create_token();
        let result = token.transfer_ownership("SD1owner", "");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("empty"));
        // State must be unchanged.
        assert_eq!(token.info.owner, "SD1owner");
    }

    #[test]
    fn transfer_ownership_rejects_same_owner() {
        // No-op transfer is also refused so the caller knows
        // nothing happened.
        let mut token = create_token();
        let result = token.transfer_ownership("SD1owner", "SD1owner");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("identical"));
        assert_eq!(token.info.owner, "SD1owner");
    }

    #[test]
    fn transfer_ownership() {
        let mut token = create_token();
        token
            .transfer_ownership("SD1owner", "SD1new_owner")
            .unwrap();
        assert_eq!(token.info.owner, "SD1new_owner");
        // Old owner can't pause anymore
        assert!(token.pause("SD1owner").is_err());
    }

    #[test]
    fn events_recorded() {
        let mut token = create_token();
        token.transfer("SD1owner", "SD1alice", 100).unwrap();
        token.transfer("SD1owner", "SD1bob", 200).unwrap();
        // 1 mint event + 2 transfers = 3
        assert_eq!(token.events().len(), 3);
    }

    #[test]
    fn holder_count() {
        let mut token = create_token();
        token.transfer("SD1owner", "SD1alice", 100).unwrap();
        token.transfer("SD1owner", "SD1bob", 200).unwrap();
        assert_eq!(token.holder_count(), 3);
    }

    #[test]
    fn top_holders() {
        let mut token = create_token();
        token.transfer("SD1owner", "SD1alice", 100).unwrap();
        token.transfer("SD1owner", "SD1bob", 300).unwrap();
        let top = token.top_holders(2);
        assert_eq!(top[0].0, "SD1owner"); // Highest balance
        assert_eq!(top[1].0, "SD1bob"); // Second highest
    }

    #[test]
    fn complex_scenario() {
        let mut token = SRC20Token::new("ShadowUSD", "SUSD", 6, 10_000_000, "SD1bank")
            .expect("SD1bank has a valid mainnet prefix");

        // Bank distributes to users
        token.transfer("SD1bank", "SD1alice", 1_000).unwrap();
        token.transfer("SD1bank", "SD1bob", 2_000).unwrap();

        // Alice approves Bob to spend her tokens
        token.approve("SD1alice", "SD1bob", 500).unwrap();

        // Bob transfers from Alice to Charlie
        token
            .transfer_from("SD1bob", "SD1alice", "SD1charlie", 300)
            .unwrap();

        // Verify balances
        assert_eq!(token.balance_of("SD1bank"), 9_997_000);
        assert_eq!(token.balance_of("SD1alice"), 700);
        assert_eq!(token.balance_of("SD1bob"), 2_000);
        assert_eq!(token.balance_of("SD1charlie"), 300);
        assert_eq!(token.allowance("SD1alice", "SD1bob"), 200);

        // Bank burns some supply
        token.burn("SD1bank", 1_000_000).unwrap();
        assert_eq!(token.total_supply(), 9_000_000);

        // Bank mints more
        token.mint("SD1bank", "SD1alice", 5_000).unwrap();
        assert_eq!(token.balance_of("SD1alice"), 5_700);
        assert_eq!(token.total_supply(), 9_005_000);
    }

    // ─── Network-aware compute_address regression tests ──────────────

    #[test]
    fn mainnet_owner_produces_sd1t_token_address() {
        // Regression pin: the pre-existing SD1owner tests must
        // continue to produce SD1t-tagged tokens after the network
        // derivation was made dynamic. This guards against a future
        // "simplification" that drops the mainnet prefix by accident.
        let token = SRC20Token::new("T", "T", 0, 1, "SD1owner").unwrap();
        assert!(
            token.info.contract_addr.starts_with("SD1t"),
            "mainnet owner must produce SD1t-prefixed contract address, got: {}",
            token.info.contract_addr
        );
    }

    #[test]
    fn testnet_owner_produces_st1t_token_address() {
        // Regression for the hardcoded "SD1t" bug. A testnet owner
        // must produce a testnet-tagged token address. The old code
        // would have silently produced SD1t regardless.
        let token = SRC20Token::new("T", "T", 0, 1, "ST1testowner").unwrap();
        assert!(
            token.info.contract_addr.starts_with("ST1t"),
            "testnet owner must produce ST1t-prefixed contract address, got: {}",
            token.info.contract_addr
        );
        assert!(
            !token.info.contract_addr.starts_with("SD1"),
            "testnet owner must NOT leak SD1 (mainnet) tag, got: {}",
            token.info.contract_addr
        );
    }

    #[test]
    fn regtest_owner_produces_sr1t_token_address() {
        let token = SRC20Token::new("T", "T", 0, 1, "SR1regowner").unwrap();
        assert!(
            token.info.contract_addr.starts_with("SR1t"),
            "regtest owner must produce SR1t-prefixed contract address, got: {}",
            token.info.contract_addr
        );
        assert!(
            !token.info.contract_addr.starts_with("SD1"),
            "regtest owner must NOT leak SD1 (mainnet) tag, got: {}",
            token.info.contract_addr
        );
    }

    #[test]
    fn different_networks_produce_different_token_addresses() {
        // Same (name, symbol), different network prefixes → different
        // contract addresses. This prevents a testnet and mainnet
        // deployment of the "same" token from aliasing at the same
        // address.
        let m = SRC20Token::new("Same", "SAME", 0, 1, "SD1owner").unwrap();
        let t = SRC20Token::new("Same", "SAME", 0, 1, "ST1owner").unwrap();
        let r = SRC20Token::new("Same", "SAME", 0, 1, "SR1owner").unwrap();

        assert_ne!(m.info.contract_addr, t.info.contract_addr);
        assert_ne!(t.info.contract_addr, r.info.contract_addr);
        assert_ne!(m.info.contract_addr, r.info.contract_addr);

        assert!(m.info.contract_addr.starts_with("SD1t"));
        assert!(t.info.contract_addr.starts_with("ST1t"));
        assert!(r.info.contract_addr.starts_with("SR1t"));
    }

    #[test]
    fn unknown_owner_prefix_rejected() {
        // An owner string with no recognized ShadowDAG prefix must
        // be refused — silently defaulting to SD1 was the whole bug.
        //
        // Note: SRC20Token does not derive Debug, so we avoid
        // `unwrap_err()` (which requires `T: Debug`) and match
        // on the Result directly.
        match SRC20Token::new("T", "T", 0, 1, "BTC1foreign") {
            Ok(_) => panic!("BTC1foreign must be refused"),
            Err(e) => {
                let msg = format!("{}", e);
                assert!(
                    msg.contains("unknown network prefix"),
                    "error must explain the problem, got: {}",
                    msg
                );
            }
        }

        // Empty owner is also refused.
        assert!(SRC20Token::new("T", "T", 0, 1, "").is_err());

        // A bare deployer name like "deployer" has no prefix.
        assert!(SRC20Token::new("T", "T", 0, 1, "deployer").is_err());
    }
}
