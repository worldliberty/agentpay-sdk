//! [`FakeCluster`]: an in-process Solana cluster behind
//! `solana-rpc-client`'s `RpcSender` seam, for paymentd's tests.
//!
//! It answers the JSON-RPC methods the flows use from a small account map,
//! records every call and submitted transaction, and simulates the effects
//! that matter to the flows: creating and initializing nonce accounts and
//! advancing them. Balances are not tracked.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Value};
use solana_nonce::state::{Data as NonceData, DurableNonce, State as NonceState};
use solana_nonce::versions::Versions as NonceVersions;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client::rpc_client::RpcClientConfig;
use solana_rpc_client::rpc_sender::{RpcSender, RpcTransportStats};
use solana_rpc_client_api::client_error::Result as ClientResult;
use solana_rpc_client_api::config::CommitmentConfig;
use solana_rpc_client_api::request::{RpcError, RpcRequest, RpcResponseErrorData};
use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::{Transaction, VersionedTransaction};
use solana_system_interface::instruction::SystemInstruction;
use spl_token_2022_interface::extension::transfer_fee::{TransferFee, TransferFeeConfig};
use spl_token_2022_interface::extension::transfer_hook::TransferHook;
use spl_token_2022_interface::extension::{
    BaseStateWithExtensionsMut, ExtensionType, StateWithExtensionsMut,
};
use spl_token_2022_interface::state::Mint;

use super::accounts::{associated_token_account, system_program_id, NONCE_ACCOUNT_LEN};
use super::{ConfirmationWait, PendingStore, SolanaProvider};

/// Devnet's genesis hash.
pub(crate) const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
/// Rent the fake charges for an 80-byte nonce account.
pub(crate) const NONCE_RENT: u64 = 1_447_680;

/// What `getSignatureStatuses` reports for submitted transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StatusMode {
    /// `finalized`.
    Finalized,
    /// Executed with this instruction error.
    Failed,
    /// Never seen (the wait times out).
    Unknown,
}

pub(crate) struct ClusterState {
    pub(crate) genesis: Hash,
    pub(crate) blockhash: Hash,
    pub(crate) accounts: HashMap<Pubkey, Account>,
    pub(crate) epoch: u64,
    pub(crate) prioritization_fees: Vec<u64>,
    pub(crate) status: StatusMode,
    pub(crate) sent: Vec<Transaction>,
    pub(crate) calls: Vec<String>,
    /// Methods that fail with a node error.
    pub(crate) failing: Vec<String>,
}

/// A shared, scriptable cluster; clones share state.
#[derive(Clone)]
pub(crate) struct FakeCluster {
    pub(crate) state: Arc<Mutex<ClusterState>>,
}

impl FakeCluster {
    /// An empty devnet.
    pub(crate) fn devnet() -> Self {
        Self {
            state: Arc::new(Mutex::new(ClusterState {
                genesis: DEVNET_GENESIS.parse().expect("genesis"),
                blockhash: Hash::new_from_array([7; 32]),
                accounts: HashMap::new(),
                epoch: 500,
                prioritization_fees: vec![0, 1_000, 3_000, 2_000],
                status: StatusMode::Finalized,
                sent: Vec::new(),
                calls: Vec::new(),
                failing: Vec::new(),
            })),
        }
    }

    /// A provider whose every client talks to this cluster, with an
    /// in-memory pending store and a short confirmation wait.
    pub(crate) fn provider(&self) -> SolanaProvider {
        let cluster = self.clone();
        let mut provider = SolanaProvider::with_connector(
            Arc::new(move |_url: &str| {
                RpcClient::new_sender(
                    cluster.clone(),
                    RpcClientConfig::with_commitment(CommitmentConfig::confirmed()),
                )
            }),
            PendingStore::in_memory(),
        );
        provider.confirmation = ConfirmationWait {
            timeout: Duration::from_millis(30),
            interval: Duration::from_millis(5),
        };
        provider
    }

    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut ClusterState) -> R) -> R {
        f(&mut self.state.lock().expect("cluster lock"))
    }

    /// How often `method` was called.
    pub(crate) fn calls(&self, method: &str) -> usize {
        self.with(|s| s.calls.iter().filter(|call| *call == method).count())
    }

    /// Every submitted transaction.
    pub(crate) fn sent(&self) -> Vec<Transaction> {
        self.with(|s| s.sent.clone())
    }

    /// Adds a mint and returns its address.
    pub(crate) fn add_mint(
        &self,
        program: Pubkey,
        decimals: u8,
        transfer_fee_bps: Option<(u16, u64)>,
        transfer_hook: bool,
    ) -> Pubkey {
        let base = Mint {
            mint_authority: None.into(),
            supply: 1_000_000_000_000,
            decimals,
            is_initialized: true,
            freeze_authority: None.into(),
        };
        let mut types = Vec::new();
        if transfer_fee_bps.is_some() {
            types.push(ExtensionType::TransferFeeConfig);
        }
        if transfer_hook {
            types.push(ExtensionType::TransferHook);
        }
        let data = if types.is_empty() {
            let mut data = vec![0; Mint::LEN];
            Mint::pack(base, &mut data).expect("pack mint");
            data
        } else {
            let len = ExtensionType::try_calculate_account_len::<Mint>(&types).expect("len");
            let mut data = vec![0; len];
            let mut state =
                StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut data).expect("state");
            if let Some((bps, maximum)) = transfer_fee_bps {
                let fee = TransferFee {
                    epoch: 0.into(),
                    maximum_fee: maximum.into(),
                    transfer_fee_basis_points: bps.into(),
                };
                let config = state
                    .init_extension::<TransferFeeConfig>(true)
                    .expect("fee extension");
                config.older_transfer_fee = fee;
                config.newer_transfer_fee = fee;
            }
            if transfer_hook {
                let hook = state.init_extension::<TransferHook>(true).expect("hook");
                hook.program_id = Some(Pubkey::new_unique()).try_into().expect("hook id");
            }
            state.base = base;
            state.pack_base();
            state.init_account_type().expect("account type");
            data
        };
        let mint = Pubkey::new_unique();
        self.put_account(mint, program, data);
        mint
    }

    /// Creates `owner`'s associated token account for `mint`.
    pub(crate) fn add_token_account(&self, owner: &Pubkey, mint: &Pubkey, program: Pubkey) {
        let address = associated_token_account(owner, mint, &program);
        self.put_account(address, program, vec![0; 165]);
    }

    /// Creates an initialized durable nonce account and returns its nonce.
    pub(crate) fn add_nonce_account(&self, address: Pubkey, authority: Pubkey) -> Hash {
        let nonce = Hash::new_from_array([9; 32]);
        self.put_account(address, system_program_id(), nonce_data(authority, &nonce));
        self.with(|s| s.accounts.get(&address).map(current_nonce))
            .flatten()
            .expect("nonce")
    }

    /// Advances the nonce stored in `address` to a fresh value.
    pub(crate) fn advance_nonce(&self, address: &Pubkey) {
        self.with(|s| {
            let account = s.accounts.get_mut(address).expect("nonce account");
            let versions: NonceVersions = bincode::deserialize(&account.data).expect("nonce");
            if let NonceState::Initialized(data) = versions.state() {
                account.data = nonce_data(data.authority, &Hash::new_unique());
            }
        });
    }

    /// The current nonce value stored in `address`.
    pub(crate) fn nonce_of(&self, address: &Pubkey) -> Option<Hash> {
        self.with(|s| s.accounts.get(address).and_then(current_nonce))
    }

    pub(crate) fn put_account(&self, address: Pubkey, owner: Pubkey, data: Vec<u8>) {
        self.with(|s| {
            s.accounts.insert(
                address,
                Account {
                    lamports: 1_000_000,
                    data,
                    owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )
        });
    }
}

fn nonce_data(authority: Pubkey, blockhash: &Hash) -> Vec<u8> {
    let state = NonceState::Initialized(NonceData::new(
        authority,
        DurableNonce::from_blockhash(blockhash),
        5_000,
    ));
    let mut data = bincode::serialize(&NonceVersions::new(state)).expect("nonce state");
    data.resize(NONCE_ACCOUNT_LEN, 0);
    data
}

fn current_nonce(account: &Account) -> Option<Hash> {
    match bincode::deserialize::<NonceVersions>(&account.data)
        .ok()?
        .state()
    {
        NonceState::Initialized(data) => Some(data.blockhash()),
        NonceState::Uninitialized => None,
    }
}

fn node_error(message: &str) -> solana_rpc_client_api::client_error::Error {
    RpcError::RpcResponseError {
        code: -32002,
        message: message.to_string(),
        data: RpcResponseErrorData::Empty,
    }
    .into()
}

fn context(value: Value) -> Value {
    json!({"context": {"slot": 77}, "value": value})
}

impl ClusterState {
    fn account_json(&self, params: &Value) -> Value {
        context(self.one_account_json(params.get(0)))
    }

    /// `getMultipleAccounts`: one entry (or `null`) per requested key.
    fn accounts_json(&self, params: &Value) -> Value {
        let keys = params.get(0).and_then(Value::as_array).cloned();
        context(Value::Array(
            keys.unwrap_or_default()
                .iter()
                .map(|key| self.one_account_json(Some(key)))
                .collect(),
        ))
    }

    fn one_account_json(&self, key: Option<&Value>) -> Value {
        let address: Option<Pubkey> = key.and_then(Value::as_str).and_then(|key| key.parse().ok());
        let account = address.and_then(|address| self.accounts.get(&address));
        account.map_or(Value::Null, |account| {
            json!({
                "data": [base64::engine::general_purpose::STANDARD.encode(&account.data), "base64"],
                "executable": account.executable,
                "lamports": account.lamports,
                "owner": account.owner.to_string(),
                "rentEpoch": account.rent_epoch,
                "space": account.data.len(),
            })
        })
    }

    fn submit(&mut self, params: &Value) -> ClientResult<Value> {
        let encoded = params.get(0).and_then(Value::as_str).unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| node_error("invalid base64"))?;
        let transaction = bincode::deserialize::<VersionedTransaction>(&bytes)
            .ok()
            .and_then(VersionedTransaction::into_legacy_transaction)
            .ok_or_else(|| node_error("invalid transaction"))?;
        let keys = &transaction.message.account_keys;
        for ix in &transaction.message.instructions {
            let Some(program) = keys.get(usize::from(ix.program_id_index)) else {
                continue;
            };
            if *program != system_program_id() {
                continue;
            }
            let account = |i: usize| keys[usize::from(ix.accounts[i])];
            match bincode::deserialize::<SystemInstruction>(&ix.data) {
                Ok(SystemInstruction::CreateAccountWithSeed { space, owner, .. }) => {
                    let data = vec![0; usize::try_from(space).expect("space")];
                    self.accounts.insert(
                        account(1),
                        Account {
                            lamports: NONCE_RENT,
                            data,
                            owner,
                            executable: false,
                            rent_epoch: 0,
                        },
                    );
                }
                Ok(SystemInstruction::InitializeNonceAccount(authority)) => {
                    let nonce = self.blockhash;
                    if let Some(nonce_account) = self.accounts.get_mut(&account(0)) {
                        nonce_account.data = nonce_data(authority, &nonce);
                    }
                }
                Ok(SystemInstruction::AdvanceNonceAccount) => {
                    let next = Hash::new_unique();
                    if let Some(nonce_account) = self.accounts.get_mut(&account(0)) {
                        if let NonceState::Initialized(data) =
                            bincode::deserialize::<NonceVersions>(&nonce_account.data)
                                .expect("nonce")
                                .state()
                        {
                            nonce_account.data = nonce_data(data.authority, &next);
                        }
                    }
                }
                _ => {}
            }
        }
        let signature = transaction.signatures[0].to_string();
        self.sent.push(transaction);
        Ok(json!(signature))
    }

    fn statuses(&self, params: &Value) -> Value {
        let count = params.get(0).and_then(Value::as_array).map_or(0, Vec::len);
        let status = match self.status {
            StatusMode::Finalized => json!({
                "slot": 88, "confirmations": null, "err": null,
                "status": {"Ok": null}, "confirmationStatus": "finalized"
            }),
            StatusMode::Failed => json!({
                "slot": 89, "confirmations": 1,
                "err": {"InstructionError": [1, {"Custom": 1}]},
                "status": {"Err": {"InstructionError": [1, {"Custom": 1}]}},
                "confirmationStatus": "confirmed"
            }),
            StatusMode::Unknown => Value::Null,
        };
        context(Value::Array(vec![status; count]))
    }
}

#[async_trait]
impl RpcSender for FakeCluster {
    async fn send(&self, request: RpcRequest, params: Value) -> ClientResult<Value> {
        let method = request.to_string();
        let mut state = self.state.lock().expect("cluster lock");
        state.calls.push(method.clone());
        if state.failing.contains(&method) {
            return Err(node_error("scripted failure"));
        }
        Ok(match method.as_str() {
            "getGenesisHash" => json!(state.genesis.to_string()),
            "getLatestBlockhash" => context(json!({
                "blockhash": state.blockhash.to_string(),
                "lastValidBlockHeight": 1_000
            })),
            "getAccountInfo" => state.account_json(&params),
            "getMultipleAccounts" => state.accounts_json(&params),
            "getMinimumBalanceForRentExemption" => json!(NONCE_RENT),
            "getEpochInfo" => json!({
                "absoluteSlot": 77, "blockHeight": 70, "epoch": state.epoch,
                "slotIndex": 1, "slotsInEpoch": 432_000, "transactionCount": null
            }),
            "getRecentPrioritizationFees" => Value::Array(
                state
                    .prioritization_fees
                    .iter()
                    .map(|fee| json!({"slot": 77, "prioritizationFee": fee}))
                    .collect(),
            ),
            "sendTransaction" => return state.submit(&params),
            "getSignatureStatuses" => state.statuses(&params),
            other => return Err(node_error(&format!("unsupported method {other}"))),
        })
    }

    fn get_transport_stats(&self) -> RpcTransportStats {
        RpcTransportStats::default()
    }

    fn url(&self) -> String {
        "fake-cluster".to_string()
    }
}
