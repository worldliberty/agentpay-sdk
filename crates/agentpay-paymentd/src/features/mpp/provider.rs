//! [`AgentPayProvider`]: paymentd's implementation of `mpp`'s open
//! [`PaymentProvider`] trait.
//!
//! `mpp`'s own `TempoProvider` only takes local keys, so this provider plugs
//! the signer daemon into `mpp`'s client flow instead: `mpp` parses and
//! ranks challenges, builds the request retries, checks origins and
//! receipts, and calls back here to choose a challenge, pay it, and commit
//! or roll back session state. Every signature comes from the signer
//! daemon's typed actions (`BroadcastTx` for charges, the
//! `TempoSessionV2*` actions for sessions).
//!
//! The provider is created per call with the persisted channel already
//! loaded, so challenge selection can be filtered by it. Errors from the
//! daemon are kept in an [`ErrorSlot`] and reported as the original
//! [`PaymentsError`] after the flow returns.

use std::sync::{Arc, Mutex, MutexGuard};

use mpp::client::{PaymentContext, PaymentProvider};
use mpp::protocol::core::{PaymentChallenge, PaymentCredential};
use mpp::MppError;

use super::charge::{self, Charged};
use super::evm_charge;
use super::management;
use super::select::{self, Intent, Offer, Payable, Preferences};
use super::session::{self, Opened};
use super::solana_charge;
use super::store::{SessionRecord, SessionStore};
use crate::error::PaymentsError;
use crate::features::payer::{ErrorSlot, Payer};

/// The caller's choices for one call.
#[derive(Debug, Clone, Default)]
pub(crate) struct Settings {
    /// Only pay this exact amount.
    pub(crate) amount: Option<u128>,
    /// Never pay more than this per payment (the proxy's cap).
    pub(crate) max_amount: Option<u128>,
    /// Deposit for new channels and default top-up target.
    pub(crate) deposit: Option<u128>,
    /// Cap on a channel's total deposit.
    pub(crate) max_deposit: Option<u128>,
    /// Only this token: an EVM address, a Solana mint, or `"sol"`.
    pub(crate) currency: Option<String>,
    /// Only this configured network.
    pub(crate) network: Option<String>,
    /// Tokens configured in AgentPay (`known_tokens`), preferred when several are offered.
    pub(crate) known_tokens: Vec<(u64, String)>,
    /// Persist the channel under this name.
    pub(crate) session_key: Option<String>,
    /// Origin of the request URL.
    pub(crate) origin: String,
    /// The request URL, lower case (testnet hints).
    pub(crate) url: String,
}

/// The channel this call uses.
#[derive(Debug, Clone)]
pub(super) struct Active {
    pub(super) record: SessionRecord,
    pub(super) opened: bool,
    pub(super) topped_up: u128,
    pub(super) vouchers: u32,
    pub(super) fee_payer: bool,
}

/// What the last `pay` did.
#[derive(Debug, Clone)]
pub(super) struct Paid {
    pub(super) challenge: PaymentChallenge,
    pub(super) offer: Payable,
    pub(super) charge: Option<Charged>,
}

#[derive(Debug, Default)]
pub(super) struct State {
    /// The channel persisted under `session_key` (loaded before selection).
    pub(super) persisted: Option<SessionRecord>,
    /// The channel in use.
    pub(super) active: Option<Active>,
    /// The channel as it will be once the merchant accepts the credential.
    pending: Option<Active>,
    /// The last payment.
    pub(super) paid: Option<Paid>,
    /// Why no challenge could be selected.
    pub(super) selection_error: Option<String>,
    /// Challenges of the last `402` the wallet cannot pay (by id).
    pub(super) unaffordable: std::collections::HashSet<String>,
}

/// paymentd's MPP payment provider.
#[derive(Clone)]
pub(crate) struct AgentPayProvider {
    inner: Arc<Inner>,
}

struct Inner {
    payer: Payer,
    settings: Settings,
    state: Mutex<State>,
    error: ErrorSlot,
}

impl AgentPayProvider {
    /// A provider for one call, with the channel persisted under
    /// `settings.session_key` loaded and checked against the agent and origin.
    pub(crate) fn new(payer: Payer, settings: Settings) -> Result<Self, PaymentsError> {
        let persisted = match &settings.session_key {
            Some(key) => SessionStore::new(&payer.state_dir, &payer.sessions)
                .load(payer.agent_key_id(), key)?,
            None => None,
        };
        if let Some(record) = &persisted {
            if record.origin != settings.origin {
                return Err(PaymentsError::InvalidRequest(format!(
                    "session_key '{}' belongs to a channel with another origin; use another \
                     session_key",
                    record.session_key
                )));
            }
            if crate::chains::evm::to_alloy_address(&record.payer)? != payer.wallet {
                return Err(PaymentsError::InvalidRequest(format!(
                    "session_key '{}' belongs to a channel of another wallet",
                    record.session_key
                )));
            }
            session::channel_id(record)?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                payer,
                settings,
                state: Mutex::new(State {
                    persisted,
                    ..State::default()
                }),
                error: ErrorSlot::default(),
            }),
        })
    }

    pub(super) fn payer(&self) -> &Payer {
        &self.inner.payer
    }

    pub(super) fn settings(&self) -> &Settings {
        &self.inner.settings
    }

    /// The provider state; a poisoned lock is still usable (plain data).
    pub(super) fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The first typed error a callback reported.
    pub(super) fn take_error(&self) -> Option<PaymentsError> {
        self.inner.error.take()
    }

    /// The credential source DID for `chain_id`.
    pub(super) fn source(&self, chain_id: u64) -> String {
        PaymentCredential::evm_did(chain_id, &self.inner.payer.wallet.to_string())
    }

    /// Persists `record` when the call has a `session_key`.
    pub(super) fn persist(&self, record: &SessionRecord) -> Result<(), PaymentsError> {
        if self.inner.settings.session_key.is_none() {
            return Ok(());
        }
        SessionStore::new(&self.inner.payer.state_dir, &self.inner.payer.sessions).save(record)
    }

    /// Forgets the persisted channel.
    pub(super) fn forget(&self) -> Result<(), PaymentsError> {
        let Some(key) = &self.inner.settings.session_key else {
            return Ok(());
        };
        SessionStore::new(&self.inner.payer.state_dir, &self.inner.payer.sessions)
            .remove(self.inner.payer.agent_key_id(), key)
    }

    /// The deposit for a new channel.
    fn deposit_for(&self, offer: &Offer) -> Result<u128, PaymentsError> {
        let settings = &self.inner.settings;
        let mut deposit = settings
            .deposit
            .or(offer.suggested_deposit)
            .unwrap_or(offer.amount);
        if let Some(max) = settings.max_deposit {
            if settings.deposit.is_some() && deposit > max {
                return Err(PaymentsError::InvalidRequest(format!(
                    "deposit {deposit} exceeds max_deposit {max}; nothing was signed"
                )));
            }
            deposit = deposit.min(max);
        }
        if deposit < offer.amount {
            return Err(PaymentsError::InvalidRequest(format!(
                "a session deposit of {deposit} does not cover the requested amount {}; nothing \
                 was signed",
                offer.amount
            )));
        }
        Ok(deposit)
    }

    /// The deposit to top a channel up to so it covers `required`: the
    /// default deposit or `required` when larger, capped at `max_deposit`.
    pub(super) fn top_up_target(
        &self,
        required: u128,
        default: u128,
    ) -> Result<u128, PaymentsError> {
        let target = default.max(required);
        let target = match self.inner.settings.max_deposit {
            Some(max) => target.min(max),
            None => target,
        };
        if target < required {
            return Err(PaymentsError::InvalidRequest(format!(
                "the session needs a deposit of {required}, above max_deposit {}",
                self.inner.settings.max_deposit.unwrap_or_default()
            )));
        }
        Ok(target)
    }

    /// Tops `active` up so it covers `required`, POSTing the top-up to
    /// `url` for `challenge`.
    pub(super) async fn ensure_deposit(
        &self,
        client: &reqwest::Client,
        url: &reqwest::Url,
        challenge: &PaymentChallenge,
        active: &mut Active,
        required: u128,
        default_deposit: u128,
    ) -> Result<(), PaymentsError> {
        if required <= active.record.deposit {
            return Ok(());
        }
        let target = self.top_up_target(required, default_deposit)?;
        let additional = target - active.record.deposit;
        let payload =
            session::top_up(self.payer(), &active.record, additional, active.fee_payer).await?;
        let source = self.source(active.record.chain_id);
        management::post(client, url, challenge, &source, &payload, "top-up").await?;
        active.record.deposit = target;
        active.topped_up += additional;
        self.persist(&active.record)?;
        Ok(())
    }

    /// Reads which challenges of a `402` (its `headers`) the wallet cannot
    /// pay, for ranking ([`super::funds`]).
    pub(super) async fn probe_funds(&self, headers: &reqwest::header::HeaderMap) {
        let unaffordable = super::funds::unaffordable(self.payer(), headers).await;
        self.state().unaffordable = unaffordable;
    }

    async fn pay_payable(
        &self,
        challenge: &PaymentChallenge,
        payable: Payable,
        context: &PaymentContext,
    ) -> Result<PaymentCredential, PaymentsError> {
        // One charge per request. A charge credential the merchant answered
        // with another 402 may still be redeemable (an authorization, a
        // permit, a signed transaction), so paying a fresh challenge could
        // pay twice; `mpp` itself stops after a `hash` credential.
        let earlier = self
            .state()
            .paid
            .as_ref()
            .and_then(|paid| paid.charge.as_ref())
            .map(|charged| charged.credential_type);
        if let Some(credential_type) = earlier {
            if payable.intent() == Intent::Charge {
                return Err(PaymentsError::Merchant(format!(
                    "the merchant answered the paid request with another 402, refusing the \
                     {credential_type} credential; AgentPay does not pay a second charge for \
                     one request, so nothing more was signed"
                )));
            }
        }
        let charged = match &payable {
            Payable::Tempo(offer) => {
                return self.pay_offer(challenge, offer.clone(), context).await
            }
            Payable::Evm(charge) => evm_charge::pay(self.payer(), challenge, charge).await?,
            Payable::Solana(charge) => solana_charge::pay(self.payer(), challenge, charge).await?,
        };
        let credential = charged.credential.clone();
        self.state().paid = Some(Paid {
            challenge: challenge.clone(),
            offer: payable,
            charge: Some(charged),
        });
        Ok(credential)
    }

    async fn pay_offer(
        &self,
        challenge: &PaymentChallenge,
        offer: Offer,
        context: &PaymentContext,
    ) -> Result<PaymentCredential, PaymentsError> {
        if offer.intent == Intent::Charge {
            let charged = charge::pay(self.payer(), challenge, &offer).await?;
            let credential = charged.credential.clone();
            self.state().paid = Some(Paid {
                challenge: challenge.clone(),
                offer: Payable::Tempo(offer),
                charge: Some(charged),
            });
            return Ok(credential);
        }
        let (current, persisted) = {
            let state = self.state();
            (state.active.clone(), state.persisted.clone())
        };
        let current = current.or_else(|| {
            persisted.map(|record| Active {
                record,
                opened: false,
                topped_up: 0,
                vouchers: 0,
                fee_payer: offer.fee_payer,
            })
        });
        let (next, payload) = match current {
            Some(mut active) => {
                let required = active.record.cumulative.saturating_add(offer.amount);
                let client = context.http_client.clone().ok_or_else(|| {
                    PaymentsError::Internal("no HTTP client for session management".into())
                })?;
                let default = self
                    .inner
                    .settings
                    .deposit
                    .or(offer.suggested_deposit)
                    .unwrap_or(offer.amount);
                active.fee_payer = offer.fee_payer;
                self.ensure_deposit(
                    &client,
                    &context.url,
                    challenge,
                    &mut active,
                    required,
                    default,
                )
                .await?;
                let payload = session::voucher(self.payer(), &active.record, required).await?;
                active.record.cumulative = required;
                active.vouchers += 1;
                (active, payload)
            }
            None => {
                let deposit = self.deposit_for(&offer)?;
                let key = self.inner.settings.session_key.clone().unwrap_or_default();
                let Opened { record, payload } = session::open(
                    self.payer(),
                    &offer,
                    deposit,
                    &key,
                    &self.inner.settings.origin,
                )
                .await?;
                let active = Active {
                    record,
                    opened: true,
                    topped_up: 0,
                    vouchers: 1,
                    fee_payer: offer.fee_payer,
                };
                (active, payload)
            }
        };
        let source = self.source(offer.chain_id);
        {
            let mut state = self.state();
            state.pending = Some(next);
            state.paid = Some(Paid {
                challenge: challenge.clone(),
                offer: Payable::Tempo(offer),
                charge: None,
            });
        }
        Ok(PaymentCredential::with_source(
            challenge.to_echo(),
            source,
            payload,
        ))
    }

    /// Makes the pending channel state current and persists it.
    fn settle_pending(&self) {
        let pending = self.state().pending.take();
        if let Some(active) = pending {
            if let Err(error) = self.persist(&active.record) {
                tracing::warn!(kind = error.kind(), "failed to persist an MPP session");
                self.inner.error.put(error);
            }
            let mut state = self.state();
            state.persisted = Some(active.record.clone());
            state.active = Some(active);
        }
    }
}

fn mpp_error(error: &PaymentsError) -> MppError {
    MppError::InvalidConfig(error.to_string())
}

impl PaymentProvider for AgentPayProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        match method {
            "tempo" => matches!(intent, "charge" | "session"),
            "evm" | "arbitrum" | "solana" => intent == "charge",
            _ => false,
        }
    }

    fn select_challenge<'a>(
        &self,
        challenges: &[&'a PaymentChallenge],
    ) -> Option<&'a PaymentChallenge> {
        let mut state = self.state();
        let settings = &self.inner.settings;
        let persisted = state
            .active
            .as_ref()
            .map(|active| active.record.clone())
            .or_else(|| state.persisted.clone());
        let config = &self.inner.payer.config;
        let chain_id = match settings.network.as_deref() {
            None => None,
            Some(network) => match config.chains.get(network) {
                Some(chain) => Some(chain.chain_id),
                None => {
                    state.selection_error = Some(format!("network '{network}' is not configured"));
                    return None;
                }
            },
        };
        let currency = settings
            .currency
            .as_deref()
            .map(|currency| currency.trim().to_ascii_lowercase());
        let configured = super::configured_chains(config);
        let unaffordable = state.unaffordable.clone();
        let preferences = Preferences {
            prefer_session: settings.session_key.is_some(),
            currency: currency.as_deref(),
            chain_id,
            configured_chains: &configured,
            persisted: persisted.as_ref(),
            url: &settings.url,
            amount: settings.amount,
            max_amount: settings.max_amount,
            known_tokens: &settings.known_tokens,
            unaffordable: &unaffordable,
        };
        match select::select(challenges, &preferences) {
            Ok((challenge, _)) => Some(challenge),
            Err(reason) => {
                state.selection_error = Some(reason);
                None
            }
        }
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        Err(MppError::InvalidConfig(format!(
            "the {} challenge needs a request context",
            challenge.intent
        )))
    }

    async fn pay_with_context(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> Result<PaymentCredential, MppError> {
        let payable = select::payable(challenge).map_err(MppError::InvalidConfig)?;
        match self.pay_payable(challenge, payable, &context).await {
            Ok(credential) => Ok(credential),
            Err(error) => {
                let mapped = mpp_error(&error);
                self.inner.error.put(error);
                Err(mapped)
            }
        }
    }

    async fn commit_payment(
        &self,
        _challenge: &PaymentChallenge,
        _credential: &PaymentCredential,
    ) -> Result<(), MppError> {
        self.settle_pending();
        Ok(())
    }

    async fn rollback_payment(
        &self,
        _challenge: &PaymentChallenge,
        _credential: &PaymentCredential,
    ) -> Result<(), MppError> {
        // The merchant refused the credential: the channel does not advance
        // (and an open that was refused never happened), and a signed
        // transaction it was handed is not sent, so its nonce is free again.
        let unsent = {
            let mut state = self.state();
            state.pending = None;
            state
                .paid
                .as_mut()
                .and_then(|paid| paid.charge.as_mut())
                .and_then(|charged| charged.unsent.take())
        };
        if let Some((tx, hash)) = unsent {
            self.payer().signer().release_unsent(&tx, Some(&hash)).await;
        }
        Ok(())
    }

    async fn invalidate_payment(
        &self,
        _challenge: &PaymentChallenge,
        _credential: &PaymentCredential,
    ) -> Result<(), MppError> {
        // `410 Gone`: the merchant no longer knows the channel. Forget it so
        // the retried request opens a new one.
        {
            let mut state = self.state();
            state.pending = None;
            state.active = None;
            state.persisted = None;
        }
        self.forget().map_err(|error| mpp_error(&error))
    }

    fn abandon_payment(&self, _challenge: &PaymentChallenge, _credential: &PaymentCredential) {
        // The outcome is unknown (lost response, server error): the merchant
        // may hold the credential, so keep what was signed.
        self.settle_pending();
    }
}
