//! [`MerchantExchange`]: `mpp`'s [`Exchange`] over paymentd's merchant HTTP
//! client.
//!
//! `mpp`'s stock exchange for a caller-owned `reqwest::Client` refuses
//! challenges that ask for the credential in `Payment-Authorization`,
//! because such a client may follow a redirect and forward that header to
//! another host. paymentd's merchant client follows no redirects, so this
//! exchange honors the challenge's `header` parameter: `Authorization` or
//! `Payment-Authorization` (`mpp` never selects any other header).

use mpp::client::{Exchange, HttpError};
use mpp::protocol::core::PaymentChallenge;
use reqwest::{Request, Response};

use super::provider::AgentPayProvider;
use crate::error::PaymentsError;
use crate::features::http;

/// Sends `mpp`'s requests through the redirect-free merchant client. On a
/// `402` it has the provider read which challenges the wallet can pay,
/// before `mpp` asks the provider to choose one.
pub(super) struct MerchantExchange {
    client: reqwest::Client,
    provider: AgentPayProvider,
}

impl MerchantExchange {
    pub(super) fn new(client: reqwest::Client, provider: AgentPayProvider) -> Self {
        Self { client, provider }
    }
}

impl Exchange for MerchantExchange {
    type Error = PaymentsError;

    fn check_challenge(&self, challenge: &PaymentChallenge) -> Result<(), HttpError> {
        match challenge.credential_header() {
            "Authorization" => Ok(()),
            header if header.eq_ignore_ascii_case("payment-authorization") => Ok(()),
            _ => Err(HttpError::UnsafeCredentialHeader),
        }
    }

    fn allows_prepaid(&self) -> bool {
        false
    }

    fn http_client(&self) -> Option<reqwest::Client> {
        Some(self.client.clone())
    }

    async fn send(&mut self, request: Request) -> Result<Response, PaymentsError> {
        let response = http::send(&self.client, request).await?;
        if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            self.provider.probe_funds(response.headers()).await;
        }
        Ok(response)
    }
}
