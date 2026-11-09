//! `TelemetryStatus` and `SetTelemetry`. The rules live in
//! [`crate::telemetry`]; the consent is per machine, so any authenticated
//! caller may read or change it.

use agentpay_api::payments::{
    PaymentsRpcRequest, PaymentsRpcResponse, SetTelemetryParams, TelemetryStatusParams,
};

use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::state::AppState;

/// Handles the telemetry methods.
pub async fn handle(
    state: &AppState,
    _agent: &AuthenticatedAgent,
    request: PaymentsRpcRequest,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    match request {
        PaymentsRpcRequest::TelemetryStatus(TelemetryStatusParams { .. }) => Ok(
            PaymentsRpcResponse::TelemetryStatus(state.telemetry.status()),
        ),
        PaymentsRpcRequest::SetTelemetry(SetTelemetryParams { enabled, .. }) => state
            .telemetry
            .set_enabled(enabled)
            .map(PaymentsRpcResponse::TelemetryStatus),
        other => Err(PaymentsError::Internal(format!(
            "the telemetry feature cannot handle {}",
            other.method_name()
        ))),
    }
}
