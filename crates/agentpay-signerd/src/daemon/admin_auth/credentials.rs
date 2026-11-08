//! Admin credential enrollment, listing, and revocation.
//!
//! A credential is a P-256 public key (for example a Secure Enclave key created
//! by the macOS auth helper). Keys are stored in canonical uncompressed SEC1
//! form so the same key cannot be enrolled twice under different encodings.

use agentpay_domain::{AdminAuth, AdminCredential};
use agentpay_signer::VaultSignerBackend;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DaemonError, InMemoryDaemon, RequestContext};

/// Maximum credential label length in characters.
const MAX_LABEL_CHARS: usize = 64;

/// Maximum accepted SEC1 public key hex length (uncompressed P-256 is 130 chars).
const MAX_PUBLIC_KEY_HEX_CHARS: usize = 130;

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Enrolls a new admin credential. Only root-equivalent callers may enroll.
    pub(crate) async fn enroll_admin_credential_impl(
        &self,
        ctx: &RequestContext,
        public_key_sec1_hex: &str,
        label: &str,
    ) -> Result<AdminCredential, DaemonError> {
        if !ctx.is_root_equivalent() {
            return Err(DaemonError::RootPeerRequired);
        }
        let public_key_sec1_hex = canonical_public_key_hex(public_key_sec1_hex)?;
        let label = validate_label(label)?;

        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        let credential = AdminCredential {
            id: Uuid::new_v4(),
            public_key_sec1_hex,
            label,
            created_at: OffsetDateTime::now_utc(),
        };
        {
            let mut credentials = self
                .admin_credentials
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            if credentials
                .values()
                .any(|existing| existing.public_key_sec1_hex == credential.public_key_sec1_hex)
            {
                return Err(DaemonError::InvalidAdminCredential(
                    "public key is already enrolled".to_string(),
                ));
            }
            if credentials.len() >= self.config.max_admin_credentials {
                return Err(DaemonError::TooManyAdminCredentials {
                    max: self.config.max_admin_credentials,
                });
            }
            credentials.insert(credential.id, credential.clone());
        }
        self.persist_or_revert(backup)?;
        Ok(credential)
    }

    /// Lists enrolled admin credentials, oldest first.
    pub(crate) fn list_admin_credentials_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
    ) -> Result<Vec<AdminCredential>, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let mut credentials = self
            .admin_credentials
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        credentials.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.id.cmp(&right.id))
        });
        Ok(credentials)
    }

    /// Revokes a credential together with its leases, pending challenges, and lockout state.
    pub(crate) async fn revoke_admin_credential_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        credential_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        self.admin_credentials
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .remove(&credential_id)
            .ok_or(DaemonError::UnknownAdminCredential(credential_id))?;
        self.persist_or_revert(backup)?;
        // Revocation takes effect immediately, including for the caller's own lease.
        self.lock_admin_auth()?.forget_credential(credential_id);
        Ok(())
    }

    /// Returns the enrolled credential with `credential_id`.
    pub(super) fn admin_credential(
        &self,
        credential_id: Uuid,
    ) -> Result<AdminCredential, DaemonError> {
        self.admin_credentials
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&credential_id)
            .cloned()
            .ok_or(DaemonError::UnknownAdminCredential(credential_id))
    }
}

/// Parses a SEC1 P-256 public key and returns its canonical uncompressed hex form.
pub(super) fn canonical_public_key_hex(value: &str) -> Result<String, DaemonError> {
    let trimmed = value.trim();
    if trimmed.len() > MAX_PUBLIC_KEY_HEX_CHARS {
        return Err(DaemonError::InvalidAdminCredential(
            "public key is too long for a P-256 SEC1 encoding".to_string(),
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|_| {
        DaemonError::InvalidAdminCredential("public key must be hex encoded".to_string())
    })?;
    let public_key = p256::PublicKey::from_sec1_bytes(&bytes).map_err(|_| {
        DaemonError::InvalidAdminCredential("public key is not a valid P-256 point".to_string())
    })?;
    Ok(hex::encode(public_key.to_encoded_point(false).as_bytes()))
}

/// Trims and bounds a credential label; control characters are rejected.
fn validate_label(label: &str) -> Result<String, DaemonError> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return Err(DaemonError::InvalidAdminCredential(format!(
            "label must be 1 to {MAX_LABEL_CHARS} characters"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(DaemonError::InvalidAdminCredential(
            "label must not contain control characters".to_string(),
        ));
    }
    Ok(label.to_string())
}

/// Integrity check for a credential loaded from the state file.
pub(crate) fn validate_persisted_admin_credential(
    credential_id: Uuid,
    credential: &AdminCredential,
) -> Result<(), DaemonError> {
    if credential.id != credential_id {
        return Err(DaemonError::Persistence(format!(
            "loaded state contains admin credential entry keyed by {credential_id} but credential id is {}",
            credential.id
        )));
    }
    let canonical = canonical_public_key_hex(&credential.public_key_sec1_hex).map_err(|err| {
        DaemonError::Persistence(format!("loaded admin credential {credential_id}: {err}"))
    })?;
    if canonical != credential.public_key_sec1_hex {
        return Err(DaemonError::Persistence(format!(
            "loaded admin credential {credential_id} public key is not canonical"
        )));
    }
    validate_label(&credential.label).map_err(|err| {
        DaemonError::Persistence(format!("loaded admin credential {credential_id}: {err}"))
    })?;
    Ok(())
}
