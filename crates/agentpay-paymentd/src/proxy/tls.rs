//! The proxy's certificate authority, after `mpp`'s forward proxy: a CA
//! generated for each proxy run and held only in memory, which signs a leaf
//! certificate per intercepted host. Clients trust it through the PEM that
//! `ProxyStart` returns.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{crypto::CryptoProvider, ServerConfig};

use crate::error::PaymentsError;

/// Most hosts whose server configurations are cached.
const MAX_CACHED_HOSTS: usize = 256;

/// A per-run certificate authority.
pub(crate) struct Authority {
    issuer: Issuer<'static, KeyPair>,
    leaf_key: KeyPair,
    crypto: Arc<CryptoProvider>,
    configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Authority {
    /// A fresh authority and its PEM certificate.
    pub(super) fn generate() -> Result<(Self, String), PaymentsError> {
        let failed = |what: &str| PaymentsError::Internal(format!("failed to {what}"));
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "AgentPay paying proxy CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().map_err(|_| failed("generate the proxy CA key"))?;
        let root = params
            .self_signed(&ca_key)
            .map_err(|_| failed("sign the proxy CA"))?;
        let pem = root.pem();
        Ok((
            Self {
                issuer: Issuer::new(params, ca_key),
                leaf_key: KeyPair::generate().map_err(|_| failed("generate the proxy key"))?,
                crypto: Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()),
                configs: Mutex::default(),
            },
            pem,
        ))
    }

    /// The TLS server configuration presenting a certificate for `host`.
    pub(super) fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, PaymentsError> {
        let failed = |what: &str| PaymentsError::Internal(format!("failed to {what}"));
        let mut configs = self.configs.lock().map_err(|_| {
            PaymentsError::Internal("the proxy certificate cache is poisoned".into())
        })?;
        if let Some(config) = configs.get(host) {
            return Ok(config.clone());
        }
        let mut params = CertificateParams::new(vec![host.to_owned()])
            .map_err(|_| PaymentsError::InvalidRequest("invalid intercepted host".into()))?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let certificate = params
            .signed_by(&self.leaf_key, &self.issuer)
            .map_err(|_| failed("sign a proxy certificate"))?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(self.crypto.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| failed("configure TLS"))?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], key)
            .map_err(|_| failed("load a proxy certificate"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if configs.len() >= MAX_CACHED_HOSTS {
            configs.clear();
        }
        configs.insert(host.to_owned(), config.clone());
        Ok(config)
    }
}
