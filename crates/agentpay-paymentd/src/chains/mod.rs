//! The chain provider registry.
//!
//! Each chain family (EVM, Solana) gets one provider: a concrete type that
//! owns that family's RPC clients and transaction building, defined in its own
//! module (for example `chains/evm.rs`). A provider implements
//! [`ChainProvider`] and is registered once in [`AppState::new`]; feature
//! handlers fetch it by type with [`ChainRegistry::get`]:
//!
//! ```ignore
//! let evm = state.chains.get::<EvmProvider>()?;
//! ```
//!
//! The trait is deliberately minimal so EVM and Solana work can proceed
//! independently: each provider adds its own inherent methods.
//!
//! [`AppState::new`]: crate::state::AppState::new

pub mod evm;
pub mod failover;
pub mod solana;

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use agentpay_api::payments::ChainFamily;

use crate::error::PaymentsError;

/// A chain family's provider.
pub trait ChainProvider: Any + Send + Sync {
    /// The family this provider serves; at most one provider per family.
    const FAMILY: ChainFamily;
}

/// Registered chain providers, one per [`ChainFamily`].
#[derive(Default)]
pub struct ChainRegistry {
    providers: BTreeMap<FamilyKey, Arc<dyn Any + Send + Sync>>,
}

/// [`ChainFamily`] as an ordered map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FamilyKey {
    Evm,
    Solana,
}

impl From<ChainFamily> for FamilyKey {
    fn from(family: ChainFamily) -> Self {
        match family {
            ChainFamily::Evm => Self::Evm,
            ChainFamily::Solana => Self::Solana,
        }
    }
}

impl ChainRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `provider` for `P::FAMILY`, replacing any earlier one.
    pub fn register<P: ChainProvider>(&mut self, provider: Arc<P>) {
        self.providers.insert(P::FAMILY.into(), provider);
    }

    /// The registered provider of type `P`.
    pub fn get<P: ChainProvider>(&self) -> Result<Arc<P>, PaymentsError> {
        self.providers
            .get(&P::FAMILY.into())
            .cloned()
            .and_then(|provider| provider.downcast::<P>().ok())
            .ok_or_else(|| {
                PaymentsError::Internal(format!("no {:?} chain provider is registered", P::FAMILY))
            })
    }

    /// Whether a provider is registered for `family`.
    #[must_use]
    pub fn supports(&self, family: ChainFamily) -> bool {
        self.providers.contains_key(&family.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeEvm(u64);
    impl ChainProvider for FakeEvm {
        const FAMILY: ChainFamily = ChainFamily::Evm;
    }

    struct OtherEvm;
    impl ChainProvider for OtherEvm {
        const FAMILY: ChainFamily = ChainFamily::Evm;
    }

    #[test]
    fn providers_are_found_by_type_and_family() {
        let mut registry = ChainRegistry::new();
        assert!(!registry.supports(ChainFamily::Evm));
        assert!(registry.get::<FakeEvm>().is_err());

        registry.register(Arc::new(FakeEvm(7)));
        assert!(registry.supports(ChainFamily::Evm));
        assert!(!registry.supports(ChainFamily::Solana));
        assert_eq!(registry.get::<FakeEvm>().expect("registered").0, 7);
        // Another type for the same family is not confused with the registered one.
        assert!(registry.get::<OtherEvm>().is_err());

        registry.register(Arc::new(FakeEvm(8)));
        assert_eq!(registry.get::<FakeEvm>().expect("replaced").0, 8);
    }
}
