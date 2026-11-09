use thiserror::Error;

/// Errors returned by domain constructors and parsers.
#[derive(Debug, Error)]
pub enum DomainError {
    /// Provided address was malformed.
    #[error(
        "address must start with 0x, contain exactly 40 hex characters, and use a valid EIP-55 checksum when mixed-case"
    )]
    InvalidAddress,
    /// Provided Solana address was malformed.
    #[error("solana address must be a valid base58-encoded 32-byte public key")]
    InvalidSolanaAddress,
    /// Spending amount was zero.
    #[error("amount must be greater than zero")]
    InvalidAmount,
    /// Numeric value could not fit target type.
    #[error("numeric value exceeds supported range")]
    AmountOutOfRange,
    /// Chain ID must be greater than zero.
    #[error("chain_id must be greater than zero")]
    InvalidChainId,
    /// ERC-20 calldata was invalid or unsupported.
    #[error("invalid erc20 calldata: {0}")]
    InvalidErc20Calldata(String),
    /// Transaction data hex was malformed.
    #[error("invalid transaction data hex")]
    InvalidTransactionDataHex,
    /// Gas fields were invalid.
    #[error("invalid gas configuration")]
    InvalidGasConfiguration,
    /// Delegation is not permitted for broadcast transactions.
    #[error("delegation is not allowed for broadcast transactions")]
    DelegationNotAllowed,
    /// ERC-20 approve/transfer calldata must not include native value.
    #[error("erc20 approve/transfer transactions must set value_wei to 0")]
    Erc20CallWithNativeValue,
    /// Broadcast calldata selector is not one the policy engine can scope.
    #[error(
        "unrecognized transaction calldata: only empty calldata or erc20 approve/transfer, permit2 permit, and eip3009 transferWithAuthorization/receiveWithAuthorization calls can be broadcast"
    )]
    UnrecognizedCalldata,
    /// A policy attachment set was empty.
    #[error("policy set cannot be empty")]
    EmptyPolicySet,
    /// An entity scope that requires explicit members was empty.
    #[error("{scope} scope must not be empty")]
    EmptyScope { scope: &'static str },
    /// Transaction type is unsupported for a requested operation.
    #[error("unsupported transaction type for operation: 0x{0:02x}")]
    UnsupportedTransactionType(u8),
    /// Invalid ECDSA recovery parity.
    #[error("invalid signature parity; must be 0 or 1")]
    InvalidSignatureParity,
    /// Authorization time window is malformed.
    #[error("authorization window is invalid")]
    InvalidAuthorizationWindow,
    /// Typed-data domain or nonce field is malformed.
    #[error("invalid typed-data domain: {0}")]
    InvalidTypedDataDomain(String),
    /// Solana recent blockhash was malformed.
    #[error("solana recent blockhash must be a valid base58-encoded 32-byte hash")]
    InvalidSolanaRecentBlockhash,
    /// Solana token decimals were invalid.
    #[error("solana token decimals are invalid")]
    InvalidSolanaTokenDecimals,
    /// Solana token program was unsupported or mismatched.
    #[error("solana token program must be token or token_2022")]
    InvalidSolanaTokenProgram,
    /// Solana compute budget settings were invalid.
    #[error("solana compute budget configuration is invalid")]
    InvalidSolanaComputeBudget,
    /// Solana durable nonce seed was invalid.
    #[error("solana nonce account seed must be non-empty ASCII and at most 32 bytes")]
    InvalidSolanaNonceSeed,
    /// Solana durable nonce account rent exceeded the wallet-maintenance cap.
    #[error("solana nonce account rent must not exceed {max_lamports} lamports")]
    SolanaNonceRentTooHigh { max_lamports: u128 },
    /// Action requested a signer algorithm that does not match the wallet key.
    #[error("signer key algorithm does not support this action")]
    InvalidKeyAlgorithmForAction,
    /// Tempo session action named an unsupported chain.
    #[error("unsupported tempo chain id {0}; expected 4217 (mainnet) or 42431 (testnet)")]
    UnsupportedTempoChain(u64),
    /// Claimed Tempo channel id does not match the id recomputed from the channel fields.
    #[error("tempo channel id does not match the id derived from the channel fields")]
    TempoChannelIdMismatch,
    /// Tempo sessions v2 amount does not fit the TIP-1034 `uint96` amount type.
    #[error("tempo channel reserve amount exceeds uint96")]
    TempoAmountOverflow,
    /// Tempo transaction envelope parameters were malformed.
    #[error("invalid tempo transaction parameters: {0}")]
    InvalidTempoTransactionParams(String),
    /// `over_limit: manual_approval` was set on a policy type without a limit to go beyond.
    #[error(
        "over_limit manual_approval is only valid for PerTxMaxSpending, DailyMaxSpending, WeeklyMaxSpending, and DailyMaxTxCount"
    )]
    OverLimitApprovalUnsupported,
    /// Solana payment transaction legs, memos, or compute budget were invalid.
    #[error("invalid solana payment transaction: {0}")]
    InvalidSolanaPaymentTransaction(&'static str),
    /// A Permit2 permit's entries, nonce, witness, or deadline were invalid.
    #[error("invalid permit2 transfer: {0}")]
    InvalidPermit2Transfer(&'static str),
}
