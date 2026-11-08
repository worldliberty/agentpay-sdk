//! Solana transaction construction and signing (SOL and SPL transfers, durable
//! nonce accounts). Payment transactions (v0, splits, foreign fee payer) are in
//! `solana_payment`.

use agentpay_domain::{Signature, VaultKey};
use agentpay_signer::{SignerError, VaultSignerBackend};

use super::signing::map_domain_to_signer_error;
use crate::{DaemonError, InMemoryDaemon};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(super) async fn sign_solana_spl_transfer(
        &self,
        vault_key: &VaultKey,
        transfer: &agentpay_domain::SolanaSplTransfer,
    ) -> Result<Signature, DaemonError> {
        let fee_payer = decode_solana_pubkey(&transfer.fee_payer)?;
        let mint = decode_solana_pubkey(&transfer.mint)?;
        let recipient_owner = decode_solana_pubkey(&transfer.recipient_owner)?;
        let signer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(decode_public_key_hex_32(
            &self
                .signer_backend
                .solana_public_key_hex(vault_key.id)
                .map_err(DaemonError::Signer)?,
        )?);
        if fee_payer != signer_pubkey {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana fee payer must match the vault-derived Solana wallet key".to_string(),
            )));
        }

        let recent_blockhash = transfer
            .recent_blockhash
            .parse::<solana_sdk::hash::Hash>()
            .map_err(|_| {
                map_domain_to_signer_error(
                    agentpay_domain::DomainError::InvalidSolanaRecentBlockhash,
                )
            })?;
        let amount = u64::try_from(transfer.amount_wei).map_err(|_| {
            map_domain_to_signer_error(agentpay_domain::DomainError::AmountOutOfRange)
        })?;
        let transfer_fee = transfer
            .transfer_fee_wei
            .map(u64::try_from)
            .transpose()
            .map_err(|_| {
                map_domain_to_signer_error(agentpay_domain::DomainError::AmountOutOfRange)
            })?;
        let token_program_id = solana_token_program_id(transfer.token_program);

        let source_ata = spl_associated_token_account::get_associated_token_address_with_program_id(
            &fee_payer,
            &mint,
            &token_program_id,
        );
        let destination_ata =
            spl_associated_token_account::get_associated_token_address_with_program_id(
                &recipient_owner,
                &mint,
                &token_program_id,
            );

        let mut instructions = Vec::with_capacity(4);
        if let Some(nonce_account) = &transfer.durable_nonce_account {
            let nonce_account = decode_solana_pubkey(nonce_account)?;
            instructions.push(solana_advance_nonce_account_instruction(
                &nonce_account,
                &fee_payer,
            ));
        }
        if let Some(limit) = transfer.compute_unit_limit {
            instructions.push(set_solana_compute_unit_limit_instruction(limit));
        }
        if let Some(price) = transfer.compute_unit_price_micro_lamports {
            instructions.push(set_solana_compute_unit_price_instruction(price));
        }
        instructions.push(build_solana_token_transfer_instruction(
            token_program_id,
            &source_ata,
            &mint,
            &destination_ata,
            &fee_payer,
            amount,
            transfer.decimals,
            transfer_fee,
        )?);

        self.sign_solana_instructions(vault_key, fee_payer, recent_blockhash, instructions)
            .await
    }

    pub(super) async fn sign_solana_sol_transfer(
        &self,
        vault_key: &VaultKey,
        transfer: &agentpay_domain::SolanaSolTransfer,
    ) -> Result<Signature, DaemonError> {
        let fee_payer = decode_solana_pubkey(&transfer.fee_payer)?;
        let to = decode_solana_pubkey(&transfer.to)?;
        let signer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(decode_public_key_hex_32(
            &self
                .signer_backend
                .solana_public_key_hex(vault_key.id)
                .map_err(DaemonError::Signer)?,
        )?);
        if fee_payer != signer_pubkey {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana fee payer must match the vault-derived Solana wallet key".to_string(),
            )));
        }

        let recent_blockhash = transfer
            .recent_blockhash
            .parse::<solana_sdk::hash::Hash>()
            .map_err(|_| {
                map_domain_to_signer_error(
                    agentpay_domain::DomainError::InvalidSolanaRecentBlockhash,
                )
            })?;
        let lamports = u64::try_from(transfer.amount_wei).map_err(|_| {
            map_domain_to_signer_error(agentpay_domain::DomainError::AmountOutOfRange)
        })?;

        let mut instructions = Vec::with_capacity(4);
        if let Some(nonce_account) = &transfer.durable_nonce_account {
            let nonce_account = decode_solana_pubkey(nonce_account)?;
            instructions.push(solana_advance_nonce_account_instruction(
                &nonce_account,
                &fee_payer,
            ));
        }
        if let Some(limit) = transfer.compute_unit_limit {
            instructions.push(set_solana_compute_unit_limit_instruction(limit));
        }
        if let Some(price) = transfer.compute_unit_price_micro_lamports {
            instructions.push(set_solana_compute_unit_price_instruction(price));
        }
        instructions.push(solana_system_transfer_instruction(
            &fee_payer, &to, lamports,
        ));

        self.sign_solana_instructions(vault_key, fee_payer, recent_blockhash, instructions)
            .await
    }

    pub(super) async fn sign_solana_nonce_account_create(
        &self,
        vault_key: &VaultKey,
        create: &agentpay_domain::SolanaNonceAccountCreate,
    ) -> Result<Signature, DaemonError> {
        let fee_payer = decode_solana_pubkey(&create.fee_payer)?;
        let nonce_account = decode_solana_pubkey(&create.nonce_account)?;
        let signer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(decode_public_key_hex_32(
            &self
                .signer_backend
                .solana_public_key_hex(vault_key.id)
                .map_err(DaemonError::Signer)?,
        )?);
        if fee_payer != signer_pubkey {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana fee payer must match the vault-derived Solana wallet key".to_string(),
            )));
        }

        let derived_nonce_account = solana_sdk::pubkey::Pubkey::create_with_seed(
            &fee_payer,
            &create.seed,
            &solana_system_program_id(),
        )
        .map_err(|err| {
            DaemonError::Signer(SignerError::Unsupported(format!(
                "invalid solana nonce account seed: {err}"
            )))
        })?;
        if nonce_account != derived_nonce_account {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana nonce account must be derived from the fee payer and seed".to_string(),
            )));
        }

        let recent_blockhash = create
            .recent_blockhash
            .parse::<solana_sdk::hash::Hash>()
            .map_err(|_| {
                map_domain_to_signer_error(
                    agentpay_domain::DomainError::InvalidSolanaRecentBlockhash,
                )
            })?;
        let rent_lamports = u64::try_from(create.rent_lamports).map_err(|_| {
            map_domain_to_signer_error(agentpay_domain::DomainError::AmountOutOfRange)
        })?;
        let instructions = solana_create_nonce_account_with_seed_instructions(
            &fee_payer,
            &nonce_account,
            &create.seed,
            rent_lamports,
        );

        self.sign_solana_instructions(vault_key, fee_payer, recent_blockhash, instructions)
            .await
    }

    async fn sign_solana_instructions(
        &self,
        vault_key: &VaultKey,
        fee_payer: solana_sdk::pubkey::Pubkey,
        recent_blockhash: solana_sdk::hash::Hash,
        instructions: Vec<solana_sdk::instruction::Instruction>,
    ) -> Result<Signature, DaemonError> {
        let message = solana_sdk::message::Message::new_with_blockhash(
            &instructions,
            Some(&fee_payer),
            &recent_blockhash,
        );
        let signed = self
            .signer_backend
            .sign_solana_payload(vault_key.id, &message.serialize())
            .await?;
        let signature_bytes = <[u8; 64]>::try_from(signed.bytes.as_slice()).map_err(|_| {
            DaemonError::Signer(SignerError::Internal(
                "ed25519 backend returned invalid signature length".to_string(),
            ))
        })?;
        let tx_signature = solana_sdk::signature::Signature::from(signature_bytes);
        let transaction = solana_sdk::transaction::Transaction {
            signatures: vec![tx_signature],
            message,
        };
        let raw_tx = bincode::serialize(&transaction).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "failed to serialize signed solana transaction: {err}"
            )))
        })?;
        let tx_id = tx_signature.to_string();

        Ok(Signature {
            bytes: signature_bytes.to_vec(),
            signature_base58: Some(tx_id.clone()),
            r_hex: None,
            s_hex: None,
            v: None,
            raw_tx_hex: None,
            tx_hash_hex: None,
            raw_tx_base64: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                raw_tx,
            )),
            tx_id: Some(tx_id),
        })
    }
}

pub(super) fn decode_public_key_hex_32(public_key_hex: &str) -> Result<[u8; 32], DaemonError> {
    let bytes = hex::decode(public_key_hex.trim().trim_start_matches("0x")).map_err(|_| {
        DaemonError::Signer(SignerError::Internal(
            "Solana public key is not valid hex".to_string(),
        ))
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        DaemonError::Signer(SignerError::Internal(
            "Solana public key is not a 32-byte ed25519 key".to_string(),
        ))
    })
}

pub(super) fn decode_solana_pubkey(
    address: &agentpay_domain::SolanaAddress,
) -> Result<solana_sdk::pubkey::Pubkey, DaemonError> {
    address
        .to_bytes()
        .map(solana_sdk::pubkey::Pubkey::new_from_array)
        .map_err(map_domain_to_signer_error)
}

pub(super) fn solana_token_program_id(
    token_program: agentpay_domain::SolanaTokenProgram,
) -> solana_sdk::pubkey::Pubkey {
    match token_program {
        agentpay_domain::SolanaTokenProgram::Token => spl_token::ID,
        agentpay_domain::SolanaTokenProgram::Token2022 => spl_token_2022_interface::id(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_solana_token_transfer_instruction(
    token_program_id: solana_sdk::pubkey::Pubkey,
    source_ata: &solana_sdk::pubkey::Pubkey,
    mint: &solana_sdk::pubkey::Pubkey,
    destination_ata: &solana_sdk::pubkey::Pubkey,
    fee_payer: &solana_sdk::pubkey::Pubkey,
    amount: u64,
    decimals: u8,
    transfer_fee: Option<u64>,
) -> Result<solana_sdk::instruction::Instruction, DaemonError> {
    if let Some(fee) = transfer_fee {
        return spl_token_2022_interface::extension::transfer_fee::instruction::transfer_checked_with_fee(
            &token_program_id,
            source_ata,
            mint,
            destination_ata,
            fee_payer,
            &[],
            amount,
            decimals,
            fee,
        )
        .map_err(|err| {
            DaemonError::Signer(SignerError::Unsupported(format!(
                "failed to build Token-2022 transfer-with-fee instruction: {err}"
            )))
        });
    }

    spl_token_2022_interface::instruction::transfer_checked(
        &token_program_id,
        source_ata,
        mint,
        destination_ata,
        fee_payer,
        &[],
        amount,
        decimals,
    )
    .map_err(|err| {
        DaemonError::Signer(SignerError::Unsupported(format!(
            "failed to build spl transfer instruction: {err}"
        )))
    })
}

pub(super) fn solana_system_transfer_instruction(
    from: &solana_sdk::pubkey::Pubkey,
    to: &solana_sdk::pubkey::Pubkey,
    lamports: u64,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: "11111111111111111111111111111111"
            .parse()
            .expect("static system program id"),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*from, true),
            solana_sdk::instruction::AccountMeta::new(*to, false),
        ],
        data,
    }
}

pub(super) fn solana_system_program_id() -> solana_sdk::pubkey::Pubkey {
    "11111111111111111111111111111111"
        .parse()
        .expect("static system program id")
}

fn solana_recent_blockhashes_sysvar_id() -> solana_sdk::pubkey::Pubkey {
    "SysvarRecentB1ockHashes11111111111111111111"
        .parse()
        .expect("static recent blockhashes sysvar id")
}

fn solana_rent_sysvar_id() -> solana_sdk::pubkey::Pubkey {
    "SysvarRent111111111111111111111111111111111"
        .parse()
        .expect("static rent sysvar id")
}

fn solana_create_account_with_seed_instruction(
    from: &solana_sdk::pubkey::Pubkey,
    new_account: &solana_sdk::pubkey::Pubkey,
    seed: &str,
    lamports: u64,
    space: u64,
    owner: &solana_sdk::pubkey::Pubkey,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(4 + 32 + 8 + seed.len() + 8 + 8 + 32);
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(from.as_ref());
    data.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    data.extend_from_slice(seed.as_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    solana_sdk::instruction::Instruction {
        program_id: solana_system_program_id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*from, true),
            solana_sdk::instruction::AccountMeta::new(*new_account, false),
        ],
        data,
    }
}

fn solana_initialize_nonce_account_instruction(
    nonce_account: &solana_sdk::pubkey::Pubkey,
    nonce_authority: &solana_sdk::pubkey::Pubkey,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&6u32.to_le_bytes());
    data.extend_from_slice(nonce_authority.as_ref());
    solana_sdk::instruction::Instruction {
        program_id: solana_system_program_id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*nonce_account, false),
            solana_sdk::instruction::AccountMeta::new_readonly(
                solana_recent_blockhashes_sysvar_id(),
                false,
            ),
            solana_sdk::instruction::AccountMeta::new_readonly(solana_rent_sysvar_id(), false),
        ],
        data,
    }
}

fn solana_create_nonce_account_with_seed_instructions(
    fee_payer: &solana_sdk::pubkey::Pubkey,
    nonce_account: &solana_sdk::pubkey::Pubkey,
    seed: &str,
    rent_lamports: u64,
) -> Vec<solana_sdk::instruction::Instruction> {
    vec![
        solana_create_account_with_seed_instruction(
            fee_payer,
            nonce_account,
            seed,
            rent_lamports,
            80,
            &solana_system_program_id(),
        ),
        solana_initialize_nonce_account_instruction(nonce_account, fee_payer),
    ]
}

fn solana_advance_nonce_account_instruction(
    nonce_account: &solana_sdk::pubkey::Pubkey,
    nonce_authority: &solana_sdk::pubkey::Pubkey,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&4u32.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: solana_system_program_id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*nonce_account, false),
            solana_sdk::instruction::AccountMeta::new_readonly(
                solana_recent_blockhashes_sysvar_id(),
                false,
            ),
            solana_sdk::instruction::AccountMeta::new_readonly(*nonce_authority, true),
        ],
        data,
    }
}

pub(super) fn set_solana_compute_unit_limit_instruction(
    limit: u32,
) -> solana_sdk::instruction::Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&limit.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: "ComputeBudget111111111111111111111111111111"
            .parse()
            .expect("static compute budget program id"),
        accounts: vec![],
        data,
    }
}

pub(super) fn set_solana_compute_unit_price_instruction(
    price: u64,
) -> solana_sdk::instruction::Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&price.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: "ComputeBudget111111111111111111111111111111"
            .parse()
            .expect("static compute budget program id"),
        accounts: vec![],
        data,
    }
}
