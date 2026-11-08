//! Permit2 witness permits: digests match the MPP SDKs, validation, policy
//! projection, and the Permit2 approval exemption.

use std::str::FromStr;

use super::*;

const TOKEN: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const SPENDER: &str = "0x1111111111111111111111111111111111111111";
const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";

fn address(text: &str) -> EvmAddress {
    text.parse().expect("address")
}

fn entries(amounts: &[u128]) -> Vec<Permit2Permission> {
    amounts
        .iter()
        .map(|amount_wei| Permit2Permission {
            amount_wei: *amount_wei,
        })
        .collect()
}

fn permit(
    chain_id: u64,
    amounts: &[u128],
    spender: &str,
    nonce: &str,
    witness: Permit2Witness,
) -> Permit2WitnessTransfer {
    Permit2WitnessTransfer {
        chain_id,
        token: address(TOKEN),
        permitted: entries(amounts),
        spender: address(spender),
        nonce: nonce.into(),
        deadline: 1_900_000_000,
        witness,
    }
}

fn bnb_witness(external_id: &str) -> Permit2Witness {
    Permit2Witness::ChallengeExternalId {
        // keccak256(abi.encodePacked("chal-1", "api.example.com")).
        challenge_hash: "0x8c544c6ee4a892b264e76d1c8912e76b7be35ea9bb711bbed90de176d7ab7ec4".into(),
        external_id: external_id.into(),
    }
}

fn hex32(digest: [u8; 32]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(digest))
}

/// Digests computed by `@bnb-chain/mpp` (`permit2Domain`, `permit2SingleTypes`,
/// `permit2BatchTypes`) and `@arbitrum/mpp` (`buildPermit2TypedData`) with
/// viem's `hashTypedData`, for the same inputs.
#[test]
fn signing_hashes_match_the_mpp_sdks() {
    let single = permit(
        84_532,
        &[1_000],
        SPENDER,
        "123456789",
        bnb_witness("order-42"),
    );
    assert_eq!(
        hex32(single.signing_hash().expect("hash")),
        "0x68fa74c99bc7ba96f607caf94628e2f790c7f5a0e0d9f62325772c5b80557ed8"
    );
    let batch = permit(84_532, &[900, 100], SPENDER, "123456789", bnb_witness(""));
    assert_eq!(
        hex32(batch.signing_hash().expect("hash")),
        "0x1592cbd601a142e75b3a63fd5fa52ab626526fe3f6a228ba65e48dd8f92618af"
    );

    // `@arbitrum/mpp`: the spender is the recipient and the nonce is the
    // challenge hash.
    let arbitrum = |amounts: &[u128], hash: &str| {
        let nonce = U256::from_str_radix(&hash[2..], 16)
            .expect("nonce")
            .to_string();
        permit(
            421_614,
            amounts,
            RECIPIENT,
            &nonce,
            Permit2Witness::Challenge {
                challenge_hash: hash.into(),
            },
        )
    };
    let single = arbitrum(
        &[1_000],
        "0xea14c6a8a053be342a76703d6aad2cac544580a208aaeb7d4154619677f6fe97",
    );
    assert_eq!(
        hex32(single.signing_hash().expect("hash")),
        "0xf9d7c4e98457eff5032eb94bb145d5ffd24975ccd9698e256c94d66c45e39eec"
    );
    let batch = arbitrum(
        &[900, 100],
        "0x5ff63be43dd233019197c032b0ef4f0baf146499aa29d21b08f4a78699e1d1ad",
    );
    assert_eq!(
        hex32(batch.signing_hash().expect("hash")),
        "0xa9c721d23aa4ef73067793375d8ee456358db691d4a010a63ac77d6069eaf1af"
    );
}

#[test]
fn the_action_projects_the_total_to_the_spender_and_counts_as_a_spend() {
    let action = AgentAction::Permit2WitnessTransfer {
        permit: permit(84_532, &[900, 100], SPENDER, "7", bnb_witness("")),
    };
    assert_eq!(action.amount_wei(), 1_000);
    assert_eq!(action.chain_id(), 84_532);
    assert_eq!(action.asset(), AssetId::Erc20(address(TOKEN)));
    assert_eq!(
        action.recipients(),
        vec![RecipientId::Evm(address(SPENDER))]
    );
    assert!(action.records_spend_event());
    assert!(!action.is_permit2_approval());
    assert!(action.signing_hash().expect("hash").is_some());
}

#[test]
fn invalid_permits_are_refused() {
    let now = OffsetDateTime::now_utc();
    let soon = future_unix_timestamp(time::Duration::minutes(10));
    let valid = || Permit2WitnessTransfer {
        deadline: soon,
        ..permit(84_532, &[1_000], SPENDER, "1", bnb_witness("x"))
    };
    valid().validate_at(now).expect("valid");

    type Mutation = Box<dyn Fn(&mut Permit2WitnessTransfer)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("no entries", Box::new(|p| p.permitted.clear())),
        ("12 entries", Box::new(|p| p.permitted = entries(&[1; 12]))),
        ("zero amount", Box::new(|p| p.permitted = entries(&[1, 0]))),
        (
            "overflow",
            Box::new(|p| p.permitted = entries(&[u128::MAX, 1])),
        ),
        (
            "zero spender",
            Box::new(|p| p.spender = address("0x0000000000000000000000000000000000000000")),
        ),
        ("hex nonce", Box::new(|p| p.nonce = "0x1".into())),
        ("leading zero nonce", Box::new(|p| p.nonce = "01".into())),
        ("empty nonce", Box::new(|p| p.nonce = String::new())),
        (
            "nonce above uint256",
            Box::new(|p| p.nonce = "9".repeat(80)),
        ),
        (
            "short challenge hash",
            Box::new(|p| {
                p.witness = Permit2Witness::Challenge {
                    challenge_hash: "0x12".into(),
                }
            }),
        ),
        (
            "long external id",
            Box::new(|p| p.witness = bnb_witness(&"x".repeat(257))),
        ),
        ("chain 0", Box::new(|p| p.chain_id = 0)),
        (
            "expired",
            Box::new(move |p| p.deadline = unix_timestamp(now)),
        ),
        (
            "deadline over an hour away",
            Box::new(|p| p.deadline = future_unix_timestamp(time::Duration::minutes(61))),
        ),
    ];
    for (name, mutate) in cases {
        let mut permit = valid();
        mutate(&mut permit);
        assert!(permit.validate_at(now).is_err(), "{name} must be refused");
        let action = AgentAction::Permit2WitnessTransfer { permit };
        assert!(
            action.validate_at(now).is_err(),
            "{name}: the action must be refused"
        );
    }
}

#[test]
fn only_an_approval_of_the_canonical_permit2_has_a_zero_policy_amount() {
    let approve = |spender: &str| AgentAction::Approve {
        chain_id: 1,
        token: address(TOKEN),
        spender: address(spender),
        amount_wei: u128::MAX,
    };
    // Its policy amount is 0; it still records a (zero) spend event, so it
    // counts toward daily transaction counts.
    assert!(approve(PERMIT2_ADDRESS).is_permit2_approval());
    assert_eq!(approve(PERMIT2_ADDRESS).amount_wei(), 0);
    assert!(approve(PERMIT2_ADDRESS).records_spend_event());
    approve(PERMIT2_ADDRESS)
        .validate_at(OffsetDateTime::now_utc())
        .expect("a valid approval");
    assert!(!approve(SPENDER).is_permit2_approval());
    assert_eq!(approve(SPENDER).amount_wei(), u128::MAX);

    let calldata = |spender: &str| {
        let spender = Address::from_str(spender).expect("address");
        format!(
            "0x{}",
            alloy_primitives::hex::encode(
                approveCall {
                    spender,
                    value: U256::from(u128::MAX),
                }
                .abi_encode()
            )
        )
    };
    let broadcast = |data: String, value| AgentAction::BroadcastTx {
        tx: broadcast_tx_with_calldata(data, value),
    };
    assert!(broadcast(calldata(PERMIT2_ADDRESS), 0).is_permit2_approval());
    assert!(
        !broadcast(calldata(PERMIT2_ADDRESS), 1).is_permit2_approval(),
        "with value"
    );
    assert!(!broadcast(calldata(SPENDER), 0).is_permit2_approval());
    // A transfer to Permit2 is a payment, not an approval.
    let transfer = format!(
        "0x{}",
        alloy_primitives::hex::encode(
            transferCall {
                to: Address::from_str(PERMIT2_ADDRESS).expect("address"),
                value: U256::from(5u8),
            }
            .abi_encode()
        )
    );
    assert!(!broadcast(transfer, 0).is_permit2_approval());
    // `increaseAllowance` is not recognized at all, so it is never exempt.
    let increase = format!(
        "0x{}",
        alloy_primitives::hex::encode(
            increaseAllowanceCall {
                spender: Address::from_str(PERMIT2_ADDRESS).expect("address"),
                addedValue: U256::from(5u8),
            }
            .abi_encode()
        )
    );
    assert!(!broadcast(increase, 0).is_permit2_approval());
}

/// The digest rebuilt the way Permit2's `PermitHash` library does (type hash
/// from its stub plus the witness type string), without `sol!` structs.
#[test]
fn signing_hashes_match_permit2s_own_construction() {
    use alloy_primitives::{keccak256, B256};
    let token = Address::from_str(TOKEN).expect("token");
    let spender = Address::from_str(SPENDER).expect("spender");
    let permit2 = Address::from_str(PERMIT2_ADDRESS).expect("permit2");
    let challenge = B256::repeat_byte(0xab);
    let hash = |words: &[[u8; 32]]| keccak256(words.concat());
    let address_word = |address: Address| {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(address.as_slice());
        word
    };
    let uint = |value: u128| U256::from(value).to_be_bytes::<32>();
    let permissions = |amount| {
        hash(&[
            keccak256("TokenPermissions(address token,uint256 amount)").0,
            address_word(token),
            uint(amount),
        ])
    };
    let separator = hash(&[
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)").0,
        keccak256("Permit2").0,
        uint(56),
        address_word(permit2),
    ]);
    let digest = |message: B256| {
        let mut bytes = vec![0x19, 0x01];
        bytes.extend_from_slice(separator.as_slice());
        bytes.extend_from_slice(message.as_slice());
        keccak256(bytes).0
    };
    let witnesses = [
        (
            "PaymentWitness witness)PaymentWitness(bytes32 challengeHash,string externalId)TokenPermissions(address token,uint256 amount)",
            hash(&[keccak256("PaymentWitness(bytes32 challengeHash,string externalId)").0, challenge.0, keccak256("ord-1").0]),
            Permit2Witness::ChallengeExternalId {
                challenge_hash: format!("{challenge:#x}"),
                external_id: "ord-1".into(),
            },
        ),
        (
            "PaymentWitness witness)PaymentWitness(bytes32 challengeHash)TokenPermissions(address token,uint256 amount)",
            hash(&[keccak256("PaymentWitness(bytes32 challengeHash)").0, challenge.0]),
            Permit2Witness::Challenge {
                challenge_hash: format!("{challenge:#x}"),
            },
        ),
    ];
    for (witness_type, witness_hash, witness) in witnesses {
        for amounts in [vec![1_000u128], vec![900, 100]] {
            let message = if amounts.len() == 1 {
                let type_hash = keccak256(format!(
                    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,{witness_type}"
                ));
                hash(&[
                    type_hash.0,
                    permissions(amounts[0]).0,
                    address_word(spender),
                    uint(7),
                    uint(1_900_000_000),
                    witness_hash.0,
                ])
            } else {
                let type_hash = keccak256(format!(
                    "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,{witness_type}"
                ));
                let entries: Vec<[u8; 32]> = amounts
                    .iter()
                    .map(|amount| permissions(*amount).0)
                    .collect();
                hash(&[
                    type_hash.0,
                    hash(&entries).0,
                    address_word(spender),
                    uint(7),
                    uint(1_900_000_000),
                    witness_hash.0,
                ])
            };
            let ours = permit(56, &amounts, SPENDER, "7", witness.clone());
            assert_eq!(
                ours.signing_hash().expect("hash"),
                digest(message),
                "{} entries",
                amounts.len()
            );
        }
    }
}
