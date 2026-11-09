//! A scripted EVM JSON-RPC endpoint on `127.0.0.1` for tests.
//!
//! It speaks just enough HTTP/1.1 (one request per connection) for the real
//! alloy HTTP transport, so tests exercise the production connection path,
//! including the chain-id check. Behaviour comes from [`MockChain`], which
//! tests can change between calls; every method name and every raw
//! transaction received is recorded. It answers JSON-RPC batches (or rejects
//! them) and serves Multicall3 `aggregate3` at the canonical address (or has
//! no code there).

use std::sync::{Arc, Mutex, MutexGuard};

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_eips::Typed2718;
use alloy_primitives::{hex, keccak256, Address, Bytes, B256, U256};
use alloy_provider::bindings::IMulticall3::{
    aggregate3Call, getEthBalanceCall, Result as Call3Result,
};
use alloy_provider::MULTICALL3_ADDRESS;
use alloy_sol_types::{sol, SolCall, SolValue};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

sol! {
    function decimals() returns (uint8);
    function symbol() returns (string);
    function balanceOf(address owner) returns (uint256);
    function allowance(address owner, address spender) returns (uint256);
    function approve(address spender, uint256 value) returns (bool);
    function name() returns (string);
    function version() returns (string);
    function eip712Domain() returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions);
}

/// Block hash used in receipts and transactions.
pub(crate) const MOCK_BLOCK_HASH: B256 = B256::repeat_byte(0x5b);

/// What the mock chain answers.
#[derive(Debug, Clone)]
pub(crate) struct MockChain {
    pub(crate) chain_id: u64,
    pub(crate) block_number: u64,
    pub(crate) nonce: u64,
    pub(crate) balance: U256,
    pub(crate) gas_estimate: u64,
    /// Gas used in receipts.
    pub(crate) gas_used: u64,
    pub(crate) gas_price: u128,
    /// Latest base fee; `0` makes `eth_feeHistory` unusable (a legacy chain).
    pub(crate) base_fee: u128,
    pub(crate) priority_fee: u128,
    pub(crate) token_decimals: u8,
    pub(crate) token_symbol: String,
    pub(crate) token_balance: U256,
    /// The token's `allowance(owner, spender)` for any pair; a sent
    /// `approve` that is mined sets it.
    pub(crate) token_allowance: U256,
    /// The token's `name()` (its EIP-712 domain name).
    pub(crate) token_name: String,
    /// The token's `version()`; `None` makes the call revert.
    pub(crate) token_version: Option<String>,
    /// The version ERC-5267 `eip712Domain()` reports; `None` makes it
    /// revert (no ERC-5267).
    pub(crate) eip5267_version: Option<String>,
    pub(crate) code: Vec<u8>,
    /// Whether Multicall3 is deployed at its canonical address.
    pub(crate) multicall: bool,
    /// Whether batch requests are refused with a single error object.
    pub(crate) reject_batches: bool,
    /// Tokens whose `balanceOf` reverts.
    pub(crate) reverting_tokens: Vec<Address>,
    /// Number of batch requests received (answered or rejected).
    pub(crate) batches: usize,
    /// JSON-RPC error returned by `eth_sendRawTransaction`.
    pub(crate) send_error: Option<String>,
    /// HTTP status (with an empty body) returned for `eth_sendRawTransaction`
    /// after recording the transaction, like a proxy that failed after the
    /// node accepted it.
    pub(crate) send_http_status: Option<u16>,
    /// Whether sent transactions have receipts.
    pub(crate) mined: bool,
    /// Every raw transaction received.
    pub(crate) sent: Vec<Vec<u8>>,
    /// Every method called, in order.
    pub(crate) calls: Vec<String>,
}

impl MockChain {
    fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            block_number: 45_000_123,
            nonce: 7,
            balance: U256::from(2_000_000_000_000_000_000_u128),
            gas_estimate: 34_512,
            gas_used: 34_512,
            gas_price: 1_000_000_000,
            base_fee: 1_000_000_000,
            priority_fee: 100_000_000,
            token_decimals: 6,
            token_symbol: "TKN".into(),
            token_balance: U256::from(25_500_000_u64),
            token_allowance: U256::ZERO,
            token_name: "USD Coin".into(),
            token_version: Some("2".into()),
            eip5267_version: None,
            code: Vec::new(),
            multicall: true,
            reject_batches: false,
            reverting_tokens: Vec::new(),
            batches: 0,
            send_error: None,
            send_http_status: None,
            mined: true,
            sent: Vec::new(),
            calls: Vec::new(),
        }
    }
}

/// A running mock endpoint; stops when dropped.
pub(crate) struct MockRpc {
    url: String,
    chain: Arc<Mutex<MockChain>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockRpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockRpc {
    /// Starts an endpoint for `chain_id`.
    pub(crate) async fn start(chain_id: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let chain = Arc::new(Mutex::new(MockChain::new(chain_id)));
        let shared = chain.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let chain = shared.clone();
                tokio::spawn(async move { serve(stream, chain).await });
            }
        });
        Self { url, chain, task }
    }

    /// The endpoint URL (`http://127.0.0.1:<port>`).
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// The chain state, to inspect or change.
    pub(crate) fn chain(&self) -> MutexGuard<'_, MockChain> {
        self.chain.lock().expect("mock chain lock")
    }

    /// Methods called so far.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.chain().calls.clone()
    }

    /// Raw transactions received so far.
    pub(crate) fn sent(&self) -> Vec<Vec<u8>> {
        self.chain().sent.clone()
    }
}

async fn serve(mut stream: TcpStream, chain: Arc<Mutex<MockChain>>) {
    let Some(body) = read_request(&mut stream).await else {
        return;
    };
    if let Some(status) = http_failure(&body, &chain) {
        let head = format!(
            "HTTP/1.1 {status} Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.shutdown().await;
        return;
    }
    let response = match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Array(batch)) => {
            let reject = {
                let mut state = chain.lock().expect("mock chain lock");
                state.batches += 1;
                state.reject_batches
            };
            if reject {
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "batch requests are not supported"}})
            } else {
                Value::Array(batch.iter().map(|r| answer(r, &chain)).collect())
            }
        }
        Ok(request) => answer(&request, &chain),
        Err(_) => {
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})
        }
    };
    let body = response.to_string();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// The scripted HTTP status for a send, after recording the transaction.
fn http_failure(body: &[u8], chain: &Mutex<MockChain>) -> Option<u16> {
    let request: Value = serde_json::from_slice(body).ok()?;
    if request["method"] != "eth_sendRawTransaction" {
        return None;
    }
    let mut chain = chain.lock().expect("mock chain lock");
    let status = chain.send_http_status?;
    chain.calls.push("eth_sendRawTransaction".to_string());
    if let Ok(raw) = hex_param(&request["params"]) {
        chain.sent.push(raw);
    }
    Some(status)
}

async fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())?;
            let start = end + 4;
            while buffer.len() < start + length {
                let read = stream.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            return Some(buffer[start..start + length].to_vec());
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn answer(request: &Value, chain: &Mutex<MockChain>) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request["method"].as_str().unwrap_or_default().to_string();
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let mut chain = chain.lock().expect("mock chain lock");
    chain.calls.push(method.clone());
    match result(&method, &params, &mut chain) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(message) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": message}})
        }
    }
}

fn quantity(value: impl std::fmt::LowerHex) -> Value {
    Value::String(format!("{value:#x}"))
}

fn result(method: &str, params: &Value, chain: &mut MockChain) -> Result<Value, String> {
    Ok(match method {
        "eth_chainId" => quantity(chain.chain_id),
        "eth_blockNumber" => quantity(chain.block_number),
        "eth_getTransactionCount" => quantity(chain.nonce),
        "eth_getBalance" => quantity(chain.balance),
        "eth_estimateGas" => quantity(chain.gas_estimate),
        "eth_gasPrice" => quantity(chain.gas_price),
        "eth_maxPriorityFeePerGas" => quantity(chain.priority_fee),
        "eth_feeHistory" => {
            if chain.base_fee == 0 {
                return Err("method not supported".into());
            }
            json!({
                "oldestBlock": quantity(chain.block_number - 9),
                "baseFeePerGas": vec![quantity(chain.base_fee); 11],
                "gasUsedRatio": vec![0.5; 10],
                "reward": vec![vec![quantity(chain.priority_fee)]; 10],
            })
        }
        "eth_getBlockByNumber" => return Err("method not supported".into()),
        "eth_getCode" => {
            let at_multicall = address_param(&params[0]) == Some(MULTICALL3_ADDRESS);
            let code = match (at_multicall, chain.multicall) {
                (true, true) => vec![0x60, 0x80],
                (true, false) => Vec::new(),
                (false, _) => chain.code.clone(),
            };
            Value::String(format!("0x{}", hex::encode(code)))
        }
        "eth_call" => eth_call(params, chain)?,
        "eth_sendRawTransaction" => {
            if let Some(error) = &chain.send_error {
                return Err(error.clone());
            }
            let raw = hex_param(params)?;
            let hash = keccak256(&raw);
            if chain.mined {
                let envelope = TxEnvelope::decode_2718_exact(&raw).map_err(|e| e.to_string())?;
                if let Ok(call) = approveCall::abi_decode(envelope.input()) {
                    chain.token_allowance = call.value;
                }
            }
            chain.sent.push(raw);
            Value::String(format!("{hash:#x}"))
        }
        "eth_getTransactionReceipt" => match sent_by_hash(params, chain)? {
            Some(envelope) if chain.mined => receipt_json(&envelope, chain)?,
            _ => Value::Null,
        },
        "eth_getTransactionByHash" => match sent_by_hash(params, chain)? {
            Some(envelope) => transaction_json(envelope, chain)?,
            None => Value::Null,
        },
        other => return Err(format!("unsupported method {other}")),
    })
}

fn eth_call(params: &Value, chain: &MockChain) -> Result<Value, String> {
    let input = params[0]["input"]
        .as_str()
        .or_else(|| params[0]["data"].as_str())
        .ok_or("eth_call without input")?;
    let input = hex::decode(input.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    let to = address_param(&params[0]["to"]).unwrap_or_default();
    let output = if to == MULTICALL3_ADDRESS {
        // No code there: a call succeeds with empty output, like on a real chain.
        if chain.multicall {
            aggregate3(&input, chain)?
        } else {
            Vec::new()
        }
    } else {
        contract_call(to, &input, chain)?
    };
    Ok(Value::String(format!("0x{}", hex::encode(output))))
}

/// The output of a call to the token contract `to`.
fn contract_call(to: Address, input: &[u8], chain: &MockChain) -> Result<Vec<u8>, String> {
    Ok(match input.get(..4) {
        Some(selector) if selector == decimalsCall::SELECTOR => {
            U256::from(chain.token_decimals).abi_encode()
        }
        Some(selector) if selector == symbolCall::SELECTOR => chain.token_symbol.abi_encode(),
        Some(selector) if selector == balanceOfCall::SELECTOR => {
            if chain.reverting_tokens.contains(&to) {
                return Err("execution reverted".into());
            }
            chain.token_balance.abi_encode()
        }
        Some(selector) if selector == allowanceCall::SELECTOR => chain.token_allowance.abi_encode(),
        Some(selector) if selector == nameCall::SELECTOR => chain.token_name.abi_encode(),
        Some(selector) if selector == versionCall::SELECTOR => match &chain.token_version {
            Some(version) => version.abi_encode(),
            None => return Err("execution reverted".into()),
        },
        Some(selector) if selector == eip712DomainCall::SELECTOR => {
            let Some(version) = chain.eip5267_version.clone() else {
                return Err("execution reverted".into());
            };
            eip712DomainCall::abi_encode_returns(&eip712DomainReturn {
                fields: alloy_primitives::FixedBytes([0x0f]),
                name: chain.token_name.clone(),
                version,
                chainId: U256::from(chain.chain_id),
                verifyingContract: to,
                salt: B256::ZERO,
                extensions: Vec::new(),
            })
        }
        _ => return Err("execution reverted".into()),
    })
}

/// Multicall3 `aggregate3`: every sub-call answered like a single call;
/// `getEthBalance` on the contract itself returns `balance`.
fn aggregate3(input: &[u8], chain: &MockChain) -> Result<Vec<u8>, String> {
    let call = aggregate3Call::abi_decode(input).map_err(|e| e.to_string())?;
    let results: Vec<Call3Result> = call
        .calls
        .iter()
        .map(|sub| {
            let output = if sub.target == MULTICALL3_ADDRESS {
                getEthBalanceCall::abi_decode(&sub.callData)
                    .map(|_| chain.balance.abi_encode())
                    .map_err(|e| e.to_string())
            } else {
                contract_call(sub.target, &sub.callData, chain)
            };
            match output {
                Ok(data) => Call3Result {
                    success: true,
                    returnData: Bytes::from(data),
                },
                Err(_) => Call3Result {
                    success: false,
                    returnData: Bytes::new(),
                },
            }
        })
        .collect();
    Ok(aggregate3Call::abi_encode_returns(&results))
}

fn address_param(value: &Value) -> Option<Address> {
    value.as_str()?.parse().ok()
}

fn hex_param(params: &Value) -> Result<Vec<u8>, String> {
    let value = params[0].as_str().ok_or("missing parameter")?;
    hex::decode(value.trim_start_matches("0x")).map_err(|e| e.to_string())
}

fn sent_by_hash(params: &Value, chain: &MockChain) -> Result<Option<TxEnvelope>, String> {
    let hash: B256 = params[0]
        .as_str()
        .ok_or("missing hash")?
        .parse()
        .map_err(|_| "bad hash".to_string())?;
    chain
        .sent
        .iter()
        .find(|raw| keccak256(raw) == hash)
        .map(|raw| TxEnvelope::decode_2718_exact(raw).map_err(|e| e.to_string()))
        .transpose()
}

fn signer(envelope: &TxEnvelope) -> Result<Address, String> {
    envelope.recover_signer().map_err(|e| e.to_string())
}

fn receipt_json(envelope: &TxEnvelope, chain: &MockChain) -> Result<Value, String> {
    Ok(json!({
        "transactionHash": format!("{:#x}", envelope.tx_hash()),
        "transactionIndex": "0x0",
        "blockHash": format!("{MOCK_BLOCK_HASH:#x}"),
        "blockNumber": quantity(chain.block_number),
        "from": format!("{:#x}", signer(envelope)?),
        "to": envelope.to().map(|to| format!("{to:#x}")),
        "cumulativeGasUsed": quantity(chain.gas_used),
        "gasUsed": quantity(chain.gas_used),
        "effectiveGasPrice": quantity(chain.gas_price),
        "contractAddress": null,
        "logs": [],
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "type": quantity(envelope.ty()),
        "status": "0x1",
    }))
}

fn transaction_json(envelope: TxEnvelope, chain: &MockChain) -> Result<Value, String> {
    let from = signer(&envelope)?;
    let transaction = alloy_rpc_types_eth::Transaction {
        inner: alloy_consensus::transaction::Recovered::new_unchecked(envelope, from),
        block_hash: Some(MOCK_BLOCK_HASH),
        block_number: Some(chain.block_number),
        transaction_index: Some(0),
        effective_gas_price: Some(chain.gas_price),
        block_timestamp: None,
    };
    serde_json::to_value(transaction).map_err(|e| e.to_string())
}
