use alloy_chains::NamedChain;
use anyhow::{anyhow, bail, Context, Result};
use hex::FromHex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vault_domain::EvmAddress;

/// Upper bound for each metadata RPC call so an unresponsive endpoint cannot hang the TUI.
const TOKEN_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const TOKEN_RPC_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FetchedTokenMetadata {
    pub(super) chain_id: u64,
    pub(super) name: String,
    pub(super) symbol: String,
    pub(super) decimals: u8,
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

pub(super) async fn fetch_token_metadata(
    chain_key: &str,
    rpc_url: &str,
    expected_chain_id: u64,
    is_native: bool,
    address: Option<&EvmAddress>,
) -> Result<FetchedTokenMetadata> {
    let client = Client::builder()
        .timeout(TOKEN_RPC_TIMEOUT)
        .connect_timeout(TOKEN_RPC_CONNECT_TIMEOUT)
        .build()
        .context("failed to initialize token metadata rpc client")?;
    let chain_id = fetch_chain_id(&client, rpc_url).await?;
    if chain_id != expected_chain_id {
        bail!(
            "rpc url returned chain id {} but the saved network expects {}",
            chain_id,
            expected_chain_id
        );
    }

    if is_native {
        let (name, symbol) = native_metadata_for_chain(chain_id, chain_key);
        return Ok(FetchedTokenMetadata {
            chain_id,
            name,
            symbol,
            decimals: 18,
        });
    }

    let address = address.context("token address is required to fetch metadata")?;
    let decimals = read_erc20_decimals(&client, rpc_url, address).await?;
    let symbol = read_erc20_string(&client, rpc_url, address, "0x95d89b41")
        .await
        .context("failed to read token symbol")?;
    let name = read_erc20_string(&client, rpc_url, address, "0x06fdde03")
        .await
        .context("failed to read token name")?;

    Ok(FetchedTokenMetadata {
        chain_id,
        name,
        symbol,
        decimals,
    })
}

async fn fetch_chain_id(client: &Client, rpc_url: &str) -> Result<u64> {
    let response = call_rpc(client, rpc_url, "eth_chainId", json!([])).await?;
    let result = response
        .as_str()
        .context("eth_chainId returned a non-string result")?;
    parse_hex_u64(result, "eth_chainId")
}

async fn read_erc20_decimals(client: &Client, rpc_url: &str, address: &EvmAddress) -> Result<u8> {
    let result = eth_call(client, rpc_url, address, "0x313ce567").await?;
    let decoded = decode_hex_bytes(&result)?;
    if decoded.len() != 32 {
        bail!("decimals() returned {} bytes; expected 32", decoded.len());
    }
    let decimals = *decoded
        .last()
        .context("decimals() returned an empty payload")?;
    Ok(decimals)
}

async fn read_erc20_string(
    client: &Client,
    rpc_url: &str,
    address: &EvmAddress,
    selector: &str,
) -> Result<String> {
    let result = eth_call(client, rpc_url, address, selector).await?;
    decode_abi_string(&result)
}

async fn eth_call(
    client: &Client,
    rpc_url: &str,
    address: &EvmAddress,
    data: &str,
) -> Result<String> {
    let result = call_rpc(
        client,
        rpc_url,
        "eth_call",
        json!([
            {
                "to": address.to_string(),
                "data": data,
            },
            "latest"
        ]),
    )
    .await?;
    result
        .as_str()
        .map(ToString::to_string)
        .context("eth_call returned a non-string result")
}

async fn call_rpc(client: &Client, rpc_url: &str, method: &str, params: Value) -> Result<Value> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        method,
        params,
        id: 1,
    };
    let response = client
        .post(rpc_url.trim())
        .json(&request)
        .send()
        .await
        .with_context(|| format!("rpc call {method} failed"))?;
    let response = response
        .error_for_status()
        .with_context(|| format!("rpc call {method} failed"))?;
    let payload: RpcResponse = response
        .json()
        .await
        .with_context(|| format!("rpc call {method} returned invalid json"))?;
    if let Some(error) = payload.error {
        bail!(
            "rpc call {method} failed: {} ({})",
            error.message,
            error.code
        );
    }
    payload
        .result
        .ok_or_else(|| anyhow!("rpc call {method} returned no result"))
}

fn native_metadata_for_chain(chain_id: u64, chain_key: &str) -> (String, String) {
    if chain_id == 20143 {
        return ("Monad".to_string(), "MON".to_string());
    }

    if let Ok(chain) = NamedChain::try_from(chain_id) {
        if let Some(symbol) = chain.native_currency_symbol() {
            return (native_currency_name(symbol).to_string(), symbol.to_string());
        }
    }

    (format!("Native Asset ({chain_key})"), "NATIVE".to_string())
}

fn native_currency_name(symbol: &str) -> &str {
    match symbol {
        "ETH" => "Ether",
        "MON" => "Monad",
        _ => symbol,
    }
}

fn parse_hex_u64(value: &str, label: &str) -> Result<u64> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .context(format!("{label} must be a 0x-prefixed hex string"))?;
    u64::from_str_radix(digits, 16).with_context(|| format!("{label} must be valid hex"))
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .context("hex payload must be 0x-prefixed")?;
    Vec::from_hex(digits).context("hex payload must contain valid hex bytes")
}

fn decode_abi_string(value: &str) -> Result<String> {
    let bytes = decode_hex_bytes(value)?;
    if bytes.len() < 64 {
        bail!("abi string payload is too short");
    }

    let offset = decode_abi_usize(&bytes[0..32]).context("invalid abi string offset")?;
    let start = offset
        .checked_add(32)
        .filter(|start| *start <= bytes.len())
        .context("abi string offset points past the payload")?;
    let length = decode_abi_usize(&bytes[offset..start]).context("invalid abi string length")?;
    let end = start
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .context("abi string length points past the payload")?;

    String::from_utf8(bytes[start..end].to_vec()).context("abi string is not valid utf-8")
}

fn decode_abi_usize(bytes: &[u8]) -> Result<usize> {
    if bytes.len() != 32 {
        bail!("abi integer must be 32 bytes");
    }
    if bytes[..24].iter().any(|byte| *byte != 0) {
        bail!("abi integer does not fit into usize");
    }
    let value = u64::from_be_bytes(
        bytes[24..32]
            .try_into()
            .map_err(|_| anyhow!("abi integer tail is malformed"))?,
    );
    usize::try_from(value).context("abi integer does not fit into usize")
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::{
        call_rpc, decode_abi_string, decode_abi_usize, decode_hex_bytes, eth_call,
        fetch_token_metadata, native_metadata_for_chain, parse_hex_u64, read_erc20_decimals,
    };
    use reqwest::Client;
    use serde_json::json;
    use vault_domain::EvmAddress;

    fn start_mock_rpc_server(responses: Vec<String>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = listener.accept().expect("accept");
                stream
                    .set_read_timeout(Some(Duration::from_millis(250)))
                    .expect("timeout");
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(err)
                            if err.kind() == std::io::ErrorKind::WouldBlock
                                || err.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            break;
                        }
                        Err(err) => panic!("failed to read request: {err}"),
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn parse_hex_u64_reads_eth_chain_id_payloads() {
        assert_eq!(parse_hex_u64("0x1", "chain").expect("chain"), 1);
        assert_eq!(parse_hex_u64("0xa4b1", "chain").expect("chain"), 42161);
    }

    #[test]
    fn decode_abi_string_reads_dynamic_strings() {
        let encoded = concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "5553443100000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(decode_abi_string(encoded).expect("string"), "USD1");
    }

    #[test]
    fn helper_parsers_reject_invalid_inputs() {
        assert!(parse_hex_u64("1", "chain").is_err());
        assert!(parse_hex_u64("0xzz", "chain").is_err());
        assert!(decode_hex_bytes("deadbeef").is_err());
        assert!(decode_hex_bytes("0xzz").is_err());
        assert!(decode_abi_usize(&[0u8; 31]).is_err());

        let too_short = "0x1234";
        assert!(decode_abi_string(too_short).is_err());
        let bad_offset = concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000060",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "5553443100000000000000000000000000000000000000000000000000000000"
        );
        assert!(decode_abi_string(bad_offset).is_err());
        let bad_utf8 = concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "ffff000000000000000000000000000000000000000000000000000000000000"
        );
        assert!(decode_abi_string(bad_utf8).is_err());
        let huge_length = concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "000000000000000000000000000000000000000000000000ffffffffffffffff",
            "5553443100000000000000000000000000000000000000000000000000000000"
        );
        let err = decode_abi_string(huge_length).expect_err("overflowing length");
        assert!(err.to_string().contains("points past the payload"));
        let huge_offset = concat!(
            "0x",
            "000000000000000000000000000000000000000000000000ffffffffffffffff",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "5553443100000000000000000000000000000000000000000000000000000000"
        );
        let err = decode_abi_string(huge_offset).expect_err("overflowing offset");
        assert!(err.to_string().contains("points past the payload"));
    }

    #[test]
    fn native_metadata_for_chain_covers_known_and_fallback_symbols() {
        assert_eq!(
            native_metadata_for_chain(1, "eth"),
            ("Ether".to_string(), "ETH".to_string())
        );
        assert_eq!(
            native_metadata_for_chain(56, "bsc"),
            ("BNB".to_string(), "BNB".to_string())
        );
        assert_eq!(
            native_metadata_for_chain(137, "polygon"),
            ("POL".to_string(), "POL".to_string())
        );
        assert_eq!(
            native_metadata_for_chain(143, "monad"),
            ("Monad".to_string(), "MON".to_string())
        );
        assert_eq!(
            native_metadata_for_chain(10143, "monad-testnet"),
            ("Monad".to_string(), "MON".to_string())
        );
        assert_eq!(
            native_metadata_for_chain(20143, "monad-devnet"),
            ("Monad".to_string(), "MON".to_string())
        );
        assert_eq!(
            native_metadata_for_chain(9_999_999_999, "custom"),
            ("Native Asset (custom)".to_string(), "NATIVE".to_string())
        );
    }

    #[tokio::test]
    async fn rpc_helpers_cover_success_and_error_responses() {
        let (rpc_url, handle) = start_mock_rpc_server(vec![
            json!({"jsonrpc":"2.0","id":1,"result":"0x1"}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"result":42}).to_string(),
        ]);

        let client = Client::new();
        let value = call_rpc(&client, &rpc_url, "eth_chainId", json!([]))
            .await
            .expect("chain id");
        assert_eq!(value, json!("0x1"));

        let err = call_rpc(&client, &rpc_url, "eth_call", json!([]))
            .await
            .expect_err("rpc error");
        assert!(err.to_string().contains("boom"));

        let address: EvmAddress = "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("address");
        let err = eth_call(&client, &rpc_url, &address, "0x313ce567")
            .await
            .expect_err("non-string eth_call");
        assert!(err.to_string().contains("non-string"));

        handle.join().expect("server join");
    }

    #[tokio::test]
    async fn fetch_token_metadata_covers_native_erc20_and_validation_failures() {
        let symbol_payload = concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "5553443100000000000000000000000000000000000000000000000000000000"
        );
        let name_payload = concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "5553443100000000000000000000000000000000000000000000000000000000"
        );
        let decimals_payload = format!("0x{}", "00".repeat(31) + "06");
        let address: EvmAddress = "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("address");

        let (rpc_url, handle) = start_mock_rpc_server(vec![
            json!({"jsonrpc":"2.0","id":1,"result":"0x1"}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"result":"0x1"}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"result":decimals_payload}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"result":symbol_payload}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"result":name_payload}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"result":"0x2"}).to_string(),
            json!({"jsonrpc":"2.0","id":1,"result":"0x1"}).to_string(),
        ]);

        let native = fetch_token_metadata("eth", &rpc_url, 1, true, None)
            .await
            .expect("native metadata");
        assert_eq!(native.symbol, "ETH");
        assert_eq!(native.decimals, 18);

        let erc20 = fetch_token_metadata("eth", &rpc_url, 1, false, Some(&address))
            .await
            .expect("erc20 metadata");
        assert_eq!(erc20.symbol, "USD1");
        assert_eq!(erc20.name, "USD1");
        assert_eq!(erc20.decimals, 6);

        let err = fetch_token_metadata("eth", &rpc_url, 1, true, None)
            .await
            .expect_err("chain mismatch");
        assert!(err.to_string().contains("expects 1"));

        let err = fetch_token_metadata("eth", &rpc_url, 1, false, None)
            .await
            .expect_err("missing address");
        assert!(err.to_string().contains("token address is required"));

        handle.join().expect("server join");
    }

    #[tokio::test]
    async fn read_erc20_decimals_rejects_wrong_length_payloads() {
        let (rpc_url, handle) = start_mock_rpc_server(vec![
            json!({"jsonrpc":"2.0","id":1,"result":"0x0102"}).to_string(),
        ]);
        let client = Client::new();
        let address: EvmAddress = "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("address");

        let err = read_erc20_decimals(&client, &rpc_url, &address)
            .await
            .expect_err("bad decimals payload");
        assert!(err.to_string().contains("expected 32"));

        handle.join().expect("server join");
    }
}
