//! `sample-llm`: an example third-party tool built on AgentPay.
//!
//! - `sample-llm run <prompt>` streams a chat completion from
//!   `openai.mpp.tempo.xyz`, paid per request with an MPP session through
//!   AgentPay's paying proxy, and shows what it was charged.
//! - `sample-llm wallet` shows the agent wallet on Tempo: where to send funds
//!   and what it holds.
//!
//! The tool never handles keys or the agent token: it asks the `agentpay` CLI
//! for a paying proxy (see `agentpay.rs`) and sends ordinary HTTPS requests
//! through it. The agent's spending limits and approvals apply to every
//! payment the proxy makes.

mod agentpay;
mod merchant;
mod money;
mod stream;

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use agentpay_api::payments::{ProxyStartResult, WalletBalanceEntry};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use money::{format_units, ChannelLog};
use stream::{delta_text, EventParser, Receipt};

#[derive(Parser)]
#[command(
    name = "sample-llm",
    version,
    about = "Stream LLM answers paid per request with AgentPay (an example third-party tool)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ask a question and stream the answer; prints what it cost.
    Run {
        /// The question.
        prompt: String,
        /// The model.
        #[arg(long, default_value = "gpt-4o-mini")]
        model: String,
        /// Pay in this token (symbol, for example PATH/USD); default: the
        /// accepted token the wallet holds most of.
        #[arg(long)]
        token: Option<String>,
        /// Deposit of a new payment channel (whole units). It counts against
        /// your AgentPay limits; later requests are paid from it.
        #[arg(long, default_value = "0.10")]
        deposit: String,
        /// Most this tool may lock in one channel, top-ups included (whole units).
        #[arg(long, default_value = "1")]
        max_spend: String,
    },
    /// Show the agent wallet on Tempo: address to fund and balances.
    Wallet {
        /// The model whose price and accepted tokens to check.
        #[arg(long, default_value = "gpt-4o-mini")]
        model: String,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Wallet { model, json } => wallet(&model, json).await,
        Command::Run {
            prompt,
            model,
            token,
            deposit,
            max_spend,
        } => run(&prompt, &model, token.as_deref(), &deposit, &max_spend).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn tempo_balances(balances: &[WalletBalanceEntry]) -> Vec<&WalletBalanceEntry> {
    balances
        .iter()
        .filter(|entry| entry.chain_id == merchant::TEMPO_CHAIN_ID)
        .collect()
}

async fn wallet(model: &str, json: bool) -> Result<()> {
    let summary = agentpay::wallet()?;
    let address = summary
        .evm_address
        .as_ref()
        .map(ToString::to_string)
        .context("this wallet has no EVM address, so it cannot be paid on Tempo")?;
    let tempo = tempo_balances(&summary.balances);
    let accepted = merchant::accepted_tokens(&reqwest::Client::new(), model)
        .await
        .unwrap_or_default();
    let usable: Vec<&str> = tempo
        .iter()
        .filter(|entry| {
            entry
                .token
                .as_ref()
                .is_some_and(|token| accepted.contains(&token.to_ascii_lowercase()))
        })
        .map(|entry| entry.symbol.as_str())
        .collect();
    if json {
        let balances: Vec<_> = tempo
            .iter()
            .map(|entry| json!({"symbol": entry.symbol, "token": entry.token, "balance": entry.balance}))
            .collect();
        let out = json!({
            "agent_key_id": summary.agent_key_id,
            "network": "tempo",
            "chain_id": merchant::TEMPO_CHAIN_ID,
            "receive_address": address,
            "balances": balances,
            "merchant": merchant::HOST,
            "merchant_accepts": accepted,
            "pays_with": usable,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    let balances: Vec<String> = tempo
        .iter()
        .map(|entry| {
            format!(
                "{} {}",
                entry.balance.as_deref().unwrap_or("unavailable"),
                entry.symbol
            )
        })
        .collect();
    let short = format!("{}…{}", &address[..6], &address[address.len() - 4..]);
    println!("Wallet      {short} · agent key {}", summary.agent_key_id);
    println!("Network     Tempo (chain {})", merchant::TEMPO_CHAIN_ID);
    println!("Receive at  {address}");
    println!("Balances    {}", balances.join(" · "));
    if accepted.is_empty() {
        println!("Pays with   (could not reach {})", merchant::HOST);
    } else if usable.is_empty() {
        println!(
            "Pays with   nothing: {} {} accepts {}, none of them set up in AgentPay",
            merchant::HOST,
            merchant::CHAT,
            accepted.join(", ")
        );
    } else {
        println!("Pays with   {} on {}", usable.join(", "), merchant::HOST);
    }
    Ok(())
}

async fn run(
    prompt: &str,
    model: &str,
    symbol: Option<&str>,
    deposit: &str,
    max_spend: &str,
) -> Result<()> {
    let summary = agentpay::wallet()?;
    let accepted = merchant::accepted_tokens(&reqwest::Client::new(), model).await?;
    let tempo: Vec<WalletBalanceEntry> = tempo_balances(&summary.balances)
        .into_iter()
        .cloned()
        .collect();
    let Some(token) = money::choose_token(&tempo, &accepted, symbol) else {
        let address = summary
            .evm_address
            .map(|address| address.to_string())
            .unwrap_or_default();
        let known: Vec<&str> = tempo
            .iter()
            .filter(|entry| {
                entry
                    .token
                    .as_ref()
                    .is_some_and(|token| accepted.contains(&token.to_ascii_lowercase()))
            })
            .map(|entry| entry.symbol.as_str())
            .collect();
        let send = if known.is_empty() {
            "a token it accepts (none is set up in AgentPay yet)".to_string()
        } else {
            known.join(" or ")
        };
        bail!(
            "the wallet holds no token {}{} accepts for {model}{}\nNext: send {send} on Tempo to {address} (see `sample-llm wallet`)",
            merchant::HOST,
            merchant::CHAT,
            symbol.map(|s| format!(" in {s}")).unwrap_or_default()
        );
    };
    let token_address = token.token.clone().context("the token has no address")?;
    let deposit = money::parse_units(deposit, token.decimals).context("--deposit")?;
    let max_spend = money::parse_units(max_spend, token.decimals).context("--max-spend")?;
    if deposit > max_spend {
        bail!("--deposit is above --max-spend");
    }
    if agentpay::proxy_status()?.running {
        bail!("AgentPay's paying proxy is already running for another program\nNext: stop it with `agentpay proxy stop`, then try again");
    }

    let proxy = agentpay::proxy_start(&agentpay::ProxyTerms {
        host: merchant::HOST,
        token: &token_address,
        deposit,
        max_spend,
    })?;
    // Stop the proxy whatever happens, Ctrl+C included.
    let outcome = tokio::select! {
        outcome = ask(&proxy, prompt, model, token) => outcome,
        _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("interrupted")),
    };
    drop(proxy);
    if let Err(error) = agentpay::proxy_stop() {
        eprintln!("(could not stop the paying proxy: {error})");
    }
    outcome
}

/// What one request cost, from the merchant's receipts.
struct Charges {
    receipt: Option<Receipt>,
    vouchers: u32,
}

async fn ask(
    proxy: &ProxyStartResult,
    prompt: &str,
    model: &str,
    token: &WalletBalanceEntry,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy.proxy_url.as_str())?)
        .add_root_certificate(reqwest::Certificate::from_pem(
            proxy.ca_certificate_pem.as_bytes(),
        )?)
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(120))
        .build()?;
    let mut response = client
        .post(format!("{}{}", merchant::ORIGIN, merchant::CHAT))
        .json(&merchant::chat_body(model, prompt))
        .send()
        .await
        .context("the request through AgentPay's paying proxy failed")?;
    let status = response.status();
    if !status.is_success() {
        let kind = response
            .headers()
            .get("x-agentpay-proxy-error")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.text().await.unwrap_or_default();
        match kind.as_deref() {
            Some("ManualApprovalPending") => bail!(
                "this payment is above your AgentPay limits and waits for your approval\nNext: approve it in `agentpay` → Approvals, then run this again"
            ),
            Some(kind) => bail!("AgentPay could not pay ({kind}): {}", body.trim()),
            None => bail!("{} answered {status}: {}", merchant::HOST, body.trim()),
        }
    }
    let mut charges = Charges {
        receipt: response
            .headers()
            .get("payment-receipt")
            .and_then(|value| value.to_str().ok())
            .and_then(Receipt::from_header),
        vouchers: 0,
    };
    let mut parser = EventParser::default();
    let mut out = std::io::stdout();
    while let Some(chunk) = response.chunk().await.context("the answer stopped")? {
        for event in parser.push(&chunk) {
            match event.name.as_str() {
                "payment-need-voucher" => charges.vouchers += 1,
                "payment-receipt" => {
                    if let Some(receipt) = serde_json::from_str(&event.data)
                        .ok()
                        .and_then(|value| Receipt::from_json(&value))
                    {
                        charges.receipt = Some(receipt);
                    }
                }
                _ => {
                    if let Some(text) = delta_text(&event.data) {
                        out.write_all(text.as_bytes())?;
                        out.flush()?;
                    }
                }
            }
        }
    }
    println!();
    report(&charges, token);
    Ok(())
}

fn report(charges: &Charges, token: &WalletBalanceEntry) {
    let amount = |units| format!("{} {}", format_units(units, token.decimals), token.symbol);
    let Some(receipt) = &charges.receipt else {
        eprintln!("─ No payment receipt: the answer may have been free.");
        return;
    };
    let before = ChannelLog::open().record(&receipt.channel_id, receipt.spent);
    let channel = &receipt.channel_id[..receipt.channel_id.len().min(10)];
    let mid_stream = if charges.vouchers > 0 {
        format!(" · {} more paid during the stream", charges.vouchers)
    } else {
        String::new()
    };
    match before {
        Some(before) => eprintln!(
            "─ Charged {} · channel {channel}… total {}{mid_stream}",
            amount(receipt.spent.saturating_sub(before)),
            amount(receipt.spent)
        ),
        None => eprintln!(
            "─ Channel {channel}… has been charged {} so far{mid_stream}",
            amount(receipt.spent)
        ),
    }
}
