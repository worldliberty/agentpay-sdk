//! `agentpay-paymentd` binary: parse flags, start logging, run the service.

use anyhow::Result;
use clap::Parser;

use agentpay_paymentd::cli::Cli;
use agentpay_paymentd::{logging, runtime};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init(&cli.log)?;
    let result = runtime::run(cli).await;
    if let Err(error) = &result {
        tracing::error!("{error:#}");
    }
    result
}
