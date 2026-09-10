mod dbgeng;
mod ipc;
mod server;
mod sessions;
mod worker;

use anyhow::Context;
use rmcp::{ServiceExt, transport::stdio};
use server::WindbgServer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().any(|argument| argument == "--engine-worker") {
        return worker::run().context("engine worker failed");
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting WinDbg MCP server"
    );

    let service = WindbgServer::new()
        .serve(stdio())
        .await
        .context("failed to start MCP stdio transport")?;

    service.waiting().await.context("MCP service failed")?;
    Ok(())
}
