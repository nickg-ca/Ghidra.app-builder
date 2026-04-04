mod bridge;
mod ghidra;
mod server;

use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting ghidra-mcp server");

    let server = server::GhidraMcpServer::new()?;
    let sessions = server.sessions.clone();

    let service = server.serve(stdio()).await.inspect_err(|e| {
        tracing::error!("serving error: {:?}", e);
    })?;

    service.waiting().await?;

    // Clean up all bridge sessions on shutdown
    tracing::info!("Shutting down, cleaning up sessions...");
    let mut sessions = sessions.lock().await;
    for (id, session) in sessions.iter_mut() {
        tracing::info!("Closing session {}", id);
        let _ = session
            .bridge
            .send_command("save", serde_json::json!({}))
            .await;
        let _ = session
            .bridge
            .send_command("shutdown", serde_json::json!({}))
            .await;
        let _ = session.child.kill().await;
    }
    sessions.clear();

    tracing::info!("ghidra-mcp shutdown complete");
    Ok(())
}
