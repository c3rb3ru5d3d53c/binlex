use std::net::SocketAddr;
use std::path::PathBuf;

use axum::serve;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "binlex-server")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = binlex::server::config::ServerConfig::load(args.config.as_deref())?;
    let bind: SocketAddr = config.server.bind.parse()?;
    let state = binlex::server::state::AppState::new(config.clone())?;
    let router = binlex::server::routes::build_router(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    serve(listener, router).await?;
    Ok(())
}
