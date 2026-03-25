use std::net::SocketAddr;
use std::path::PathBuf;

use axum::serve;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "binlex-server")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut config = binlex::Config::load(args.config.as_deref())?;
    if args.debug {
        config.server.debug = true;
    }
    let bind: SocketAddr = config.server.bind.parse()?;
    let state = binlex::server::state::AppState::new(config.clone())?;
    let router = binlex::server::routes::build_router(state);

    if config.server.debug {
        eprintln!(
            "[binlex-server] listening on {} debug=true",
            config.server.bind
        );
    }

    let listener = tokio::net::TcpListener::bind(bind).await?;
    serve(listener, router).await?;
    Ok(())
}
