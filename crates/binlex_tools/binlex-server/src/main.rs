use std::net::SocketAddr;
use std::path::PathBuf;

use axum::serve;
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "binlex-server")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    debug: bool,
}

fn ensure_config_exists(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(());
    }

    let path_str = path.to_str().ok_or("invalid configuration path")?;
    binlex::Config::default().write_to_file(path_str)?;
    binlex::Config::ensure_default_processor_directory()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if let Some(path) = args.config.as_deref() {
        ensure_config_exists(path)?;
    }
    let mut config = binlex::Config::load(args.config.as_deref())?;
    if let Some(listen) = args.listen {
        let port = args.port.unwrap_or_else(|| {
            config
                .server
                .bind
                .rsplit(':')
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(5000)
        });
        config.server.bind = format!("{}:{}", listen, port);
    } else if let Some(port) = args.port {
        let listen = config
            .server
            .bind
            .rsplit_once(':')
            .map(|(host, _)| host.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        config.server.bind = format!("{}:{}", listen, port);
    }
    if args.debug {
        config.server.debug = true;
    }
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(if config.server.debug {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .init();
    let bind: SocketAddr = config.server.bind.parse()?;
    let state = binlex::server::state::AppState::new(config.clone())?;
    let router = binlex::server::routes::build_router(state);
    info!(
        "listening on {} debug={}",
        config.server.bind, config.server.debug
    );

    let listener = tokio::net::TcpListener::bind(bind).await?;
    serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
