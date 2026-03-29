use std::io::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::serve;
use binlex::config::DIRECTORY;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::info;

const SERVER_FILE_NAME: &str = "binlex-server.toml";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ServerRuntimeConfig {
    bind: String,
    #[serde(default)]
    debug: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerConfigFile {
    #[serde(default)]
    server: ServerRuntimeConfig,
    #[serde(flatten)]
    binlex: binlex::Config,
}

impl Default for ServerRuntimeConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:5000".to_string(),
            debug: false,
        }
    }
}

impl Default for ServerConfigFile {
    fn default() -> Self {
        Self {
            server: ServerRuntimeConfig::default(),
            binlex: server_default_config(),
        }
    }
}

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

fn server_default_path() -> Result<PathBuf, Error> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| Error::other("unable to resolve config directory"))?;
    Ok(config_dir.join(DIRECTORY).join(SERVER_FILE_NAME))
}

fn resolve_config_path(
    path: Option<&std::path::Path>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(match path {
        Some(path) => path.to_path_buf(),
        None => server_default_path()?,
    })
}

fn server_default_config() -> binlex::Config {
    let mut config = binlex::Config::default();
    let default_index_path = binlex::Config::default_local_index_directory();
    if let Some(processor) = config.processors.ensure_processor("embeddings") {
        processor.enabled = true;
        processor.complete.enabled = true;
        processor.transport.ipc.enabled = true;
        processor.transport.http.enabled = false;
        processor.options.insert(
            "index".to_string(),
            std::collections::BTreeMap::from([
                (
                    "local".to_string(),
                    std::collections::BTreeMap::from([
                        ("enabled".to_string(), true.into()),
                        ("path".to_string(), default_index_path.into()),
                        ("selector".to_string(), "processors.embeddings.vector".into()),
                        ("corpus".to_string(), "default".into()),
                    ])
                    .into(),
                ),
                (
                    "collection".to_string(),
                    std::collections::BTreeMap::from([
                        ("function".to_string(), true.into()),
                        ("block".to_string(), false.into()),
                        ("instruction".to_string(), false.into()),
                    ])
                    .into(),
                ),
            ])
            .into(),
        );
    }
    config
}

fn load_server_config(path: &std::path::Path) -> Result<ServerConfigFile, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let config: ServerConfigFile = toml::from_str(&raw)?;
    Ok(config)
}

fn ensure_config_exists(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, toml::to_string_pretty(&ServerConfigFile::default())?)?;
    binlex::Config::ensure_default_processor_directory()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config_path = resolve_config_path(args.config.as_deref())?;
    ensure_config_exists(&config_path)?;
    let mut loaded = load_server_config(&config_path)?;
    if let Some(listen) = args.listen {
        let port = args.port.unwrap_or_else(|| {
            loaded
                .server
                .bind
                .rsplit(':')
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(5000)
        });
        loaded.server.bind = format!("{}:{}", listen, port);
    } else if let Some(port) = args.port {
        let listen = loaded
            .server
            .bind
            .rsplit_once(':')
            .map(|(host, _)| host.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        loaded.server.bind = format!("{}:{}", listen, port);
    }
    if args.debug {
        loaded.server.debug = true;
    }
    let config = loaded.binlex;
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(if loaded.server.debug {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .init();
    let bind: SocketAddr = loaded.server.bind.parse()?;
    let state = binlex::server::state::AppState::new(config.clone(), loaded.server.debug)?;
    let router = binlex::server::routes::build_router(state);
    info!(
        "listening on {} debug={}",
        loaded.server.bind, loaded.server.debug
    );

    let listener = tokio::net::TcpListener::bind(bind).await?;
    serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SERVER_FILE_NAME, server_default_config};

    #[test]
    fn server_config_uses_server_specific_file_name() {
        assert_eq!(SERVER_FILE_NAME, "binlex-server.toml");
    }

    #[test]
    fn server_default_config_enables_embeddings_processor() {
        let config = server_default_config();
        let embeddings = config
            .processors
            .processor("embeddings")
            .expect("embeddings processor config should exist");
        assert!(embeddings.enabled);
        assert!(embeddings.graph.enabled);
        assert!(!embeddings.instructions.enabled);
        assert!(!embeddings.blocks.enabled);
        assert!(!embeddings.functions.enabled);
        assert!(embeddings.complete.enabled);
        assert!(embeddings.transport.ipc.enabled);
        assert!(!embeddings.transport.http.enabled);
        let index = embeddings
            .options
            .get("index")
            .and_then(binlex::config::ConfigProcessorValue::as_table)
            .expect("embeddings index config should exist");
        let local = index
            .get("local")
            .and_then(binlex::config::ConfigProcessorValue::as_table)
            .expect("embeddings local index config should exist");
        assert_eq!(
            local.get("selector")
                .and_then(binlex::config::ConfigProcessorValue::as_string),
            Some("processors.embeddings.vector")
        );
    }

    #[test]
    fn shared_binlex_config_has_no_server_section() {
        let toml = toml::to_string_pretty(&binlex::Config::default())
            .expect("shared config should serialize");
        assert!(!toml.contains("[server]"));
    }
}
