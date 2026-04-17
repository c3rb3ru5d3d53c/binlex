use std::io::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::serve;
use binlex::config::DIRECTORY;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

mod routes;

const SERVER_FILE_NAME: &str = "binlex-server.toml";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ServerRuntimeConfig {
    bind: String,
    #[serde(default)]
    debug: bool,
    binlex_config: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerConfigFile {
    #[serde(rename = "binlex-server")]
    server: ServerRuntimeConfig,
}

impl Default for ServerRuntimeConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:5000".to_string(),
            debug: false,
            binlex_config: binlex::Config::default_path()
                .unwrap_or_else(|| PathBuf::from("binlex.toml"))
                .to_string_lossy()
                .into_owned(),
        }
    }
}

impl Default for ServerConfigFile {
    fn default() -> Self {
        Self {
            server: ServerRuntimeConfig::default(),
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
    #[arg(long, value_delimiter = ',')]
    processors: Option<Vec<String>>,
    #[arg(long)]
    processes: Option<usize>,
    #[arg(long)]
    processor_directory: Option<String>,
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

fn resolve_binlex_config_path(path: &str) -> PathBuf {
    if path == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from(path));
    }
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

fn load_server_config(
    path: &std::path::Path,
) -> Result<ServerConfigFile, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let config: ServerConfigFile = toml::from_str(&raw)?;
    Ok(config)
}

fn apply_processor_cli_overrides(config: &mut binlex::Config, args: &Args) {
    if let Some(processes) = args.processes {
        config.processors.processes = processes;
    }
    if let Some(directory) = args
        .processor_directory
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        config.processors.path = Some(directory.to_string());
    }
    if let Some(processors) = args.processors.as_ref() {
        let enabled: std::collections::BTreeSet<String> = processors
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
        config.processors.enabled = !enabled.is_empty();
        for processor in config.processors.processors.values_mut() {
            processor.enabled = false;
        }
        for name in enabled {
            if let Some(processor) = config.processors.ensure_processor(&name) {
                processor.enabled = true;
            }
        }
    }
}

fn ensure_config_exists(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, toml::to_string_pretty(&ServerConfigFile::default())?)?;
    let binlex_config_path = binlex::Config::default_path()
        .ok_or_else(|| Error::other("unable to resolve default binlex configuration path"))?;
    if !binlex_config_path.exists() {
        binlex::Config::default().write_to_file(
            binlex_config_path
                .to_str()
                .ok_or_else(|| Error::other("invalid default binlex configuration path"))?,
        )?;
    }
    binlex::Config::ensure_default_processor_directory()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config_path = resolve_config_path(args.config.as_deref())?;
    ensure_config_exists(&config_path)?;
    let mut loaded = load_server_config(&config_path)?;
    if let Some(listen) = args.listen.as_ref() {
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
    let binlex_config_path = resolve_binlex_config_path(&loaded.server.binlex_config);
    let mut config = binlex::Config::load(Some(binlex_config_path.as_path()))?;
    apply_processor_cli_overrides(&mut config, &args);
    let embeddings_registered = binlex::processor::processor_registration_by_name_for_config(
        &config.processors,
        "embeddings",
    )
    .is_some();
    let embeddings_config = config.processors.processor("embeddings").cloned();
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
    let router = routes::build_router(state);
    info!(
        "listening on {} debug={} processors_path={:?} embeddings_registered={} embeddings_enabled={} embeddings_graph_enabled={} embeddings_complete_enabled={}",
        loaded.server.bind,
        loaded.server.debug,
        config.processors.path,
        embeddings_registered,
        embeddings_config
            .as_ref()
            .map(|processor| processor.enabled)
            .unwrap_or(false),
        embeddings_config
            .as_ref()
            .map(|processor| processor.graph.enabled)
            .unwrap_or(false),
        embeddings_config
            .as_ref()
            .map(|processor| processor.complete.enabled)
            .unwrap_or(false),
    );
    if !embeddings_registered {
        for diagnostic in
            binlex::processor::processor_discovery_diagnostics_for_config(&config.processors)
        {
            match diagnostic.status {
                binlex::processor::ProcessorDiscoveryStatus::Registered { name } => {
                    info!(
                        "processor discovery candidate={:?} status=registered name={}",
                        diagnostic.candidate, name
                    );
                }
                binlex::processor::ProcessorDiscoveryStatus::DuplicateName { name } => {
                    warn!(
                        "processor discovery candidate={:?} status=duplicate_name name={}",
                        diagnostic.candidate, name
                    );
                }
                binlex::processor::ProcessorDiscoveryStatus::SpawnFailed { error } => {
                    warn!(
                        "processor discovery candidate={:?} status=spawn_failed error={}",
                        diagnostic.candidate, error
                    );
                }
                binlex::processor::ProcessorDiscoveryStatus::DescribeFailed { status, stderr } => {
                    warn!(
                        "processor discovery candidate={:?} status=describe_failed exit_status={} stderr={:?}",
                        diagnostic.candidate, status, stderr
                    );
                }
                binlex::processor::ProcessorDiscoveryStatus::InvalidRegistrationJson {
                    error,
                    stdout,
                    stderr,
                } => {
                    warn!(
                        "processor discovery candidate={:?} status=invalid_registration_json error={} stdout={:?} stderr={:?}",
                        diagnostic.candidate, error, stdout, stderr
                    );
                }
                binlex::processor::ProcessorDiscoveryStatus::InvalidRegistrationMetadata => {
                    warn!(
                        "processor discovery candidate={:?} status=invalid_registration_metadata",
                        diagnostic.candidate
                    );
                }
            }
        }
    }

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
    use super::{SERVER_FILE_NAME, ServerConfigFile, ServerRuntimeConfig};

    #[test]
    fn server_config_uses_server_specific_file_name() {
        assert_eq!(SERVER_FILE_NAME, "binlex-server.toml");
    }

    #[test]
    fn server_runtime_config_defaults_to_binlex_default_path() {
        let config = ServerRuntimeConfig::default();
        assert!(!config.binlex_config.is_empty());
    }

    #[test]
    fn shared_binlex_config_is_namespaced() {
        let toml = toml::to_string_pretty(&binlex::Config::default())
            .expect("shared config should serialize");
        assert!(toml.contains("[binlex]"));
    }

    #[test]
    fn server_config_uses_binlex_server_namespace() {
        let toml = toml::to_string_pretty(&ServerConfigFile::default())
            .expect("server config should serialize");
        assert!(toml.contains("[binlex-server]"));
        assert!(!toml.contains("[server]"));
    }
}
