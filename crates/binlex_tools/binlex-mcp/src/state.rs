use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use binlex::config::DIRECTORY;
use binlex::processor::registered_processor_registrations_for_config;
use binlex::server::dto::ProcessorHttpRequest;
use binlex::server::state::AppState;
use binlex::{Config, VERSION};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::error::DynError;
use crate::samples::{McpSamplesConfig, SampleStore};

const MCP_FILE_NAME: &str = "binlex-mcp.toml";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpConfig {
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    pub samples: McpSamplesConfig,
    #[serde(default)]
    pub skills: Vec<McpSkill>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpSkill {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SkillSourceFile {
    #[serde(default)]
    skills: Vec<McpSkill>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1".to_string(),
            port: 5001,
            samples: McpSamplesConfig::default(),
            skills: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct McpState {
    pub config: Config,
    pub mcp: McpConfig,
    pub processor_state: AppState,
    pub python_command: String,
    pub sample_store: Arc<SampleStore>,
}

impl McpState {
    pub fn new(
        config: Config,
        mcp: McpConfig,
        python_command: String,
    ) -> Result<Self, DynError> {
        let processor_state = AppState::new(config.clone())?;
        let samples_dir = resolve_samples_dir(mcp.samples.directory.as_deref().map(Path::new))?;
        let sample_store = Arc::new(SampleStore::new(
            samples_dir,
            mcp.samples.max_upload_size_bytes,
        )?);
        Ok(Self {
            config,
            mcp,
            processor_state,
            python_command,
            sample_store,
        })
    }

    pub fn processor_list(&self) -> Value {
        json!(
            registered_processor_registrations_for_config(&self.config.processors)
                .into_iter()
                .map(|registration| {
                    let enabled = self
                        .config
                        .processors
                        .processor(&registration.name)
                        .is_some_and(|processor| processor.enabled);
                    json!({
                        "name": registration.name,
                        "backend_name": registration.backend_name,
                        "requires": registration.requires,
                        "architectures": registration.architectures,
                        "transports": registration.transports,
                        "enabled": enabled,
                    })
                })
                .collect::<Vec<_>>()
        )
    }

    pub fn processor_run(&self, processor: &str, data: Value) -> Result<Value, DynError> {
        let registration = binlex::processor::processor_registration_by_name_for_config(
            &self.config.processors,
            processor,
        )
        .ok_or_else(|| format!("unknown processor: {}", processor))?;
        binlex::server::processors::execute(
            &self.processor_state,
            processor,
            ProcessorHttpRequest {
                binlex_version: VERSION.to_string(),
                requires: registration.registration.requires,
                data,
            },
        )
        .map_err(|error| format!("{:?}", error).into())
    }
}

pub fn load_binlex_config(path: Option<&Path>) -> Result<Config, DynError> {
    Ok(Config::load(path)?)
}

pub fn mcp_default_path() -> Result<PathBuf, DynError> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| "unable to resolve default configuration directory")?;
    Ok(config_dir.join(DIRECTORY).join(MCP_FILE_NAME))
}

fn resolve_mcp_path(path: Option<&Path>) -> Result<PathBuf, DynError> {
    Ok(match path {
        Some(path) => path.to_path_buf(),
        None => mcp_default_path()?,
    })
}

pub fn load_mcp_config(path: Option<&Path>) -> Result<McpConfig, DynError> {
    let path = resolve_mcp_path(path)?;
    if !path.exists() {
        return Err(format!(
            "missing MCP config at {}. Run `binlex-mcp init` or create it first.",
            path.display()
        )
        .into());
    }
    let content = fs::read_to_string(&path)?;
    Ok(toml::from_str(&content)?)
}

fn ensure_mcp_config(path: Option<&Path>) -> Result<(PathBuf, McpConfig), DynError> {
    let path = resolve_mcp_path(path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        fs::write(&path, toml::to_string_pretty(&McpConfig::default())?)?;
    }
    let content = fs::read_to_string(&path)?;
    let config: McpConfig = toml::from_str(&content)?;
    Ok((path, config))
}

pub fn init_mcp_config(
    path: Option<&Path>,
    sources: &[String],
    yes: bool,
) -> Result<PathBuf, DynError> {
    let (path, mut config) = ensure_mcp_config(path)?;
    let expanded_sources = expand_sources(sources)?;
    let remote_urls = unique_remote_sources(&expanded_sources);
    if !remote_urls.is_empty() && !yes {
        prompt_trust_sources(&remote_urls)?;
    }

    for source in expanded_sources {
        let imported = load_skill_file(source.as_str())?;
        merge_skill_sets(&mut config, imported.skills)?;
    }

    fs::write(&path, toml::to_string_pretty(&config)?)?;
    Ok(path)
}

pub fn clear_skills(path: Option<&Path>) -> Result<PathBuf, DynError> {
    let (path, mut config) = ensure_mcp_config(path)?;
    config.skills.clear();
    fs::write(&path, toml::to_string_pretty(&config)?)?;
    Ok(path)
}

fn load_skill_file(source: &str) -> Result<SkillSourceFile, DynError> {
    let content = if is_remote_source(source) {
        let response = reqwest::blocking::get(source)?;
        if !response.status().is_success() {
            return Err(format!("failed to download skills from {}", source).into());
        }
        response.text()?
    } else {
        fs::read_to_string(source)?
    };
    Ok(toml::from_str(&content)?)
}

fn expand_sources(sources: &[String]) -> Result<Vec<String>, DynError> {
    let mut expanded = Vec::new();

    for source in sources {
        if is_remote_source(source) {
            expanded.push(source.clone());
            continue;
        }

        let path = Path::new(source);
        if path.is_dir() {
            let mut entries = fs::read_dir(path)?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(|entry| {
                    let path = entry.path();
                    if !path.is_file() {
                        return None;
                    }
                    if path.extension().is_some_and(|extension| extension == "toml") {
                        return Some(path);
                    }
                    None
                })
                .collect::<Vec<_>>();
            entries.sort();
            expanded.extend(
                entries
                    .into_iter()
                    .map(|entry| entry.to_string_lossy().into_owned()),
            );
            continue;
        }

        expanded.push(source.clone());
    }

    Ok(expanded)
}

fn merge_skill_sets(config: &mut McpConfig, incoming: Vec<McpSkill>) -> Result<(), DynError> {
    for skill in incoming {
        if let Some(existing) = config.skills.iter().find(|existing| existing.name == skill.name) {
            if !skills_equal(existing, &skill) {
                return Err(format!("skill conflict for '{}'", skill.name).into());
            }
            continue;
        }
        config.skills.push(skill);
    }
    Ok(())
}

fn skills_equal(left: &McpSkill, right: &McpSkill) -> bool {
    left.name == right.name
        && left.description == right.description
        && left.instructions == right.instructions
        && left.python == right.python
}

fn is_remote_source(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

fn unique_remote_sources(sources: &[String]) -> Vec<String> {
    let mut urls = Vec::<String>::new();
    for source in sources {
        if is_remote_source(source) && !urls.contains(source) {
            urls.push(source.clone());
        }
    }
    urls
}

fn prompt_trust_sources(sources: &[String]) -> Result<(), DynError> {
    println!("Do you trust these remote sources?");
    for source in sources {
        println!("- {}", source);
    }
    print!("(y/n): ");
    io::stdout().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    match response.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => Err("aborted by user".into()),
    }
}

pub fn resolve_python_command() -> String {
    if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
        let candidate = Path::new(&venv).join("bin/python");
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "python3".to_string()
}

pub fn resolve_samples_dir(configured: Option<&Path>) -> Result<PathBuf, DynError> {
    let path = configured
        .map(Path::to_path_buf)
        .unwrap_or_else(default_samples_dir);
    fs::create_dir_all(&path)?;
    if !path.is_dir() {
        return Err(format!("samples path is not a directory: {}", path.display()).into());
    }
    let probe = path.join(format!(
        ".binlex-mcp-write-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    fs::write(&probe, b"")?;
    fs::remove_file(probe)?;
    Ok(path)
}

fn default_samples_dir() -> PathBuf {
    dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join(DIRECTORY)
        .join("samples")
}

pub fn log_startup(
    listen: &str,
    port: u16,
    python_command: &str,
    samples_dir: &Path,
    max_upload_size_bytes: usize,
    skills: &[McpSkill],
) -> Result<(), DynError> {
    info!(
        listen = listen,
        port = port,
        python = python_command,
        samples = %samples_dir.display(),
        max_upload_size_bytes = max_upload_size_bytes,
        skills = skills.len(),
        "starting binlex-mcp"
    );
    for skill in skills {
        info!(
            skill = skill.name,
            description = skill.description,
            "loaded skill"
        );
    }
    if skills.is_empty() {
        warn!("no MCP skills configured in ~/.config/binlex/binlex-mcp.toml");
        warn!("add skills like:");
        warn!("[[skills]]");
        warn!("name = \"triage\"");
        warn!("description = \"Analyze a binary\"");
        warn!("instructions = \"...\"");
        warn!("python = \"...\"");
        warn!("example skills are available in the official binlex repository");
        return Err("no MCP skills configured".into());
    }
    Ok(())
}

pub fn to_json_string<T: Serialize>(value: &T) -> Result<String, DynError> {
    Ok(serde_json::to_string_pretty(value)?)
}
