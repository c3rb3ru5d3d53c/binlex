use std::fs;
use std::io::Error;
use std::path::{Path, PathBuf};

use crate::ConfigProcessors;
use crate::global::config::DIRECTORY;

pub const FILE_NAME: &str = "binlex-server.toml";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerSection {
    pub bind: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    #[serde(default)]
    pub processors: ConfigProcessors,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:5000".to_string(),
        }
    }
}

impl ServerConfig {
    pub fn embeddings_dimensions(&self) -> usize {
        self.processors
            .processor("embeddings")
            .and_then(|processor| processor.option_integer("dimensions"))
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > 0)
            .unwrap_or(64)
    }

    pub fn embeddings_device(&self) -> String {
        self.processors
            .processor("embeddings")
            .and_then(|processor| processor.option_string("device"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "cpu".to_string())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        let mut processors = ConfigProcessors::default();
        crate::processors::apply_server_defaults(&mut processors);
        Self {
            server: ServerSection::default(),
            processors,
        }
    }
}

impl ServerConfig {
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|config_dir| config_dir.join(format!("{}/{}", DIRECTORY, FILE_NAME)))
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), Error> {
        let contents = toml::to_string_pretty(self).map_err(Error::other)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }

    pub fn ensure_default() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = Self::default_path().ok_or_else(|| {
            Error::other("unable to resolve default binlex-server configuration path")
        })?;
        if !path.exists() {
            Self::default().write_to_file(&path)?;
        }
        Ok(path)
    }

    pub fn load(path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let owned_path;
        let path = match path {
            Some(path) => path,
            None => {
                owned_path = Self::ensure_default()?;
                owned_path.as_path()
            }
        };
        let contents = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&contents)?;
        crate::processors::apply_server_defaults(&mut config.processors);
        Ok(config)
    }
}
