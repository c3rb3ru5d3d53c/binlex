// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::{Config, ConfigData, DIRECTORY, FILE_NAME};
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

impl Config {
    #[allow(dead_code)]
    pub fn print(&self) {
        println!("{}", self.to_string().unwrap());
    }

    #[allow(dead_code)]
    pub fn to_string(&self) -> Result<String, Error> {
        toml::to_string_pretty(self).map_err(Error::other)
    }

    pub fn from_file(file_path: &str) -> Result<Config, Error> {
        let toml_string = fs::read_to_string(file_path)?;
        let config: ConfigData = toml::from_str(&toml_string).map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!(
                    "failed to read configuration file {}\n\n{}",
                    file_path, error
                ),
            )
        })?;
        Ok(Self::from_data(config))
    }

    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|config_dir| config_dir.join(format!("{}/{}", DIRECTORY, FILE_NAME)))
    }

    pub fn ensure_default_path() -> Result<PathBuf, Error> {
        let path = Self::default_path()
            .ok_or_else(|| Error::other("unable to resolve default binlex configuration path"))?;
        if !path.exists() {
            Self::default().write_to_file(
                path.to_str()
                    .ok_or_else(|| Error::other("invalid default configuration path"))?,
            )?;
        }
        Ok(path)
    }

    pub fn load(path: Option<&Path>) -> Result<Self, Error> {
        let owned_path;
        let path = match path {
            Some(path) => path,
            None => {
                owned_path = Self::ensure_default_path()?;
                owned_path.as_path()
            }
        };
        Self::from_file(
            path.to_str()
                .ok_or_else(|| Error::other("invalid configuration path"))?,
        )
    }

    #[allow(dead_code)]
    pub fn write_to_file(&self, file_path: &str) -> Result<(), Error> {
        let toml_string = self
            .to_string()
            .expect("failed to serialize binlex configration to toml format");
        fs::write(file_path, toml_string)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn write_default(&self) -> Result<(), Error> {
        if let Some(config_directory) = dirs::config_dir() {
            let config_file_path: PathBuf =
                config_directory.join(format!("{}/{}", DIRECTORY, FILE_NAME));
            if let Some(parent_directory) = config_file_path.parent() {
                if !parent_directory.exists() {
                    fs::create_dir_all(parent_directory)
                        .expect("failed to create binlex configuration directory");
                }
            }
            if !config_file_path.exists() {
                return self.write_to_file(config_file_path.to_str().unwrap());
            }
        }
        Err(Error::other("default configuration already exists"))
    }

    #[allow(dead_code)]
    pub fn from_default(&mut self) -> Result<(), Error> {
        if let Some(config_directory) = dirs::config_dir() {
            let config_file_path: PathBuf =
                config_directory.join(format!("{}/{}", DIRECTORY, FILE_NAME));
            if config_file_path.exists() {
                match Config::from_file(config_file_path.to_str().unwrap()) {
                    Ok(config) => {
                        return {
                            *self = config;
                            Ok(())
                        };
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Err(Error::other(
            "unable to read binlex default configuration file",
        ))
    }
}
