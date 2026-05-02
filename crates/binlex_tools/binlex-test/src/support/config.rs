use binlex::Configuration;
use std::error::Error;
use std::fs;
use std::path::Path;

pub fn load_config(path: Option<&Path>) -> Result<Configuration, Box<dyn Error>> {
    match path {
        Some(path) => Ok(toml::from_str::<Configuration>(&fs::read_to_string(path)?)?),
        None => Ok(Configuration::default()),
    }
}
