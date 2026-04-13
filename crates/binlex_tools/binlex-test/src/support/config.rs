use binlex::Config;
use std::error::Error;
use std::fs;
use std::path::Path;

pub fn load_config(path: Option<&Path>) -> Result<Config, Box<dyn Error>> {
    match path {
        Some(path) => Ok(toml::from_str::<Config>(&fs::read_to_string(path)?)?),
        None => Ok(Config::default()),
    }
}
