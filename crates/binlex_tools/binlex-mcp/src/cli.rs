use std::path::PathBuf;

use clap::{Parser, Subcommand};

use binlex::{AUTHOR, VERSION};

#[derive(Parser, Debug)]
#[command(
    name = "binlex-mcp",
    version = VERSION,
    about = format!("A Binlex MCP Server\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Init(InitArgs),
    Serve(ServeArgs),
    Skills(SkillsArgs),
}

#[derive(Parser, Debug)]
pub struct InitArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub yes: bool,
    #[arg()]
    pub sources: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub listen: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub base_url: Option<String>,
    #[arg(long)]
    pub samples: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct SkillsArgs {
    #[command(subcommand)]
    pub command: SkillsCommand,
}

#[derive(Subcommand, Debug)]
pub enum SkillsCommand {
    Clear(SkillsClearArgs),
}

#[derive(Parser, Debug)]
pub struct SkillsClearArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,
}
