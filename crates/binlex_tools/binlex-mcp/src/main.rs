mod cli;
mod error;
mod python;
mod samples;
mod server;
mod skills;
mod state;

use clap::Parser;

use crate::cli::{Args, Command, SkillsCommand};
use crate::python::verify_python_environment;
use crate::server::BinlexMcpServer;
use crate::state::{
    McpState, clear_skills, init_mcp_config, load_binlex_config, load_mcp_config, log_startup,
    resolve_base_url, resolve_python_command, resolve_samples_dir,
};

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    tracing_subscriber::fmt().with_target(false).init();
    match args.command {
        Command::Init(args) => {
            let path = init_mcp_config(args.config.as_deref(), &args.sources, args.yes)?;
            println!("{}", path.display());
            Ok(())
        }
        Command::Serve(args) => {
            let config = load_binlex_config(None)?;
            let mut mcp = load_mcp_config(args.config.as_deref())?;
            if let Some(listen) = args.listen {
                mcp.listen = listen;
            }
            if let Some(port) = args.port {
                mcp.port = port;
            }
            if let Ok(base_url) = std::env::var("BINLEX_MCP_BASE_URL") {
                mcp.base_url = resolve_base_url(Some(&base_url))?;
            }
            if let Some(base_url) = args.base_url.as_deref() {
                mcp.base_url = resolve_base_url(Some(base_url))?;
            } else {
                mcp.base_url = resolve_base_url(mcp.base_url.as_deref())?;
            }
            if let Some(samples) = &args.samples {
                mcp.samples.directory = Some(samples.to_string_lossy().into_owned());
            }
            let python_command = resolve_python_command();
            verify_python_environment(&python_command)?;
            let samples_dir =
                resolve_samples_dir(mcp.samples.directory.as_deref().map(std::path::Path::new))?;
            log_startup(
                &mcp.listen,
                mcp.port,
                mcp.base_url.as_deref(),
                &python_command,
                &samples_dir,
                mcp.samples.max_upload_size_bytes,
                &mcp.skills,
            )?;
            let state = McpState::new(config, mcp, python_command)?;
            BinlexMcpServer::new(state).serve().await
        }
        Command::Skills(args) => match args.command {
            SkillsCommand::Clear(args) => {
                let path = clear_skills(args.config.as_deref())?;
                println!("{}", path.display());
                Ok(())
            }
        },
    }
}
