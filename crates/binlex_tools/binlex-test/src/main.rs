mod cli;
mod commands;
mod support;

use crate::cli::{Args, Domain};
use crate::support::config::load_config;
use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;

    match args.command {
        Domain::Query(query) => commands::query::run(query),
        Domain::Perf(perf) => commands::perf::run(&config, perf),
    }
}
