use crate::commands::{perf::PerfArgs, query::QueryArgs};
use binlex::VERSION;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "binlex-test", version = VERSION)]
pub struct Args {
    #[arg(long)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Domain,
}

#[derive(Subcommand, Debug)]
pub enum Domain {
    Query(QueryArgs),
    Perf(PerfArgs),
}
