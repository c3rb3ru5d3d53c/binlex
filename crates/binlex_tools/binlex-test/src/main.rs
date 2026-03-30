use binlex::search::{Query, query_architecture_values, query_collection_values};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Parser, Debug)]
#[command(name = "binlex-test")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Query(QueryArgs),
}

#[derive(Parser, Debug)]
struct QueryArgs {
    #[command(subcommand)]
    command: QueryCommand,
}

#[derive(Subcommand, Debug)]
enum QueryCommand {
    Parse(QueryParseArgs),
    Suggest(QuerySuggestArgs),
    Apply(QueryApplyArgs),
}

#[derive(Parser, Debug)]
struct QueryParseArgs {
    #[arg(long)]
    query: String,
}

#[derive(Parser, Debug)]
struct QuerySuggestArgs {
    #[arg(long)]
    query: String,
    #[arg(long)]
    cursor: Option<usize>,
    #[arg(long, value_enum, default_value_t = QueryEngine::Js)]
    engine: QueryEngine,
}

#[derive(Parser, Debug)]
struct QueryApplyArgs {
    #[arg(long)]
    query: String,
    #[arg(long)]
    item: String,
    #[arg(long)]
    kind: String,
    #[arg(long)]
    insert: Option<String>,
    #[arg(long)]
    cursor: Option<usize>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum QueryEngine {
    Rust,
    Js,
}

#[derive(Serialize)]
struct RustParseOutput<'a> {
    raw: &'a str,
    expr: &'a binlex::search::QueryExpr,
    analysis: binlex::search::QueryAnalysis,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.command {
        Commands::Query(query) => run_query(query)?,
    }
    Ok(())
}

fn run_query(args: QueryArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        QueryCommand::Parse(parse) => {
            let query = Query::parse(&parse.query)?;
            let payload = RustParseOutput {
                raw: query.raw(),
                expr: query.expr(),
                analysis: query.analyze()?,
            };
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        QueryCommand::Suggest(suggest) => match suggest.engine {
            QueryEngine::Rust => {
                let query = Query::parse(&suggest.query)?;
                let payload = RustParseOutput {
                    raw: query.raw(),
                    expr: query.expr(),
                    analysis: query.analyze()?,
                };
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
            QueryEngine::Js => {
                let architectures = query_architecture_values();
                let collections = query_collection_values();
                let payload = json!({
                    "mode": "suggest",
                    "query": suggest.query,
                    "cursor": suggest.cursor.unwrap_or(suggest.query.len()),
                    "options": {
                        "architectures": architectures,
                        "collections": collections
                    }
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&run_node_query_cli(&payload)?)?
                );
            }
        },
        QueryCommand::Apply(apply) => {
            let architectures = query_architecture_values();
            let collections = query_collection_values();
            let payload = json!({
                "mode": "apply",
                "query": apply.query,
                "cursor": apply.cursor.unwrap_or(apply.query.len()),
                "item": {
                    "label": apply.item,
                    "kind": apply.kind,
                    "insert": apply.insert
                },
                "options": {
                    "architectures": architectures,
                    "collections": collections
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&run_node_query_cli(&payload)?)?
            );
        }
    }
    Ok(())
}

fn run_node_query_cli(
    payload: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut child = Command::new("node")
        .arg(query_cli_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(serde_json::to_string(payload)?.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!("node query CLI failed with status {}", output.status).into());
    }
    let mut stdout = String::new();
    stdout.push_str(std::str::from_utf8(&output.stdout)?);
    Ok(serde_json::from_str(&stdout)?)
}

fn query_cli_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../../..")
        .join("src/search/query_cli.js")
}
