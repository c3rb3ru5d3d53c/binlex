use base64::Engine;
use binlex::clients::Server;
use binlex::controlflow::Graph;
use binlex::indexing::{Collection, LocalIndex};
use binlex::server::analyze;
use binlex::server::dto::AnalyzeRequest;
use binlex::{Architecture, Config, Magic};
use clap::{Parser, Subcommand, ValueEnum};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Parser, Debug)]
pub struct PerfArgs {
    #[command(subcommand)]
    command: PerfCommand,
}

#[derive(Subcommand, Debug)]
enum PerfCommand {
    Analyze(AnalyzeArgs),
    IndexLocal(IndexLocalArgs),
    PipelineLocal(PipelineLocalArgs),
    PipelineRemote(PipelineRemoteArgs),
}

#[derive(Parser, Debug, Clone)]
struct AnalyzeArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    magic: Option<String>,
    #[arg(long)]
    architecture: Option<String>,
    #[arg(long, value_delimiter = ',', default_value = "default")]
    corpora: Vec<String>,
    #[arg(long, default_value_t = 1)]
    iterations: usize,
}

#[derive(Parser, Debug, Clone)]
struct IndexLocalArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    index_path: Option<PathBuf>,
    #[arg(long)]
    keep_index: bool,
    #[arg(long)]
    selector: Option<String>,
    #[arg(long, alias = "collection", value_enum, value_delimiter = ',', default_values_t = vec![PerfCollection::Function, PerfCollection::Block])]
    collections: Vec<PerfCollection>,
    #[arg(long, value_delimiter = ',', default_value = "default")]
    corpora: Vec<String>,
    #[arg(long, default_value = "anonymous")]
    username: String,
    #[arg(long)]
    dimensions: Option<usize>,
    #[arg(long)]
    magic: Option<String>,
    #[arg(long)]
    architecture: Option<String>,
    #[arg(long, default_value_t = 1)]
    iterations: usize,
}

#[derive(Parser, Debug, Clone)]
struct PipelineLocalArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    index_path: Option<PathBuf>,
    #[arg(long)]
    keep_index: bool,
    #[arg(long)]
    selector: Option<String>,
    #[arg(long, alias = "collection", value_enum, value_delimiter = ',', default_values_t = vec![PerfCollection::Function, PerfCollection::Block])]
    collections: Vec<PerfCollection>,
    #[arg(long, value_delimiter = ',', default_value = "default")]
    corpora: Vec<String>,
    #[arg(long, default_value = "anonymous")]
    username: String,
    #[arg(long)]
    dimensions: Option<usize>,
    #[arg(long)]
    magic: Option<String>,
    #[arg(long)]
    architecture: Option<String>,
    #[arg(long, default_value_t = 1)]
    iterations: usize,
}

#[derive(Parser, Debug, Clone)]
struct PipelineRemoteArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    index_path: Option<PathBuf>,
    #[arg(long)]
    keep_index: bool,
    #[arg(long)]
    selector: Option<String>,
    #[arg(long, alias = "collection", value_enum, value_delimiter = ',', default_values_t = vec![PerfCollection::Function, PerfCollection::Block])]
    collections: Vec<PerfCollection>,
    #[arg(long, value_delimiter = ',', default_value = "default")]
    corpora: Vec<String>,
    #[arg(long, default_value = "anonymous")]
    username: String,
    #[arg(long)]
    dimensions: Option<usize>,
    #[arg(long)]
    magic: Option<String>,
    #[arg(long)]
    architecture: Option<String>,
    #[arg(long)]
    server_url: Option<String>,
    #[arg(long)]
    insecure: bool,
    #[arg(long)]
    no_compression: bool,
    #[arg(long, default_value_t = 1)]
    iterations: usize,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PerfCollection {
    Function,
    Block,
    Instruction,
}

struct AnalysisOutcome {
    sha256: String,
    graph: Graph,
    analyze_elapsed: Duration,
}

struct IndexRoot {
    path: PathBuf,
    temp_dir: Option<TempDir>,
}

pub fn run(config: &Config, args: PerfArgs) -> Result<(), Box<dyn Error>> {
    match args.command {
        PerfCommand::Analyze(command) => run_analyze(config, &command),
        PerfCommand::IndexLocal(command) => run_index_local(config, &command),
        PerfCommand::PipelineLocal(command) => run_pipeline_local(config, &command),
        PerfCommand::PipelineRemote(command) => run_pipeline_remote(config, &command),
    }
}

fn run_analyze(config: &Config, args: &AnalyzeArgs) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(&args.input)?;
    let iterations = normalize_iterations(args.iterations);
    let mut durations = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let outcome = analyze_sample(
            config,
            &bytes,
            &normalize_corpora(&args.corpora),
            args.magic.as_deref(),
            args.architecture.as_deref(),
        )?;
        println!(
            "iteration={} mode=analyze sha256={} functions={} blocks={} instructions={} elapsed_ms={}",
            iteration + 1,
            outcome.sha256,
            outcome.graph.functions().len(),
            outcome.graph.blocks().len(),
            outcome.graph.instructions().len(),
            outcome.analyze_elapsed.as_millis()
        );
        durations.push(outcome.analyze_elapsed);
    }
    print_summary("analyze", &durations);
    Ok(())
}

fn run_index_local(config: &Config, args: &IndexLocalArgs) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(&args.input)?;
    let corpora = normalize_corpora(&args.corpora);
    let collections = normalize_collections(&args.collections);
    let selector = args
        .selector
        .clone()
        .unwrap_or_else(|| "processors.embeddings.vector".to_string());
    let iterations = normalize_iterations(args.iterations);
    let mut durations = Vec::with_capacity(iterations);
    let analysis = analyze_sample(
        config,
        &bytes,
        &corpora,
        args.magic.as_deref(),
        args.architecture.as_deref(),
    )?;
    println!(
        "prepared_graph sha256={} functions={} blocks={} instructions={} analyze_elapsed_ms={}",
        analysis.sha256,
        analysis.graph.functions().len(),
        analysis.graph.blocks().len(),
        analysis.graph.instructions().len(),
        analysis.analyze_elapsed.as_millis()
    );

    for iteration in 0..iterations {
        let mut iteration_config = config.clone();
        if let Some(dimensions) = args.dimensions {
            iteration_config.index.local.dimensions = Some(dimensions);
        }
        let root = resolve_index_root(args.index_path.as_deref(), iteration, args.keep_index)?;
        let _temp_dir = root.temp_dir;
        let index =
            LocalIndex::with_options(iteration_config, Some(root.path.clone()), args.dimensions)?;
        let started_at = Instant::now();
        index.sample_put(&bytes)?;
        index.graph_many_as(
            &corpora,
            &analysis.sha256,
            &analysis.graph,
            &[],
            Some(&selector),
            Some(&collections),
            &args.username,
        )?;
        index.commit()?;
        let elapsed = started_at.elapsed();
        println!(
            "iteration={} mode=index-local index_path={} sha256={} collections={:?} selector={} elapsed_ms={}",
            iteration + 1,
            root.path.display(),
            analysis.sha256,
            collections,
            selector,
            elapsed.as_millis()
        );
        durations.push(elapsed);
        if !args.keep_index && args.index_path.is_some() {
            let _ = fs::remove_dir_all(&root.path);
        }
    }
    print_summary("index-local", &durations);
    Ok(())
}

fn run_pipeline_local(config: &Config, args: &PipelineLocalArgs) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(&args.input)?;
    let corpora = normalize_corpora(&args.corpora);
    let collections = normalize_collections(&args.collections);
    let selector = args
        .selector
        .clone()
        .unwrap_or_else(|| "processors.embeddings.vector".to_string());
    let iterations = normalize_iterations(args.iterations);
    let mut durations = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let mut iteration_config = config.clone();
        if let Some(dimensions) = args.dimensions {
            iteration_config.index.local.dimensions = Some(dimensions);
        }
        let root = resolve_index_root(args.index_path.as_deref(), iteration, args.keep_index)?;
        let _temp_dir = root.temp_dir;
        let started_at = Instant::now();
        let analysis = analyze_sample(
            &iteration_config,
            &bytes,
            &corpora,
            args.magic.as_deref(),
            args.architecture.as_deref(),
        )?;
        let analyzed_at = Instant::now();
        let index =
            LocalIndex::with_options(iteration_config, Some(root.path.clone()), args.dimensions)?;
        index.sample_put(&bytes)?;
        index.graph_many_as(
            &corpora,
            &analysis.sha256,
            &analysis.graph,
            &[],
            Some(&selector),
            Some(&collections),
            &args.username,
        )?;
        index.commit()?;
        let elapsed = started_at.elapsed();
        println!(
            "iteration={} mode=pipeline-local index_path={} sha256={} analyze_elapsed_ms={} index_elapsed_ms={} total_elapsed_ms={}",
            iteration + 1,
            root.path.display(),
            analysis.sha256,
            analysis.analyze_elapsed.as_millis(),
            analyzed_at.elapsed().as_millis(),
            elapsed.as_millis()
        );
        durations.push(elapsed);
        if !args.keep_index && args.index_path.is_some() {
            let _ = fs::remove_dir_all(&root.path);
        }
    }
    print_summary("pipeline-local", &durations);
    Ok(())
}

fn run_pipeline_remote(config: &Config, args: &PipelineRemoteArgs) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(&args.input)?;
    let corpora = normalize_corpora(&args.corpora);
    let collections = normalize_collections(&args.collections);
    let selector = args
        .selector
        .clone()
        .unwrap_or_else(|| "processors.embeddings.vector".to_string());
    let iterations = normalize_iterations(args.iterations);
    let mut durations = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let mut iteration_config = config.clone();
        if let Some(dimensions) = args.dimensions {
            iteration_config.index.local.dimensions = Some(dimensions);
        }
        let root = resolve_index_root(args.index_path.as_deref(), iteration, args.keep_index)?;
        let _temp_dir = root.temp_dir;
        let started_at = Instant::now();
        let client = Server::new(
            iteration_config.clone(),
            args.server_url.clone(),
            Some(!args.insecure),
            Some(!args.no_compression),
        )?;
        let analyze_started_at = Instant::now();
        let graph = client.analyze_bytes_with_corpora(
            &bytes,
            parse_magic_option(args.magic.as_deref())?,
            parse_architecture_option(args.architecture.as_deref())?,
            &corpora,
        )?;
        let analyze_elapsed = analyze_started_at.elapsed();
        let sha256 = binlex::hashing::SHA256::new(&bytes)
            .hexdigest()
            .ok_or_else(|| std::io::Error::other("failed to compute sha256"))?;
        let index_started_at = Instant::now();
        let index =
            LocalIndex::with_options(iteration_config, Some(root.path.clone()), args.dimensions)?;
        index.sample_put(&bytes)?;
        index.graph_many_as(
            &corpora,
            &sha256,
            &graph,
            &[],
            Some(&selector),
            Some(&collections),
            &args.username,
        )?;
        index.commit()?;
        let elapsed = started_at.elapsed();
        println!(
            "iteration={} mode=pipeline-remote index_path={} server_url={} sha256={} functions={} blocks={} instructions={} remote_analyze_elapsed_ms={} local_index_elapsed_ms={} total_elapsed_ms={}",
            iteration + 1,
            root.path.display(),
            client.url(),
            sha256,
            graph.functions().len(),
            graph.blocks().len(),
            graph.instructions().len(),
            analyze_elapsed.as_millis(),
            index_started_at.elapsed().as_millis(),
            elapsed.as_millis()
        );
        durations.push(elapsed);
        if !args.keep_index && args.index_path.is_some() {
            let _ = fs::remove_dir_all(&root.path);
        }
    }
    print_summary("pipeline-remote", &durations);
    Ok(())
}

fn analyze_sample(
    config: &Config,
    bytes: &[u8],
    corpora: &[String],
    magic: Option<&str>,
    architecture: Option<&str>,
) -> Result<AnalysisOutcome, Box<dyn Error>> {
    let request = AnalyzeRequest {
        data: base64::engine::general_purpose::STANDARD.encode(bytes),
        magic: magic.map(ToOwned::to_owned),
        architecture: architecture.map(ToOwned::to_owned),
        corpora: corpora.to_vec(),
    };
    let started_at = Instant::now();
    let snapshot = analyze::execute(config, request)
        .map_err(|error| std::io::Error::other(format!("{:?}", error)))?;
    let analyze_elapsed = started_at.elapsed();
    let graph = Graph::from_snapshot(snapshot, config.clone())?;
    let sha256 = binlex::hashing::SHA256::new(bytes)
        .hexdigest()
        .ok_or_else(|| std::io::Error::other("failed to compute sha256"))?;
    Ok(AnalysisOutcome {
        sha256,
        graph,
        analyze_elapsed,
    })
}

fn parse_magic_option(value: Option<&str>) -> Result<Option<Magic>, Box<dyn Error>> {
    value
        .map(|value| value.parse::<Magic>())
        .transpose()
        .map_err(|error| Box::new(std::io::Error::other(error.to_string())) as Box<dyn Error>)
}

fn parse_architecture_option(value: Option<&str>) -> Result<Option<Architecture>, Box<dyn Error>> {
    value
        .map(Architecture::from_string)
        .transpose()
        .map_err(|error| Box::new(std::io::Error::other(error.to_string())) as Box<dyn Error>)
}

fn normalize_iterations(iterations: usize) -> usize {
    iterations.max(1)
}

fn normalize_corpora(values: &[String]) -> Vec<String> {
    let mut corpora = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if corpora.is_empty() {
        corpora.push("default".to_string());
    }
    corpora
}

fn normalize_collections(values: &[PerfCollection]) -> Vec<Collection> {
    values.iter().copied().map(Into::into).collect()
}

fn print_summary(label: &str, durations: &[Duration]) {
    if durations.is_empty() {
        return;
    }
    let total = durations.iter().copied().sum::<Duration>();
    let min = durations.iter().copied().min().unwrap_or_default();
    let max = durations.iter().copied().max().unwrap_or_default();
    let avg = total / durations.len() as u32;
    println!(
        "summary mode={} iterations={} min_ms={} avg_ms={} max_ms={} total_ms={}",
        label,
        durations.len(),
        min.as_millis(),
        avg.as_millis(),
        max.as_millis(),
        total.as_millis()
    );
}

fn resolve_index_root(
    base: Option<&Path>,
    iteration: usize,
    keep_index: bool,
) -> Result<IndexRoot, Box<dyn Error>> {
    if let Some(base) = base {
        let path = if keep_index && iteration == 0 {
            base.to_path_buf()
        } else {
            base.join(format!("iteration-{}", iteration + 1))
        };
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        return Ok(IndexRoot {
            path,
            temp_dir: None,
        });
    }
    let temp_dir = tempfile::Builder::new()
        .prefix("binlex-test-index-")
        .tempdir()?;
    let path = temp_dir.path().to_path_buf();
    Ok(IndexRoot {
        path,
        temp_dir: Some(temp_dir),
    })
}

impl From<PerfCollection> for Collection {
    fn from(value: PerfCollection) -> Self {
        match value {
            PerfCollection::Function => Collection::Function,
            PerfCollection::Block => Collection::Block,
            PerfCollection::Instruction => Collection::Instruction,
        }
    }
}
