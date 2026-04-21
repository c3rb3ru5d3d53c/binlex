fn configure_analysis_embeddings(config: &mut Config, ui: &BinlexWebConfig) {
    if ui.index.local.selector != "embeddings.llvm.vector" {
        return;
    }
    if ui.index.local.instructions {
        config.instructions.embeddings.llvm.enabled = true;
    }
    if ui.index.local.blocks {
        config.blocks.embeddings.llvm.enabled = true;
    }
    if ui.index.local.functions {
        config.functions.embeddings.llvm.enabled = true;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut config = WebConfigFile::load()?;
    if let Some(listen) = args.listen {
        config.binlex_web.listen = listen;
    }
    if let Some(port) = args.port {
        config.binlex_web.port = port;
    }
    if let Some(url) = args.url {
        config.binlex_web.url = url;
    }
    if let Some(server) = args.server {
        config.binlex_web.server_url = server;
    }

    tracing_subscriber::fmt().with_target(false).init();
    info!(
        "binlex-web starting bind={} server_url={} default_corpus={} index_path={} index_selector={} compare_limit={} ascending_limit={} collections=functions:{} blocks:{} instructions:{} upload_corpora_lock={}",
        format!("{}:{}", config.binlex_web.listen, config.binlex_web.port),
        config.binlex_web.server_url,
        config.binlex_web.index.local.default_corpus,
        config.binlex_web.index.local.path,
        config.binlex_web.index.local.selector,
        config.binlex_web.compare.limit,
        config.binlex_web.compare.ascending_limit,
        config.binlex_web.index.local.functions,
        config.binlex_web.index.local.blocks,
        config.binlex_web.index.local.instructions,
        config.binlex_web.index.local.lock_corpora
    );

    let mut analysis_config = Config::default();
    analysis_config.index.local.dimensions = Some(64);
    configure_analysis_embeddings(&mut analysis_config, &config.binlex_web);
    let index_root = PathBuf::from(expand_path(&config.binlex_web.index.local.path));
    let client = Server::new(
        analysis_config.clone(),
        Some(config.binlex_web.server_url.clone()),
        Some(false),
        Some(true),
    )
    .map_err(|error| Error::other(error.to_string()))?;
    let index = LocalIndex::with_options(
        analysis_config.clone(),
        Some(index_root.clone()),
        analysis_config.index.local.dimensions,
    )
    .map_err(|error| Error::other(error.to_string()))?;
    let database =
        Arc::new(LocalDB::new(&analysis_config).map_err(|error| Error::other(error.to_string()))?);

    let state = Arc::new(AppState {
        ui: config.binlex_web.clone(),
        client,
        index,
        database,
        analysis_config,
        index_root,
        staged_indexes: Arc::new(Mutex::new(BTreeMap::new())),
    });

    let bind: SocketAddr = format!("{}:{}", config.binlex_web.listen, config.binlex_web.port)
        .parse()
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
    info!("binlex-web listening on {}", bind);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        run_server(state, bind).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
