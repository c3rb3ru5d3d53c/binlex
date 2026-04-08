fn parse_collection(value: &str) -> Option<Collection> {
    match value.trim().to_ascii_lowercase().as_str() {
        "instructions" => Some(Collection::Instruction),
        "blocks" => Some(Collection::Block),
        "functions" => Some(Collection::Function),
        _ => None,
    }
}
fn default_collections(config: &WebLocalIndexConfig) -> Vec<Collection> {
    let mut collections = Vec::new();
    if config.functions {
        collections.push(Collection::Function);
    }
    if config.blocks {
        collections.push(Collection::Block);
    }
    if config.instructions {
        collections.push(Collection::Instruction);
    }
    if collections.is_empty() {
        collections.push(Collection::Function);
    }
    collections
}

fn clamp_top_k(params: &mut PageParams) {
    params.top_k = Some(params.top_k.unwrap_or(DEFAULT_TOP_K).clamp(1, MAX_TOP_K));
}

fn clamp_page(params: &mut PageParams) {
    params.page = Some(params.page.unwrap_or(1).max(1));
}

fn clamp_search_request_top_k(params: &mut SearchRequest) {
    params.top_k = Some(params.top_k.unwrap_or(DEFAULT_TOP_K).clamp(1, MAX_TOP_K));
}

fn clamp_search_request_page(params: &mut SearchRequest) {
    params.page = Some(params.page.unwrap_or(1).max(1));
}

fn expand_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn parse_magic_override(value: Option<&str>) -> Option<Magic> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("PE") => Some(Magic::PE),
        Some("ELF") => Some(Magic::ELF),
        Some("Mach-O") => Some(Magic::MACHO),
        Some("Shellcode") => Some(Magic::CODE),
        _ => None,
    }
}

fn parse_architecture_override(value: Option<&str>) -> Option<Architecture> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("AMD64") => Some(Architecture::AMD64),
        Some("I386") => Some(Architecture::I386),
        Some("CIL") => Some(Architecture::CIL),
        _ => None,
    }
}
