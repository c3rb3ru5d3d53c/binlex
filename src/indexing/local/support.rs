use super::LocalIndex;
use super::types::{EntityMetrics, Error, IndexEntry, SearchResult};
use crate::Config;
use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::databases::localdb::normalize_metadata_name;
use crate::formats::SymbolJson;
use crate::indexing::{Collection, Entity};
use crate::metadata::{Attribute, SymbolType};
use crate::processor::ProcessorTarget;
use crate::query::{
    QueryExpr, QueryField, QueryTerm, SearchRoot, query_bool_matches, query_float_matches,
    query_integer_matches, query_score_matches, query_size_matches, query_timestamp_matches,
};
use chrono::{DateTime, SecondsFormat, Utc};
use ring::digest::{SHA256, digest};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
pub(super) fn resolve_root(directory: Option<PathBuf>, config: &Config) -> Result<PathBuf, Error> {
    let root = match directory {
        Some(directory) => directory,
        None => PathBuf::from(config.index.local.directory.clone()),
    };
    if root.as_os_str().is_empty() {
        return Err(Error::InvalidConfiguration("directory must not be empty"));
    }
    let root = expand_home_directory(root)?;
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()
            .map_err(|_| Error::InvalidConfiguration("failed to resolve current directory"))?
            .join(root)
    };
    if root.exists() && !root.is_dir() {
        return Err(Error::InvalidConfiguration(
            "directory must reference a directory path",
        ));
    }
    std::fs::create_dir_all(&root).map_err(|error| Error::LocalStore(error.to_string()))?;
    Ok(root)
}

pub(super) fn expand_home_directory(path: PathBuf) -> Result<PathBuf, Error> {
    let value = path.to_string_lossy();
    if value == "~" {
        return dirs::home_dir().ok_or(Error::InvalidConfiguration(
            "unable to resolve home directory",
        ));
    }
    if let Some(remainder) = value.strip_prefix("~/") {
        return dirs::home_dir()
            .ok_or(Error::InvalidConfiguration(
                "unable to resolve home directory",
            ))
            .map(|home| home.join(remainder));
    }
    Ok(path)
}

pub(super) fn accumulate_entry(
    entries: &mut BTreeMap<String, IndexEntry>,
    key: String,
    entity: Entity,
    architecture: &str,
    username: &str,
    object_id: String,
    sha256: &str,
    address: u64,
    size: u64,
    metrics: Option<&EntityMetrics>,
    vector: Vec<f32>,
    explicit_corpora: Option<&[String]>,
    attributes: &[Value],
    json: Option<Value>,
) {
    let entry = entries.entry(key).or_insert_with(|| IndexEntry {
        object_id,
        entity,
        architecture: architecture.to_string(),
        username: username.to_string(),
        sha256: sha256.to_string(),
        address,
        size,
        cyclomatic_complexity: None,
        average_instructions_per_block: None,
        number_of_instructions: None,
        number_of_blocks: None,
        markov: None,
        entropy: None,
        contiguous: None,
        chromosome_entropy: None,
        collection_tag_count: 0,
        collection_tags: Vec::new(),
        collection_comment_count: 0,
        vector: vector.clone(),
        timestamp: current_timestamp(),
        explicit_corpora: None,
        attributes: Vec::new(),
        json: None,
    });
    entry.entity = entity;
    entry.username = username.to_string();
    entry.sha256 = sha256.to_string();
    entry.address = address;
    entry.size = size;
    entry.cyclomatic_complexity = metrics.and_then(|metrics| metrics.cyclomatic_complexity);
    entry.average_instructions_per_block =
        metrics.and_then(|metrics| metrics.average_instructions_per_block);
    entry.number_of_instructions = metrics.and_then(|metrics| metrics.number_of_instructions);
    entry.number_of_blocks = metrics.and_then(|metrics| metrics.number_of_blocks);
    entry.markov = metrics.and_then(|metrics| metrics.markov);
    entry.entropy = metrics.and_then(|metrics| metrics.entropy);
    entry.contiguous = metrics.and_then(|metrics| metrics.contiguous);
    entry.chromosome_entropy = metrics.and_then(|metrics| metrics.chromosome_entropy);
    entry.explicit_corpora = explicit_corpora.map(unique_corpora);
    entry.attributes = attributes.to_vec();
    dedupe_attribute_values(&mut entry.attributes);
    entry.vector = vector;
    if json.is_some() {
        entry.json = json;
    }
}

pub(super) fn set_entity_corpora(
    entity_corpora: &mut BTreeMap<String, Vec<String>>,
    key: &str,
    corpora: &[String],
) {
    entity_corpora.insert(key.to_string(), unique_corpora(corpora));
}

pub(super) fn digest_hex(data: &[u8]) -> String {
    crate::hex::encode(digest(&SHA256, data).as_ref())
}

pub(super) fn page_search_results(
    mut hits: Vec<SearchResult>,
    offset: usize,
    limit: usize,
) -> Vec<SearchResult> {
    if offset >= hits.len() {
        return Vec::new();
    }
    let end = offset.saturating_add(limit).min(hits.len());
    hits.drain(offset..end).collect()
}

pub(super) fn embedding_id_for_vector(vector: &[f32]) -> String {
    let mut bytes = Vec::with_capacity(vector.len() * std::mem::size_of::<f32>());
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    digest_hex(&bytes)
}

pub(super) fn process_attributes(attributes: &[Attribute]) -> Option<Value> {
    if attributes.is_empty() {
        return None;
    }
    Some(Value::Array(
        attributes
            .iter()
            .map(Attribute::to_json_value)
            .collect::<Vec<_>>(),
    ))
}

pub(super) fn entity_metrics_for_block(block: &Block<'_>) -> EntityMetrics {
    let processed = block.process();
    EntityMetrics {
        number_of_blocks: None,
        number_of_instructions: Some(processed.number_of_instructions as u64),
        markov: None,
        entropy: processed.entropy,
        contiguous: Some(processed.contiguous),
        chromosome_entropy: processed.chromosome.entropy,
        ..EntityMetrics::default()
    }
}

pub(super) fn entity_metrics_for_function(function: &Function<'_>) -> EntityMetrics {
    let processed = function.process();
    EntityMetrics {
        cyclomatic_complexity: Some(processed.cyclomatic_complexity as u64),
        average_instructions_per_block: Some(processed.average_instructions_per_block),
        number_of_instructions: Some(processed.number_of_instructions as u64),
        number_of_blocks: Some(processed.number_of_blocks as u64),
        markov: None,
        entropy: processed.entropy,
        contiguous: Some(processed.contiguous),
        chromosome_entropy: processed
            .chromosome
            .as_ref()
            .and_then(|chromosome| chromosome.entropy),
    }
}

pub(super) struct SearchHitContext<'a> {
    pub(super) object_id: &'a str,
    pub(super) entity: Entity,
    pub(super) architecture: &'a str,
    pub(super) sha256: &'a str,
    pub(super) address: u64,
    pub(super) entry: &'a IndexEntry,
    pub(super) vector: &'a [f32],
    pub(super) score: f32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SearchHydration {
    Summary,
    Detail,
}

pub(super) fn build_search_result(
    _index: &LocalIndex,
    _cache: &mut BTreeMap<(String, String), Graph>,
    context: &SearchHitContext<'_>,
    corpora: &[String],
    symbol: Option<String>,
    hydration: SearchHydration,
) -> SearchResult {
    SearchResult {
        corpora: corpora.to_vec(),
        object_id: context.object_id.to_string(),
        entity: context.entity,
        architecture: context.architecture.to_string(),
        username: context.entry.username.clone(),
        sha256: context.sha256.to_string(),
        address: context.address,
        size: context.entry.size,
        cyclomatic_complexity: context.entry.cyclomatic_complexity,
        average_instructions_per_block: context.entry.average_instructions_per_block,
        number_of_instructions: context.entry.number_of_instructions,
        number_of_blocks: context.entry.number_of_blocks,
        markov: context.entry.markov,
        entropy: context.entry.entropy,
        contiguous: context.entry.contiguous,
        chromosome_entropy: context.entry.chromosome_entropy,
        collection_tag_count: context.entry.collection_tag_count,
        collection_tags: context.entry.collection_tags.clone(),
        collection_comment_count: context.entry.collection_comment_count,
        timestamp: context.entry.timestamp.clone(),
        symbol,
        attributes: context.entry.attributes.clone(),
        vector: context.vector.to_vec(),
        json: match hydration {
            SearchHydration::Summary => None,
            SearchHydration::Detail => context.entry.json.clone(),
        },
        embedding: String::new(),
        embeddings: 0,
        score: context.score,
    }
}

pub(super) fn push_search_hits(
    hits: &mut Vec<SearchResult>,
    index: &LocalIndex,
    cache: &mut BTreeMap<(String, String), Graph>,
    context: SearchHitContext<'_>,
    corpora: &[String],
    hydration: SearchHydration,
) {
    let symbols =
        symbol_names_for_attributes(&context.entry.attributes, context.entity, context.address);
    if symbols.is_empty() {
        hits.push(build_search_result(
            index, cache, &context, corpora, None, hydration,
        ));
        return;
    }
    for symbol in symbols {
        hits.push(build_search_result(
            index,
            cache,
            &context,
            corpora,
            Some(symbol),
            hydration,
        ));
    }
}

pub(super) fn symbol_type_matches_collection(symbol_type: &str, collection: Collection) -> bool {
    match collection {
        Collection::Instruction => symbol_type == SymbolType::Instruction.as_str(),
        Collection::Block => symbol_type == SymbolType::Block.as_str(),
        Collection::Function => symbol_type == SymbolType::Function.as_str(),
    }
}

pub(super) fn validate_corpus_sha256(corpus: &str, sha256: &str) -> Result<(), Error> {
    normalize_metadata_name("corpus", corpus)
        .map_err(|error| Error::Validation(error.to_string()))?;
    if sha256.trim().is_empty() {
        return Err(Error::InvalidConfiguration("sha256 must not be empty"));
    }
    Ok(())
}

pub(super) fn normalize_corpora(corpora: &[String]) -> Result<Vec<String>, Error> {
    let corpora = unique_corpora(
        &corpora
            .iter()
            .map(|corpus| normalize_metadata_name("corpus", corpus))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Error::Validation(error.to_string()))?,
    );
    if corpora.is_empty() {
        return Err(Error::InvalidConfiguration("corpora must not be empty"));
    }
    Ok(corpora)
}

pub(super) fn normalize_index_corpora(corpora: &[String]) -> Result<Vec<String>, Error> {
    normalize_corpora(corpora)
}

pub(super) fn corpus_match_score(corpus: &str, query: &str) -> usize {
    if query.is_empty() {
        return 1;
    }
    let corpus = corpus.to_ascii_lowercase();
    if corpus == query {
        return 10_000;
    }
    if corpus.starts_with(query) {
        return 8_000usize.saturating_sub(corpus.len());
    }
    if corpus.contains(query) {
        return 6_000usize.saturating_sub(corpus.len());
    }
    fuzzy_subsequence_score(&corpus, query)
}

pub(super) fn fuzzy_subsequence_score(haystack: &str, needle: &str) -> usize {
    let mut score = 0usize;
    let mut streak = 0usize;
    let mut chars = haystack.char_indices();
    let mut last_index = None;
    for needle_char in needle.chars() {
        let mut matched = false;
        for (index, hay_char) in chars.by_ref() {
            if hay_char != needle_char {
                streak = 0;
                continue;
            }
            matched = true;
            streak += 1;
            score += 10 + streak * 4;
            if let Some(previous) = last_index {
                if index == previous + 1 {
                    score += 8;
                }
            }
            last_index = Some(index);
            break;
        }
        if !matched {
            return 0;
        }
    }
    score.saturating_sub(haystack.len())
}

pub(super) fn union_corpora(lhs: &[String], rhs: &[String]) -> Vec<String> {
    let mut merged = lhs.to_vec();
    merged.extend_from_slice(rhs);
    unique_corpora(&merged)
}

pub(super) fn prune_pending_entries_for_sample(
    entries: &mut BTreeMap<String, IndexEntry>,
    entity_corpora: &mut BTreeMap<String, Vec<String>>,
    sha256: &str,
    corpus: &str,
) {
    entries.retain(|key, entry| {
        let _ = remove_corpus_from_entry(entry, Some(corpus));
        if let Some(corpora) = entity_corpora.get_mut(key) {
            corpora.retain(|existing| existing != corpus);
            if corpora.is_empty() && entry.explicit_corpora.is_none() && entry.sha256 == sha256 {
                entity_corpora.remove(key);
                return false;
            }
        }
        true
    });
}

pub(super) fn prune_pending_entries_for_corpus(
    entries: &mut BTreeMap<String, IndexEntry>,
    entity_corpora: &mut BTreeMap<String, Vec<String>>,
    corpus: &str,
) {
    entries.retain(|key, entry| {
        let _ = remove_corpus_from_entry(entry, Some(corpus));
        if let Some(corpora) = entity_corpora.get_mut(key) {
            corpora.retain(|existing| existing != corpus);
            if corpora.is_empty() && entry.explicit_corpora.is_none() {
                entity_corpora.remove(key);
                return false;
            }
        }
        true
    });
}

pub(super) fn remove_corpus_from_entry(entry: &mut IndexEntry, corpus: Option<&str>) -> bool {
    let before = entry.explicit_corpora.clone();
    if let Some(corpus) = corpus {
        if let Some(explicit) = &mut entry.explicit_corpora {
            explicit.retain(|existing| existing != corpus);
            if explicit.is_empty() {
                entry.explicit_corpora = None;
            }
        }
    }
    entry.explicit_corpora != before
}

pub(super) fn current_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(super) fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|date| date.with_timezone(&Utc))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SymbolMutation {
    Add,
    Remove,
    Replace,
}

pub(super) fn resolve_query_corpora(
    index: &LocalIndex,
    requested: &[String],
) -> Result<Vec<String>, Error> {
    if !requested.is_empty() {
        return Ok(requested.to_vec());
    }
    index.corpus_list()
}

pub(super) fn search_expr_matches(
    result: &SearchResult,
    expr: &QueryExpr,
    root: &Option<SearchRoot>,
) -> bool {
    match expr {
        QueryExpr::Term(term) => search_term_matches(result, term, root),
        QueryExpr::Not(inner) => !search_expr_matches(result, inner, root),
        QueryExpr::And(lhs, rhs) => {
            search_expr_matches(result, lhs, root) && search_expr_matches(result, rhs, root)
        }
        QueryExpr::Or(lhs, rhs) => {
            search_expr_matches(result, lhs, root) || search_expr_matches(result, rhs, root)
        }
    }
}

pub(super) fn search_term_matches(
    result: &SearchResult,
    term: &QueryTerm,
    root: &Option<SearchRoot>,
) -> bool {
    let value = term.value.trim();
    match term.field {
        QueryField::Sha256 => result.sha256().eq_ignore_ascii_case(value),
        QueryField::Embedding => result.embedding().eq_ignore_ascii_case(value),
        QueryField::Embeddings => count_query_matches(value, result.embeddings()),
        QueryField::Vector => matches!(root, Some(SearchRoot::Vector(_))),
        QueryField::Score => query_score_matches(value, result.score()),
        QueryField::Corpus => result
            .corpora()
            .iter()
            .any(|corpus| corpus.eq_ignore_ascii_case(value)),
        QueryField::Collection => result.collection().as_str().eq_ignore_ascii_case(value),
        QueryField::Architecture => result.architecture().eq_ignore_ascii_case(value),
        QueryField::Username => result.username().eq_ignore_ascii_case(value),
        QueryField::Address => parse_query_address(value) == Some(result.address()),
        QueryField::Timestamp => query_timestamp_matches(value, result.timestamp()),
        QueryField::Size => query_size_matches(value, result.size()),
        QueryField::Symbol => {
            result
                .attributes()
                .iter()
                .filter_map(|attribute| matching_symbol_name(result, attribute))
                .map(|symbol| symbol_match_score(&symbol, value))
                .max()
                .unwrap_or(0)
                > 0
        }
        QueryField::Tag => result
            .collection_tags()
            .iter()
            .any(|tag| tag.eq_ignore_ascii_case(value)),
        QueryField::Symbols => query_integer_matches(value, result.symbol_count()),
        QueryField::Tags => query_integer_matches(value, result.collection_tag_count()),
        QueryField::Comments => query_integer_matches(value, result.collection_comment_count()),
        QueryField::CyclomaticComplexity => {
            result.collection() != Collection::Function
                || result
                    .cyclomatic_complexity()
                    .map(|actual| query_integer_matches(value, actual))
                    .unwrap_or(false)
        }
        QueryField::AverageInstructionsPerBlock => {
            result.collection() != Collection::Function
                || result
                    .average_instructions_per_block()
                    .map(|actual| query_float_matches(value, actual))
                    .unwrap_or(false)
        }
        QueryField::NumberOfInstructions => result
            .number_of_instructions()
            .map(|actual| query_integer_matches(value, actual))
            .unwrap_or(false),
        QueryField::NumberOfBlocks => {
            result.collection() != Collection::Function
                || result
                    .number_of_blocks()
                    .map(|actual| query_integer_matches(value, actual))
                    .unwrap_or(false)
        }
        QueryField::Markov => {
            result.collection() != Collection::Block
                || result
                    .markov()
                    .map(|actual| query_float_matches(value, actual))
                    .unwrap_or(false)
        }
        QueryField::Entropy => result
            .entropy()
            .map(|actual| query_float_matches(value, actual))
            .unwrap_or(false),
        QueryField::Contiguous => result
            .contiguous()
            .map(|actual| query_bool_matches(value, actual))
            .unwrap_or(false),
        QueryField::ChromosomeEntropy => result
            .chromosome_entropy()
            .map(|actual| query_float_matches(value, actual))
            .unwrap_or(false),
    }
}

fn matching_symbol_name(result: &SearchResult, attribute: &Value) -> Option<String> {
    let object = attribute.as_object()?;
    if object.get("type")?.as_str()? != "symbol" {
        return None;
    }
    let symbol_type = object.get("symbol_type")?.as_str()?;
    if !symbol_type_matches_collection(symbol_type, result.collection()) {
        return None;
    }
    let symbol_address = object.get("address")?.as_u64()?;
    if symbol_address != result.address() {
        return None;
    }
    object.get("name")?.as_str().map(str::to_string)
}

fn symbol_match_score(symbol: &str, query: &str) -> usize {
    let symbol = symbol.trim().to_ascii_lowercase();
    let query = query.trim().to_ascii_lowercase();
    if symbol.is_empty() || query.is_empty() {
        return 0;
    }
    if symbol == query {
        return 20_000;
    }
    if symbol.starts_with(&query) {
        return 16_000usize.saturating_sub(symbol.len());
    }
    if symbol.contains(&query) {
        return 12_000usize.saturating_sub(symbol.len());
    }
    fuzzy_subsequence_score(&symbol, &query)
}

pub(super) fn parse_query_address(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

pub(super) fn count_query_matches(raw: &str, actual: u64) -> bool {
    let Some((operator, expected)) = parse_count_query(raw) else {
        return false;
    };
    match operator {
        CountOperator::Eq => actual == expected,
        CountOperator::Gt => actual > expected,
        CountOperator::Gte => actual >= expected,
        CountOperator::Lt => actual < expected,
        CountOperator::Lte => actual <= expected,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CountOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

pub(super) fn parse_count_query(raw: &str) -> Option<(CountOperator, u64)> {
    let trimmed = raw.trim();
    let (operator, remainder) = if let Some(value) = trimmed.strip_prefix(">=") {
        (CountOperator::Gte, value)
    } else if let Some(value) = trimmed.strip_prefix("<=") {
        (CountOperator::Lte, value)
    } else if let Some(value) = trimmed.strip_prefix('>') {
        (CountOperator::Gt, value)
    } else if let Some(value) = trimmed.strip_prefix('<') {
        (CountOperator::Lt, value)
    } else if let Some(value) = trimmed.strip_prefix('=') {
        (CountOperator::Eq, value)
    } else {
        (CountOperator::Eq, trimmed)
    };
    parse_compact_count(remainder).map(|value| (operator, value))
}

pub(super) fn parse_compact_count(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, multiplier) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1_000f64),
        Some('m') => (&lower[..lower.len() - 1], 1_000_000f64),
        Some('b') => (&lower[..lower.len() - 1], 1_000_000_000f64),
        _ => (lower.as_str(), 1f64),
    };
    let value = number.trim().parse::<f64>().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let scaled = value * multiplier;
    if scaled > u64::MAX as f64 {
        return None;
    }
    Some(scaled.round() as u64)
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn mutate_symbol_attributes(
    attributes: &mut Vec<Value>,
    entity: Entity,
    address: u64,
    name: &str,
    username: &str,
    timestamp: &str,
    mutation: SymbolMutation,
) -> (bool, bool) {
    let symbol_value = symbol_attribute_value(name, entity, address, username, timestamp);
    let had_symbol = symbol_names_for_attributes(attributes, entity, address)
        .iter()
        .any(|existing| existing == name);
    match mutation {
        SymbolMutation::Add => {
            if had_symbol {
                return (false, true);
            }
            attributes.push(symbol_value);
            dedupe_attribute_values(attributes);
            (true, had_symbol)
        }
        SymbolMutation::Remove => {
            let before = attributes.len();
            attributes.retain(|attribute| {
                !symbol_attribute_matches(attribute, entity, address, Some(name))
            });
            (attributes.len() != before, had_symbol)
        }
        SymbolMutation::Replace => {
            let before = attributes.clone();
            attributes
                .retain(|attribute| !symbol_attribute_matches(attribute, entity, address, None));
            attributes.push(symbol_value);
            dedupe_attribute_values(attributes);
            (*attributes != before, had_symbol)
        }
    }
}

pub(super) fn symbol_attribute_matches(
    value: &Value,
    entity: Entity,
    address: u64,
    name: Option<&str>,
) -> bool {
    let object = match value.as_object() {
        Some(object) => object,
        None => return false,
    };
    if object.get("type").and_then(Value::as_str) != Some("symbol") {
        return false;
    }
    if !symbol_type_matches_collection(
        object
            .get("symbol_type")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        entity,
    ) {
        return false;
    }
    if object.get("address").and_then(Value::as_u64) != Some(address) {
        return false;
    }
    match name {
        Some(expected) => object.get("name").and_then(Value::as_str) == Some(expected),
        None => true,
    }
}

pub(super) fn symbol_attribute_value(
    name: &str,
    entity: Entity,
    address: u64,
    username: &str,
    timestamp: &str,
) -> Value {
    Attribute::Symbol(SymbolJson {
        type_: "symbol".to_string(),
        symbol_type: match entity {
            Collection::Instruction => SymbolType::Instruction,
            Collection::Block => SymbolType::Block,
            Collection::Function => SymbolType::Function,
        }
        .to_string(),
        name: name.to_string(),
        address,
        username: username.to_string(),
        timestamp: timestamp.to_string(),
    })
    .to_json_value()
}

pub(super) fn instruction_selector_vector(
    graph: &Graph,
    instruction: &Instruction,
    selector: &str,
    processor_selector: Option<(&str, &str)>,
) -> Result<Option<Vec<f32>>, Error> {
    if let Some((processor_name, output_selector)) = processor_selector {
        return Ok(processor_output_vector(
            graph,
            ProcessorTarget::Instruction,
            instruction.address,
            processor_name,
            output_selector,
        ));
    }
    let processed = serde_json::to_value(instruction.process())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    Ok(selector_vector(&processed, selector))
}

pub(super) fn block_selector_vector(
    graph: &Graph,
    block: &Block<'_>,
    selector: &str,
    processor_selector: Option<(&str, &str)>,
) -> Result<Option<Vec<f32>>, Error> {
    if let Some((processor_name, output_selector)) = processor_selector {
        return Ok(processor_output_vector(
            graph,
            ProcessorTarget::Block,
            block.address(),
            processor_name,
            output_selector,
        ));
    }
    let processed = serde_json::to_value(block.process())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    Ok(selector_vector(&processed, selector))
}

pub(super) fn function_selector_vector(
    graph: &Graph,
    function: &Function<'_>,
    selector: &str,
    processor_selector: Option<(&str, &str)>,
) -> Result<Option<Vec<f32>>, Error> {
    if let Some((processor_name, output_selector)) = processor_selector {
        return Ok(processor_output_vector(
            graph,
            ProcessorTarget::Function,
            function.address,
            processor_name,
            output_selector,
        ));
    }
    let processed = serde_json::to_value(function.process())
        .map_err(|error| Error::Serialization(error.to_string()))?;
    Ok(selector_vector(&processed, selector))
}

pub(super) fn processor_selector(selector: &str) -> Option<(&str, &str)> {
    let remainder = selector.strip_prefix("processors.")?;
    let (processor_name, output_selector) = remainder.split_once('.')?;
    if processor_name.is_empty() || output_selector.is_empty() {
        return None;
    }
    Some((processor_name, output_selector))
}

pub(super) fn processor_output_vector(
    graph: &Graph,
    target: ProcessorTarget,
    address: u64,
    processor_name: &str,
    output_selector: &str,
) -> Option<Vec<f32>> {
    if graph
        .processor_output(target, address, processor_name)
        .is_none()
        && !crate::processor::enabled_processors_for_target(&graph.config, ProcessorTarget::Graph)
            .is_empty()
    {
        let _ = graph.process_graph();
    }
    let output = graph.processor_output(target, address, processor_name)?;
    selector_vector(&output, output_selector)
}

pub(super) fn selector_value<'a>(value: &'a Value, selector: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in selector.split('.') {
        if part.is_empty() {
            return None;
        }
        let mut remainder = part;
        let key_end = remainder.find('[').unwrap_or(remainder.len());
        if key_end > 0 {
            current = current.get(&remainder[..key_end])?;
            remainder = &remainder[key_end..];
        }
        while !remainder.is_empty() {
            let Some(after_open) = remainder.strip_prefix('[') else {
                return None;
            };
            let close = after_open.find(']')?;
            let index = after_open[..close].parse::<usize>().ok()?;
            current = current.get(index)?;
            remainder = &after_open[close + 1..];
        }
    }
    Some(current)
}

pub(super) fn selector_vector(value: &Value, selector: &str) -> Option<Vec<f32>> {
    let vector = selector_value(value, selector)?.as_array()?;
    vector
        .iter()
        .map(|value| value.as_f64().map(|item| item as f32))
        .collect()
}

pub(super) fn object_id_for_value(entity: Entity, value: &Value) -> String {
    format!(
        "{}:{}",
        entity.as_str(),
        digest_hex(value.to_string().as_bytes())
    )
}

pub(super) fn manual_object_id(
    entity: Entity,
    architecture: &str,
    sha256: &str,
    address: u64,
) -> String {
    object_id_for_value(
        entity,
        &serde_json::json!({
            "architecture": architecture,
            "sha256": sha256,
            "address": address,
        }),
    )
}

pub(super) fn sample_key(sha256: &str) -> String {
    format!("samples/{0}/{0}", sha256)
}

pub(super) fn graph_key(sha256: &str) -> String {
    format!("samples/{0}/{0}.graph.json", sha256)
}

pub(super) fn index_entry_key(entity: Entity, architecture: &str, object_id: &str) -> String {
    format!(
        "index/{}/{}/{}.json",
        entity.as_str(),
        architecture,
        object_id
    )
}

pub(super) fn architecture_from_index_entry_key(key: &str) -> Option<String> {
    let remainder = key.strip_prefix("index/")?;
    let (_, remainder) = remainder.split_once('/')?;
    let (architecture, _) = remainder.split_once('/')?;
    Some(architecture.to_string())
}

pub(super) fn unique_corpora(items: &[String]) -> Vec<String> {
    let mut values = items.to_vec();
    values.sort();
    values.dedup();
    values
}

pub(super) fn unique_samples(items: &[(String, String)]) -> Vec<(String, String)> {
    let mut values = items.to_vec();
    values.sort();
    values.dedup();
    values
}

pub(super) fn dedupe_attribute_values(values: &mut Vec<Value>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.to_string()));
}

pub(super) fn symbol_names_for_attributes(
    attributes: &[Value],
    entity: Entity,
    address: u64,
) -> Vec<String> {
    let mut symbols = attributes
        .iter()
        .filter_map(|attribute| {
            let object = attribute.as_object()?;
            if object.get("type")?.as_str()? != "symbol" {
                return None;
            }
            if object.get("name")?.as_str()?.is_empty() {
                return None;
            }
            let symbol_type = object.get("symbol_type")?.as_str()?;
            if !symbol_type_matches_collection(symbol_type, entity) {
                return None;
            }
            let symbol_address = object.get("address")?.as_u64()?;
            if symbol_address != address {
                return None;
            }
            Some(object.get("name")?.as_str()?.to_string())
        })
        .collect::<Vec<_>>();
    symbols.sort();
    symbols.dedup();
    symbols
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolAttribution {
    pub name: String,
    pub username: String,
    pub timestamp: String,
}
