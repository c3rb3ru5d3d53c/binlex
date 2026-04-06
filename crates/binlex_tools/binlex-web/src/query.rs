use binlex::Architecture;
use binlex::indexing::local;
use binlex::indexing::{Collection, LocalIndex, SearchResult};
use binlex::search::{
    Query, QueryCollection, QueryError, QueryExpr, QueryField, QueryTerm, query_bool_matches,
    query_float_matches, query_integer_matches, query_score_matches, query_size_matches,
    query_timestamp_matches,
};

pub use binlex::search::SearchRoot;

#[derive(Clone, Debug)]
pub enum StreamPlan {
    Search(SearchPlan),
    Compare {
        left: Box<StreamPlan>,
        right: Box<StreamPlan>,
        direction: CompareDirection,
    },
    Pipe {
        input: Box<StreamPlan>,
        op: StreamOp,
    },
}

#[derive(Clone, Debug)]
pub struct SearchPlan {
    pub query: Query,
    pub root: Option<SearchRoot>,
    pub corpora: Vec<String>,
    pub collections: Vec<Collection>,
    pub architectures: Vec<Architecture>,
    pub side: QuerySide,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuerySide {
    Lhs,
    Rhs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareDirection {
    BestPerLeft,
    BestPerRight,
}

#[derive(Clone, Debug)]
pub enum StreamOp {
    ScoreFilter(String),
    Limit(usize),
    Ascending(SortKey),
    Descending(SortKey),
    Drop(QuerySide),
    Expand(ExpandTarget),
    SearchFilter(Query),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    Score,
    Size,
    Embeddings,
    Address,
    Timestamp,
    CyclomaticComplexity,
    AverageInstructionsPerBlock,
    NumberOfInstructions,
    NumberOfBlocks,
    Markov,
    Entropy,
    ChromosomeEntropy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandTarget {
    Blocks,
    Instructions,
}

pub fn build_query_plan(
    index: &LocalIndex,
    default_corpus: &str,
    default_collections: &[Collection],
    query: &str,
) -> Result<StreamPlan, QueryError> {
    parse_stream_plan(index, default_corpus, default_collections, query.trim())
}

fn parse_stream_plan(
    index: &LocalIndex,
    default_corpus: &str,
    default_collections: &[Collection],
    raw: &str,
) -> Result<StreamPlan, QueryError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(QueryError("enter a search query".to_string()));
    }

    let stripped = strip_wrapping_parens(raw);
    if stripped.len() != raw.len() {
        return parse_stream_plan(index, default_corpus, default_collections, stripped);
    }

    if let Some((lhs_raw, rhs_raw, direction)) = split_directional_compare(raw)? {
        return Ok(StreamPlan::Compare {
            left: Box::new(parse_stream_plan(
                index,
                default_corpus,
                default_collections,
                &lhs_raw,
            )?),
            right: Box::new(parse_stream_plan(
                index,
                default_corpus,
                default_collections,
                &rhs_raw,
            )?),
            direction,
        });
    }

    if let Some((group_raw, tail_raw)) = split_group_tail(raw)? {
        let mut plan = parse_stream_plan(index, default_corpus, default_collections, &group_raw)?;
        for stage in split_top_level_pipe_stages(&tail_raw)? {
            plan = StreamPlan::Pipe {
                input: Box::new(plan),
                op: parse_stream_op(&stage)?,
            };
        }
        return Ok(plan);
    }

    let stages = split_top_level_pipe_stages(raw)?;
    if stages.len() > 1 {
        let mut root_plan =
            build_search_plan(index, default_corpus, default_collections, &stages[0])?;
        let mut plan = StreamPlan::Search(root_plan.clone());
        let mut can_fold_root_filters = true;
        for stage in stages.into_iter().skip(1) {
            let op = parse_stream_op(&stage)?;
            if can_fold_root_filters {
                if let StreamOp::SearchFilter(query) = &op {
                    if fold_root_search_filter(&mut root_plan, query)? {
                        plan = rebuild_root_search_plan(plan, root_plan.clone());
                        continue;
                    }
                    validate_query_fields_for_collections(query.expr(), &root_plan.collections)?;
                }
            }
            if !matches!(op, StreamOp::SearchFilter(_)) {
                can_fold_root_filters = false;
            }
            plan = StreamPlan::Pipe {
                input: Box::new(plan),
                op,
            };
        }
        return Ok(plan);
    }

    Ok(StreamPlan::Search(build_search_plan(
        index,
        default_corpus,
        default_collections,
        raw,
    )?))
}

pub fn build_search_plan(
    index: &LocalIndex,
    default_corpus: &str,
    default_collections: &[Collection],
    query: &str,
) -> Result<SearchPlan, QueryError> {
    let query = Query::parse(query)?;
    let analysis = query.analyze()?;
    let corpora = resolve_corpora(index, &analysis.corpora, default_corpus)
        .map_err(|error| QueryError(error.to_string()))?;
    let collections = if analysis.collections.is_empty() {
        default_collections.to_vec()
    } else {
        analysis
            .collections
            .iter()
            .copied()
            .map(map_collection)
            .collect()
    };
    validate_query_fields_for_collections(query.expr(), &collections)?;
    Ok(SearchPlan {
        root: analysis.root,
        corpora,
        collections,
        architectures: analysis.architectures,
        query,
        side: QuerySide::Lhs,
    })
}

pub fn search_expr_matches(
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

fn resolve_corpora(
    index: &LocalIndex,
    requested: &[String],
    default_corpus: &str,
) -> Result<Vec<String>, local::Error> {
    if !requested.is_empty() {
        return Ok(requested.to_vec());
    }
    let corpora = index.corpus_list()?;
    if corpora.is_empty() {
        return Ok(vec![default_corpus.to_string()]);
    }
    Ok(corpora)
}

fn split_directional_compare(
    query: &str,
) -> Result<Option<(String, String, CompareDirection)>, QueryError> {
    let chars = query.char_indices().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut vector_depth = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    while index < chars.len() {
        let (offset, ch) = chars[index];
        if in_quotes {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            index += 1;
            continue;
        }
        match ch {
            '"' => in_quotes = true,
            '[' => vector_depth += 1,
            ']' => vector_depth = vector_depth.saturating_sub(1),
            '(' if vector_depth == 0 => depth += 1,
            ')' if vector_depth == 0 => depth = depth.saturating_sub(1),
            '-' if depth == 0 && vector_depth == 0 => {
                if index + 1 < chars.len() && chars[index + 1].1 == '>' {
                    let lhs = query[..offset].trim();
                    let rhs = query[chars[index + 1].0 + '>'.len_utf8()..].trim();
                    if lhs.is_empty() || rhs.is_empty() {
                        return Err(QueryError(
                            "directional compares must include a left and right query".to_string(),
                        ));
                    }
                    return Ok(Some((
                        lhs.to_string(),
                        rhs.to_string(),
                        CompareDirection::BestPerLeft,
                    )));
                }
            }
            '<' if depth == 0 && vector_depth == 0 => {
                if index + 1 < chars.len() && chars[index + 1].1 == '-' {
                    let lhs = query[..offset].trim();
                    let rhs = query[chars[index + 1].0 + '-'.len_utf8()..].trim();
                    if lhs.is_empty() || rhs.is_empty() {
                        return Err(QueryError(
                            "directional compares must include a left and right query".to_string(),
                        ));
                    }
                    return Ok(Some((
                        lhs.to_string(),
                        rhs.to_string(),
                        CompareDirection::BestPerRight,
                    )));
                }
            }
            _ => {}
        }
        index += 1;
    }
    if in_quotes || depth != 0 || vector_depth != 0 {
        return Err(QueryError(
            "queries must use balanced parentheses, quotes, and vectors".to_string(),
        ));
    }
    Ok(None)
}

fn split_group_tail(query: &str) -> Result<Option<(String, String)>, QueryError> {
    let query = query.trim();
    if !query.starts_with('(') {
        return Ok(None);
    }
    let Some(close_index) = find_matching_group_close(query)? else {
        return Ok(None);
    };
    if close_index == query.len() - 1 {
        return Ok(None);
    }
    let remainder = query[close_index + ')'.len_utf8()..].trim_start();
    if !remainder.starts_with('|') {
        return Ok(None);
    }
    Ok(Some((
        query[1..close_index].trim().to_string(),
        remainder.to_string(),
    )))
}

fn find_matching_group_close(query: &str) -> Result<Option<usize>, QueryError> {
    let mut depth = 0usize;
    let mut vector_depth = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (index, ch) in query.char_indices() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            continue;
        }
        match ch {
            '"' => in_quotes = true,
            '[' => vector_depth += 1,
            ']' => vector_depth = vector_depth.saturating_sub(1),
            '(' if vector_depth == 0 => depth += 1,
            ')' if vector_depth == 0 => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(Some(index));
                }
            }
            _ => {}
        }
    }
    if in_quotes || depth != 0 || vector_depth != 0 {
        return Err(QueryError(
            "queries must use balanced parentheses, quotes, and vectors".to_string(),
        ));
    }
    Ok(None)
}

fn strip_wrapping_parens(raw: &str) -> &str {
    let mut current = raw.trim();
    loop {
        if !(current.starts_with('(') && current.ends_with(')')) {
            return current;
        }
        let mut depth = 0usize;
        let mut vector_depth = 0usize;
        let mut in_quotes = false;
        let mut escaped = false;
        let mut encloses = true;
        for (index, ch) in current.char_indices() {
            if in_quotes {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_quotes = false;
                }
                continue;
            }
            match ch {
                '"' => in_quotes = true,
                '[' => vector_depth += 1,
                ']' => vector_depth = vector_depth.saturating_sub(1),
                '(' if vector_depth == 0 => depth += 1,
                ')' if vector_depth == 0 => {
                    if depth == 0 {
                        encloses = false;
                        break;
                    }
                    depth -= 1;
                    if depth == 0 && index != current.len() - 1 {
                        encloses = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !encloses || depth != 0 || vector_depth != 0 || in_quotes {
            return current;
        }
        current = current[1..current.len() - 1].trim();
    }
}

fn split_top_level_pipe_stages(raw: &str) -> Result<Vec<String>, QueryError> {
    let mut stages = Vec::new();
    let mut current = String::new();
    let chars = raw.char_indices().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut vector_depth = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    while index < chars.len() {
        let (_, ch) = chars[index];
        if in_quotes {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            index += 1;
            continue;
        }
        match ch {
            '"' => {
                in_quotes = true;
                current.push(ch);
            }
            '[' => {
                vector_depth += 1;
                current.push(ch);
            }
            ']' => {
                vector_depth = vector_depth.saturating_sub(1);
                current.push(ch);
            }
            '(' if vector_depth == 0 => {
                depth += 1;
                current.push(ch);
            }
            ')' if vector_depth == 0 => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            '|' if depth == 0 && vector_depth == 0 => {
                if index + 1 < chars.len() && chars[index + 1].1 == '|' {
                    current.push('|');
                    current.push('|');
                    index += 2;
                    continue;
                }
                let stage = current.trim();
                if !stage.is_empty() {
                    stages.push(stage.to_string());
                }
                current.clear();
                index += 1;
                continue;
            }
            _ => current.push(ch),
        }
        index += 1;
    }
    if in_quotes || depth != 0 || vector_depth != 0 {
        return Err(QueryError(
            "queries must use balanced parentheses, quotes, and vectors".to_string(),
        ));
    }
    let stage = current.trim();
    if !stage.is_empty() {
        stages.push(stage.to_string());
    }
    Ok(stages)
}

fn parse_stream_op(raw: &str) -> Result<StreamOp, QueryError> {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower == "ascending" {
        return Err(QueryError(
            "ascending expects a field like ascending:score".to_string(),
        ));
    }
    if lower == "descending" {
        return Err(QueryError(
            "descending expects a field like descending:score".to_string(),
        ));
    }
    if let Some(value) = trimmed.strip_prefix("ascending:") {
        return Ok(StreamOp::Ascending(parse_sort_key(value.trim())?));
    }
    if let Some(value) = trimmed.strip_prefix("descending:") {
        return Ok(StreamOp::Descending(parse_sort_key(value.trim())?));
    }
    if let Some(value) = lower.strip_prefix("limit:") {
        let limit = value
            .trim()
            .parse::<usize>()
            .map_err(|_| QueryError("limit expects a positive integer".to_string()))?;
        if limit == 0 {
            return Err(QueryError("limit expects a positive integer".to_string()));
        }
        return Ok(StreamOp::Limit(limit));
    }
    if let Some(value) = lower.strip_prefix("drop:") {
        return match value.trim() {
            "lhs" => Ok(StreamOp::Drop(QuerySide::Lhs)),
            "rhs" => Ok(StreamOp::Drop(QuerySide::Rhs)),
            _ => Err(QueryError("drop expects lhs or rhs".to_string())),
        };
    }
    if let Some(value) = lower.strip_prefix("expand:") {
        return match value.trim() {
            "blocks" => Ok(StreamOp::Expand(ExpandTarget::Blocks)),
            "instructions" => Ok(StreamOp::Expand(ExpandTarget::Instructions)),
            _ => Err(QueryError(
                "expand expects blocks or instructions".to_string(),
            )),
        };
    }
    if let Some(value) = trimmed.strip_prefix("score:") {
        return Ok(StreamOp::ScoreFilter(value.trim().to_string()));
    }

    let query = Query::parse(trimmed)?;
    let analysis = query.analyze()?;
    if analysis.root.is_some() {
        return Err(QueryError(
            "post-projection filters cannot declare a new search root".to_string(),
        ));
    }
    Ok(StreamOp::SearchFilter(query))
}

fn fold_root_search_filter(root_plan: &mut SearchPlan, query: &Query) -> Result<bool, QueryError> {
    if !expr_is_root_narrowing_filter(query.expr()) {
        return Ok(false);
    }
    let analysis = query.analyze()?;
    if analysis.root.is_some() {
        return Ok(false);
    }
    if !analysis.corpora.is_empty() {
        root_plan.corpora = intersect_strings(&root_plan.corpora, &analysis.corpora);
    }
    if !analysis.collections.is_empty() {
        let requested = analysis
            .collections
            .iter()
            .copied()
            .map(map_collection)
            .collect::<Vec<_>>();
        root_plan.collections = intersect_collections(&root_plan.collections, &requested);
    }
    if !analysis.architectures.is_empty() {
        root_plan.architectures =
            intersect_architectures(&root_plan.architectures, &analysis.architectures);
    }
    Ok(true)
}

fn expr_is_root_narrowing_filter(expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Term(term) => matches!(
            term.field,
            QueryField::Corpus | QueryField::Collection | QueryField::Architecture
        ),
        QueryExpr::And(lhs, rhs) => {
            expr_is_root_narrowing_filter(lhs) && expr_is_root_narrowing_filter(rhs)
        }
        QueryExpr::Not(_) | QueryExpr::Or(_, _) => false,
    }
}

fn validate_query_fields_for_collections(
    expr: &QueryExpr,
    collections: &[Collection],
) -> Result<(), QueryError> {
    match expr {
        QueryExpr::Term(term) => validate_query_term_for_collections(term, collections),
        QueryExpr::Not(inner) => validate_query_fields_for_collections(inner, collections),
        QueryExpr::And(lhs, rhs) | QueryExpr::Or(lhs, rhs) => {
            validate_query_fields_for_collections(lhs, collections)?;
            validate_query_fields_for_collections(rhs, collections)
        }
    }
}

fn validate_query_term_for_collections(
    term: &QueryTerm,
    collections: &[Collection],
) -> Result<(), QueryError> {
    let Some(valid_collections) = valid_collections_for_field(&term.field) else {
        return Ok(());
    };
    if collections
        .iter()
        .any(|collection| valid_collections.contains(collection))
    {
        return Ok(());
    }
    Err(QueryError(format!(
        "{} is only valid for {}",
        query_field_label(&term.field),
        describe_collection_scope(valid_collections)
    )))
}

fn valid_collections_for_field(field: &QueryField) -> Option<&'static [Collection]> {
    match field {
        QueryField::CyclomaticComplexity
        | QueryField::AverageInstructionsPerBlock
        | QueryField::NumberOfBlocks => Some(&[Collection::Function]),
        QueryField::Markov => Some(&[Collection::Block]),
        _ => None,
    }
}

fn query_field_label(field: &QueryField) -> &'static str {
    match field {
        QueryField::Sha256 => "sample",
        QueryField::Embedding => "embedding",
        QueryField::Embeddings => "embeddings",
        QueryField::Vector => "vector",
        QueryField::Score => "score",
        QueryField::Corpus => "corpus",
        QueryField::Collection => "collection",
        QueryField::Architecture => "architecture",
        QueryField::Username => "username",
        QueryField::Address => "address",
        QueryField::Timestamp => "timestamp",
        QueryField::Size => "size",
        QueryField::Symbol => "symbol",
        QueryField::CyclomaticComplexity => "cyclomatic_complexity",
        QueryField::AverageInstructionsPerBlock => "average_instructions_per_block",
        QueryField::NumberOfInstructions => "instructions",
        QueryField::NumberOfBlocks => "blocks",
        QueryField::Markov => "markov",
        QueryField::Entropy => "entropy",
        QueryField::Contiguous => "contiguous",
        QueryField::ChromosomeEntropy => "chromosome.entropy",
    }
}

fn parse_sort_key(value: &str) -> Result<SortKey, QueryError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "score" => Ok(SortKey::Score),
        "size" => Ok(SortKey::Size),
        "embeddings" => Ok(SortKey::Embeddings),
        "address" => Ok(SortKey::Address),
        "timestamp" => Ok(SortKey::Timestamp),
        "cyclomatic_complexity" => Ok(SortKey::CyclomaticComplexity),
        "average_instructions_per_block" => Ok(SortKey::AverageInstructionsPerBlock),
        "instructions" => Ok(SortKey::NumberOfInstructions),
        "blocks" => Ok(SortKey::NumberOfBlocks),
        "markov" => Ok(SortKey::Markov),
        "entropy" => Ok(SortKey::Entropy),
        "chromosome.entropy" => Ok(SortKey::ChromosomeEntropy),
        _ => Err(QueryError(format!("unknown sort field {}", value.trim()))),
    }
}

fn describe_collection_scope(collections: &[Collection]) -> String {
    let names = collections
        .iter()
        .map(|collection| format!("collection:{}", collection.as_str()))
        .collect::<Vec<_>>();
    match names.as_slice() {
        [] => "supported collections".to_string(),
        [only] => only.clone(),
        [first, second] => format!("{first} or {second}"),
        _ => {
            let mut parts = names;
            let last = parts.pop().unwrap_or_default();
            format!("{} or {}", parts.join(", "), last)
        }
    }
}

fn intersect_strings(current: &[String], requested: &[String]) -> Vec<String> {
    current
        .iter()
        .filter(|value| {
            requested
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(value))
        })
        .cloned()
        .collect()
}

fn intersect_collections(current: &[Collection], requested: &[Collection]) -> Vec<Collection> {
    current
        .iter()
        .copied()
        .filter(|value| requested.iter().any(|candidate| candidate == value))
        .collect()
}

fn intersect_architectures(
    current: &[Architecture],
    requested: &[Architecture],
) -> Vec<Architecture> {
    current
        .iter()
        .copied()
        .filter(|value| requested.iter().any(|candidate| candidate == value))
        .collect()
}

fn rebuild_root_search_plan(plan: StreamPlan, root_plan: SearchPlan) -> StreamPlan {
    match plan {
        StreamPlan::Search(_) => StreamPlan::Search(root_plan),
        StreamPlan::Pipe { input, op } => StreamPlan::Pipe {
            input: Box::new(rebuild_root_search_plan(*input, root_plan)),
            op,
        },
        StreamPlan::Compare { .. } => plan,
    }
}

fn map_collection(collection: QueryCollection) -> Collection {
    match collection {
        QueryCollection::Instruction => Collection::Instruction,
        QueryCollection::Block => Collection::Block,
        QueryCollection::Function => Collection::Function,
    }
}

fn search_term_matches(result: &SearchResult, term: &QueryTerm, root: &Option<SearchRoot>) -> bool {
    let value = term.value.trim();
    match term.field {
        QueryField::Sha256 => result.sha256().eq_ignore_ascii_case(value),
        QueryField::Embedding => result.embedding().eq_ignore_ascii_case(value),
        QueryField::Embeddings => embeddings_filter_matches(value, result.embeddings()),
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
        QueryField::Symbol => result
            .symbol()
            .map(|symbol| symbol.eq_ignore_ascii_case(value))
            .unwrap_or(false),
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

fn parse_query_address(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn embeddings_filter_matches(raw: &str, actual: u64) -> bool {
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
enum CountOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

fn parse_count_query(raw: &str) -> Option<(CountOperator, u64)> {
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

fn parse_compact_count(raw: &str) -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use binlex::Config;
    use std::path::PathBuf;

    #[test]
    fn parse_compact_count_supports_suffixes() {
        assert_eq!(parse_compact_count("184"), Some(184));
        assert_eq!(parse_compact_count("1k"), Some(1_000));
        assert_eq!(parse_compact_count("1.5k"), Some(1_500));
        assert_eq!(parse_compact_count("12m"), Some(12_000_000));
        assert_eq!(parse_compact_count("1.5b"), Some(1_500_000_000));
    }

    #[test]
    fn embeddings_filter_matches_comparisons() {
        assert!(embeddings_filter_matches("184", 184));
        assert!(embeddings_filter_matches(">1k", 1_001));
        assert!(embeddings_filter_matches(">=1.5k", 1_500));
        assert!(embeddings_filter_matches("<12m", 11_999_999));
        assert!(embeddings_filter_matches("<=1.5b", 1_500_000_000));
        assert!(!embeddings_filter_matches(">1.5k", 1_500));
        assert!(!embeddings_filter_matches("bogus", 10));
    }

    #[test]
    fn resolve_corpora_defaults_to_all_indexed_corpora() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-query-corpora-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let sha256 = index
            .sample_put(b"web-corpus-sample")
            .expect("store sample");
        let graph = {
            let mut graph = binlex::controlflow::Graph::new(Architecture::AMD64, Config::default());
            let mut instruction = binlex::controlflow::Instruction::create(
                0x1000,
                Architecture::AMD64,
                Config::default(),
            );
            instruction.bytes = vec![0xC3];
            instruction.pattern = "c3".to_string();
            instruction.is_return = true;
            graph.insert_instruction(instruction);
            assert!(graph.set_block(0x1000));
            assert!(graph.set_function(0x1000));
            graph
        };
        let function = binlex::controlflow::Function::new(0x1000, &graph).expect("build function");
        index
            .function(&function, &[1.0; 64], &sha256, &[])
            .expect("stage function");
        index.commit().expect("commit function");
        index
            .collection_corpus_add(
                &sha256,
                Collection::Function,
                "amd64",
                0x1000,
                "malware",
                "",
            )
            .expect("add second corpus");

        let plan = build_search_plan(
            &index,
            "default",
            &[Collection::Function],
            "collection:function",
        )
        .expect("build search plan");

        assert!(plan.corpora.iter().any(|corpus| corpus == "default"));
        assert!(plan.corpora.iter().any(|corpus| corpus == "malware"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_directional_compare_extracts_both_sides() {
        let parts = split_directional_compare(
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | collection:function -> corpus:goodware | collection:function",
        )
        .expect("split compare query")
        .expect("compare query");
        assert!(parts.0.contains("sample:"));
        assert!(parts.1.contains("corpus:goodware"));
        assert_eq!(parts.2, CompareDirection::BestPerLeft);
    }

    #[test]
    fn build_query_plan_detects_directional_compare_queries() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-directional-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | collection:function -> corpus:goodware | collection:function",
        )
        .expect("build query plan");
        match plan {
            StreamPlan::Compare { direction, .. } => {
                assert_eq!(direction, CompareDirection::BestPerLeft);
            }
            other => panic!("expected compare plan, got {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_supports_grouped_post_compare_ops() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-grouped-post-ops-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function],
            "( sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -> corpus:goodware | collection:function ) | score:<0.25 | ascending:score | drop:rhs",
        )
        .expect("build query plan");
        match plan {
            StreamPlan::Pipe { .. } => {}
            other => panic!("expected post-compare pipe plan, got {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_parses_expand_pipe_stage() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-expand-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | expand:blocks | collection:block",
        )
        .expect("build query plan");
        assert!(stream_plan_contains_expand(&plan, ExpandTarget::Blocks));
        assert!(stream_plan_contains_search_filter(
            &plan,
            &QueryField::Collection,
            "block"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_rejects_bare_ascending() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-bare-ascending-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let error = build_query_plan(
            &index,
            "default",
            &[Collection::Function],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | ascending",
        )
        .expect_err("reject bare ascending");
        assert!(error.to_string().contains("ascending expects a field"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_allows_markov_sort_after_expand_blocks() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-expand-markov-sort-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function, Collection::Block, Collection::Instruction],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | collection:function | expand:blocks | ascending:markov | limit:10",
        )
        .expect("allow markov sort after expand to blocks");
        assert!(stream_plan_contains_expand(&plan, ExpandTarget::Blocks));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_keeps_post_expand_collection_filter_out_of_root_fold() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-expand-root-fold-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function, Collection::Block],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | collection:function | expand:blocks | collection:block",
        )
        .expect("build query plan");
        let root_plan = unwrap_stream_search_root(&plan);
        assert_eq!(root_plan.collections, vec![Collection::Function]);
        assert!(stream_plan_contains_expand(&plan, ExpandTarget::Blocks));
        assert!(stream_plan_contains_search_filter(
            &plan,
            &QueryField::Collection,
            "block"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_rejects_function_only_metrics_for_block_queries() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-invalid-block-metric-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let error = build_query_plan(
            &index,
            "default",
            &[Collection::Function, Collection::Block],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | collection:block | blocks:>1",
        )
        .expect_err("reject block-only blocks filter");
        assert!(error.to_string().contains("blocks"));
        assert!(error.to_string().contains("collection:function"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_rejects_piped_function_only_metrics_after_block_fold() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-invalid-block-metric-after-fold-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let error = build_query_plan(
            &index,
            "default",
            &[Collection::Function, Collection::Block],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | collection:block | blocks:1",
        )
        .expect_err("reject piped block-only blocks filter");
        assert!(error.to_string().contains("blocks"));
        assert!(error.to_string().contains("collection:function"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_query_plan_keeps_mixed_collections_for_unscoped_function_metrics() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-unscoped-function-metric-mixed-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function, Collection::Block],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | blocks:>10",
        )
        .expect("keep mixed collections for function-only metric");
        let root_plan = unwrap_stream_search_root(&plan);
        assert_eq!(
            root_plan.collections,
            vec![Collection::Function, Collection::Block]
        );
        assert!(stream_plan_contains_search_filter(
            &plan,
            &QueryField::NumberOfBlocks,
            ">10"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn single_sided_search_supports_sample_root_without_compare() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-single-side-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | collection:function",
        )
        .expect("build query plan");
        let root_plan = unwrap_stream_search_root(&plan);
        assert!(matches!(root_plan.root, Some(SearchRoot::Sha256(_))));
        assert_eq!(root_plan.collections, vec![Collection::Function]);
        assert!(!stream_plan_contains_search_filter(
            &plan,
            &QueryField::Collection,
            "function"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn single_sided_search_folds_corpus_and_collection_filters_into_root_plan() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-root-filter-fold-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function, Collection::Block],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | corpus:default | collection:function",
        )
        .expect("build query plan");
        let root_plan = unwrap_stream_search_root(&plan);
        assert!(matches!(root_plan.root, Some(SearchRoot::Sha256(_))));
        assert_eq!(root_plan.corpora, vec!["default".to_string()]);
        assert_eq!(root_plan.collections, vec![Collection::Function]);
        assert!(!stream_plan_contains_search_filter(
            &plan,
            &QueryField::Corpus,
            "default"
        ));
        assert!(!stream_plan_contains_search_filter(
            &plan,
            &QueryField::Collection,
            "function"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn single_sided_search_keeps_non_root_filters_as_pipe_ops() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-root-filter-pipe-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let index = LocalIndex::with_options(Config::default(), Some(PathBuf::from(&root)), None)
            .expect("create local index");
        let plan = build_query_plan(
            &index,
            "default",
            &[Collection::Function],
            "sample:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | size:>1",
        )
        .expect("build query plan");
        let root_plan = unwrap_stream_search_root(&plan);
        assert!(matches!(root_plan.root, Some(SearchRoot::Sha256(_))));
        assert!(stream_plan_contains_search_filter(
            &plan,
            &QueryField::Size,
            ">1"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn search_plan_contains_term(query: &Query, field: &QueryField, value: &str) -> bool {
        expr_contains_term(query.expr(), field, value)
    }

    fn unwrap_stream_search_root(plan: &StreamPlan) -> &SearchPlan {
        match plan {
            StreamPlan::Search(plan) => plan,
            StreamPlan::Pipe { input, .. } => unwrap_stream_search_root(input),
            StreamPlan::Compare { .. } => panic!("expected a search-rooted plan"),
        }
    }

    fn stream_plan_contains_search_filter(
        plan: &StreamPlan,
        field: &QueryField,
        value: &str,
    ) -> bool {
        match plan {
            StreamPlan::Search(plan) => search_plan_contains_term(&plan.query, field, value),
            StreamPlan::Pipe { input, op } => {
                let current = match op {
                    StreamOp::SearchFilter(query) => search_plan_contains_term(query, field, value),
                    _ => false,
                };
                current || stream_plan_contains_search_filter(input, field, value)
            }
            StreamPlan::Compare { left, right, .. } => {
                stream_plan_contains_search_filter(left, field, value)
                    || stream_plan_contains_search_filter(right, field, value)
            }
        }
    }

    fn stream_plan_contains_expand(plan: &StreamPlan, target: ExpandTarget) -> bool {
        match plan {
            StreamPlan::Search(_) => false,
            StreamPlan::Pipe { input, op } => {
                matches!(op, StreamOp::Expand(current) if *current == target)
                    || stream_plan_contains_expand(input, target)
            }
            StreamPlan::Compare { left, right, .. } => {
                stream_plan_contains_expand(left, target)
                    || stream_plan_contains_expand(right, target)
            }
        }
    }

    fn expr_contains_term(expr: &QueryExpr, field: &QueryField, value: &str) -> bool {
        match expr {
            QueryExpr::Term(term) => term.field == *field && term.value == value,
            QueryExpr::Not(inner) => expr_contains_term(inner, field, value),
            QueryExpr::And(lhs, rhs) | QueryExpr::Or(lhs, rhs) => {
                expr_contains_term(lhs, field, value) || expr_contains_term(rhs, field, value)
            }
        }
    }
}
