use super::LocalIndex;
use super::support::{resolve_query_corpora, search_expr_matches};
use super::types::{DEFAULT_INDEX_GRAPH_COLLECTIONS, Error, SearchResult};
use crate::Architecture;
use crate::indexing::Collection;
use crate::math::similarity::cosine;
use crate::query::{Query, QueryCollection, QueryError, SearchRoot, query_score_matches};

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
    Ascending,
    Descending,
    Drop(QuerySide),
    SearchFilter(Query),
}

#[derive(Clone, Debug)]
pub struct CompareResult {
    lhs: SearchResult,
    rhs: SearchResult,
    score: f32,
}

impl CompareResult {
    pub fn left(&self) -> &SearchResult {
        &self.lhs
    }

    pub fn right(&self) -> &SearchResult {
        &self.rhs
    }

    pub fn score(&self) -> f32 {
        self.score
    }
}

#[derive(Clone, Debug)]
pub struct QueryResult {
    lhs: Option<SearchResult>,
    rhs: Option<SearchResult>,
    score: f32,
}

impl QueryResult {
    pub fn lhs(&self) -> Option<&SearchResult> {
        self.lhs.as_ref()
    }

    pub fn rhs(&self) -> Option<&SearchResult> {
        self.rhs.as_ref()
    }

    pub fn primary(&self) -> Option<&SearchResult> {
        self.lhs().or_else(|| self.rhs())
    }

    pub fn sha256(&self) -> &str {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .sha256()
    }

    pub fn address(&self) -> u64 {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .address()
    }

    pub fn size(&self) -> u64 {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .size()
    }

    pub fn corpora(&self) -> &[String] {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .corpora()
    }

    pub fn corpus(&self) -> &str {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .corpus()
    }

    pub fn collection(&self) -> Collection {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .collection()
    }

    pub fn architecture(&self) -> &str {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .architecture()
    }

    pub fn symbol(&self) -> Option<&str> {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .symbol()
    }

    pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        self.primary()
            .expect("query result must contain lhs or rhs")
            .timestamp()
    }

    pub fn score(&self) -> f32 {
        self.score
    }

    fn from_search(result: SearchResult) -> Self {
        let score = result.score();
        Self {
            lhs: Some(result),
            rhs: None,
            score,
        }
    }

    fn from_compare(result: CompareResult) -> Self {
        Self {
            lhs: Some(result.lhs),
            rhs: Some(result.rhs),
            score: result.score,
        }
    }

    fn project_lhs(result: SearchResult, score: f32) -> Self {
        Self {
            lhs: Some(result.with_score(score)),
            rhs: None,
            score,
        }
    }

    fn project_rhs(result: SearchResult, score: f32) -> Self {
        Self {
            lhs: None,
            rhs: Some(result.with_score(score)),
            score,
        }
    }
}

enum ExecutedStream {
    Search { results: Vec<QueryResult> },
    Compare { pairs: Vec<CompareResult> },
}

const DEFAULT_ASCENDING_LIMIT: usize = 256;

impl LocalIndex {
    pub fn search(
        &self,
        query: &str,
        top_k: usize,
        page: usize,
    ) -> Result<Vec<QueryResult>, Error> {
        self.search_stream(query, top_k, page)
    }

    pub fn search_stream(
        &self,
        query: &str,
        top_k: usize,
        page: usize,
    ) -> Result<Vec<QueryResult>, Error> {
        let top_k = top_k.max(1);
        let page = page.max(1);
        let offset = page.saturating_sub(1).saturating_mul(top_k);
        let candidate_limit = offset
            .saturating_add(top_k.saturating_mul(8))
            .saturating_add(1)
            .clamp(64, 512);
        let plan = build_query_plan(self, "default", DEFAULT_INDEX_GRAPH_COLLECTIONS, query)
            .map_err(|error| Error::Validation(error.to_string()))?;
        let stream = evaluate_stream(self, &plan, candidate_limit, top_k, page)
            .map_err(Error::Validation)?;
        Ok(match stream {
            ExecutedStream::Search { results } => {
                results.into_iter().skip(offset).take(top_k).collect()
            }
            ExecutedStream::Compare { pairs } => pairs
                .into_iter()
                .skip(offset)
                .take(top_k)
                .map(QueryResult::from_compare)
                .collect(),
        })
    }
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
        let mut plan = StreamPlan::Search(build_search_plan(
            index,
            default_corpus,
            default_collections,
            &stages[0],
        )?);
        for stage in stages.into_iter().skip(1) {
            plan = StreamPlan::Pipe {
                input: Box::new(plan),
                op: parse_stream_op(&stage)?,
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

fn build_search_plan(
    index: &LocalIndex,
    default_corpus: &str,
    default_collections: &[Collection],
    query: &str,
) -> Result<SearchPlan, QueryError> {
    let query = Query::parse(query)?;
    let analysis = query.analyze()?;
    let corpora =
        resolve_query_corpora(index, &analysis.corpora).map_err(|e| QueryError(e.to_string()))?;
    let corpora = if corpora.is_empty() {
        vec![default_corpus.to_string()]
    } else {
        corpora
    };
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
    Ok(SearchPlan {
        root: analysis.root,
        corpora,
        collections,
        architectures: analysis.architectures,
        query,
    })
}

fn map_collection(collection: QueryCollection) -> Collection {
    match collection {
        QueryCollection::Instruction => Collection::Instruction,
        QueryCollection::Block => Collection::Block,
        QueryCollection::Function => Collection::Function,
    }
}

fn evaluate_stream(
    index: &LocalIndex,
    plan: &StreamPlan,
    candidate_limit: usize,
    limit: usize,
    page: usize,
) -> Result<ExecutedStream, String> {
    match plan {
        StreamPlan::Search(plan) => Ok(ExecutedStream::Search {
            results: collect_search_candidates(index, plan, candidate_limit, limit, page)
                .map_err(|error| error.to_string())?,
        }),
        StreamPlan::Compare {
            left,
            right,
            direction,
        } => {
            let left_stream = evaluate_stream(index, left, candidate_limit, limit, page)?;
            let right_stream = evaluate_stream(index, right, candidate_limit, limit, page)?;
            let left_results = expect_search_stream(left_stream, "left compare operand")?;
            let right_results = expect_search_stream(right_stream, "right compare operand")?;
            let pairs = match direction {
                CompareDirection::BestPerLeft => {
                    build_best_pairs_per_left(&left_results, &right_results, candidate_limit)
                }
                CompareDirection::BestPerRight => {
                    build_best_pairs_per_right(&left_results, &right_results, candidate_limit)
                }
            };
            Ok(ExecutedStream::Compare { pairs })
        }
        StreamPlan::Pipe { input, op } => {
            let stream = evaluate_stream(index, input, candidate_limit, limit, page)?;
            apply_stream_op(stream, op)
        }
    }
}

fn collect_search_candidates(
    index: &LocalIndex,
    plan: &SearchPlan,
    broad_limit: usize,
    limit: usize,
    page: usize,
) -> Result<Vec<QueryResult>, Error> {
    let mut candidates = match &plan.root {
        Some(SearchRoot::Sha256(sha256)) => index.exact_search_page(
            &plan.corpora,
            sha256,
            Some(&plan.collections),
            &plan.architectures,
            0,
            broad_limit,
        )?,
        Some(SearchRoot::Embedding(embedding)) => index.embedding_search_page(
            &plan.corpora,
            embedding,
            Some(&plan.collections),
            &plan.architectures,
            0,
            broad_limit,
        )?,
        Some(SearchRoot::Vector(vector)) => index.nearest_page(
            &plan.corpora,
            vector,
            Some(&plan.collections),
            &plan.architectures,
            0,
            broad_limit,
        )?,
        None => index.scan_search_page(
            &plan.corpora,
            Some(&plan.collections),
            &plan.architectures,
            0,
            broad_limit.max(limit * page).max(64),
        )?,
    };
    candidates.retain(|result| search_expr_matches(result, plan.query.expr(), &plan.root));
    Ok(candidates
        .into_iter()
        .map(QueryResult::from_search)
        .collect())
}

fn expect_search_stream(stream: ExecutedStream, label: &str) -> Result<Vec<SearchResult>, String> {
    match stream {
        ExecutedStream::Search { results } => results
            .into_iter()
            .map(|result| {
                result
                    .primary()
                    .cloned()
                    .ok_or_else(|| format!("{label} must resolve to a search stream"))
            })
            .collect(),
        ExecutedStream::Compare { .. } => Err(format!("{label} must resolve to a search stream")),
    }
}

fn apply_stream_op(stream: ExecutedStream, op: &StreamOp) -> Result<ExecutedStream, String> {
    match (stream, op) {
        (ExecutedStream::Compare { mut pairs }, StreamOp::ScoreFilter(raw)) => {
            pairs.retain(|pair| query_score_matches(raw, pair.score));
            Ok(ExecutedStream::Compare { pairs })
        }
        (ExecutedStream::Search { mut results }, StreamOp::ScoreFilter(raw)) => {
            results.retain(|result| query_score_matches(raw, result.score()));
            Ok(ExecutedStream::Search { results })
        }
        (ExecutedStream::Compare { mut pairs }, StreamOp::Limit(limit)) => {
            pairs.truncate(*limit);
            Ok(ExecutedStream::Compare { pairs })
        }
        (ExecutedStream::Search { mut results }, StreamOp::Limit(limit)) => {
            results.truncate(*limit);
            Ok(ExecutedStream::Search { results })
        }
        (ExecutedStream::Compare { mut pairs }, StreamOp::Ascending) => {
            if pairs.len() > DEFAULT_ASCENDING_LIMIT {
                return Err(format!(
                    "ascending requires at most {} compare results; refine the query or use limit:<n>",
                    DEFAULT_ASCENDING_LIMIT
                ));
            }
            pairs.sort_by(|lhs, rhs| lhs.score.total_cmp(&rhs.score));
            Ok(ExecutedStream::Compare { pairs })
        }
        (ExecutedStream::Compare { mut pairs }, StreamOp::Descending) => {
            pairs.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
            Ok(ExecutedStream::Compare { pairs })
        }
        (ExecutedStream::Compare { pairs }, StreamOp::Drop(QuerySide::Lhs)) => {
            Ok(ExecutedStream::Search {
                results: pairs
                    .into_iter()
                    .map(|pair| QueryResult::project_rhs(pair.rhs, pair.score))
                    .collect(),
            })
        }
        (ExecutedStream::Compare { pairs }, StreamOp::Drop(QuerySide::Rhs)) => {
            Ok(ExecutedStream::Search {
                results: pairs
                    .into_iter()
                    .map(|pair| QueryResult::project_lhs(pair.lhs, pair.score))
                    .collect(),
            })
        }
        (ExecutedStream::Search { mut results }, StreamOp::SearchFilter(query)) => {
            let analysis = query.analyze().map_err(|error| error.to_string())?;
            results.retain(|result| {
                result
                    .primary()
                    .is_some_and(|search| search_expr_matches(search, query.expr(), &analysis.root))
            });
            Ok(ExecutedStream::Search { results })
        }
        (ExecutedStream::Search { mut results }, StreamOp::Ascending) => {
            if results.len() > DEFAULT_ASCENDING_LIMIT {
                return Err(format!(
                    "ascending requires at most {} results; refine the query or use limit:<n>",
                    DEFAULT_ASCENDING_LIMIT
                ));
            }
            results.sort_by(|lhs, rhs| lhs.score().total_cmp(&rhs.score()));
            Ok(ExecutedStream::Search { results })
        }
        (ExecutedStream::Search { mut results }, StreamOp::Descending) => {
            results.sort_by(|lhs, rhs| rhs.score().total_cmp(&lhs.score()));
            Ok(ExecutedStream::Search { results })
        }
        (ExecutedStream::Search { .. }, StreamOp::Drop(_)) => {
            Err("drop:lhs and drop:rhs require a compare result stream".to_string())
        }
        (ExecutedStream::Compare { .. }, StreamOp::SearchFilter(_)) => {
            Err("search filters can only run after drop:lhs or drop:rhs".to_string())
        }
    }
}

fn build_best_pairs_per_left(
    lhs: &[SearchResult],
    rhs: &[SearchResult],
    compare_limit: usize,
) -> Vec<CompareResult> {
    let mut pairs = Vec::new();
    for lhs_result in lhs.iter().take(compare_limit) {
        let Some((rhs_result, score)) = best_match(lhs_result, rhs) else {
            continue;
        };
        pairs.push(CompareResult {
            lhs: lhs_result.clone(),
            rhs: rhs_result.clone(),
            score,
        });
    }
    pairs.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
    pairs
}

fn build_best_pairs_per_right(
    lhs: &[SearchResult],
    rhs: &[SearchResult],
    compare_limit: usize,
) -> Vec<CompareResult> {
    let mut pairs = Vec::new();
    for rhs_result in rhs.iter().take(compare_limit) {
        let Some((lhs_result, score)) = best_match(rhs_result, lhs) else {
            continue;
        };
        pairs.push(CompareResult {
            lhs: lhs_result.clone(),
            rhs: rhs_result.clone(),
            score,
        });
    }
    pairs.sort_by(|lhs, rhs| rhs.score.total_cmp(&lhs.score));
    pairs
}

fn best_match<'a>(
    anchor: &SearchResult,
    candidates: &'a [SearchResult],
) -> Option<(&'a SearchResult, f32)> {
    let vector = anchor.vector();
    if vector.is_empty() {
        return None;
    }
    candidates
        .iter()
        .filter_map(|candidate| {
            if candidate.vector().is_empty() || candidate.vector().len() != vector.len() {
                return None;
            }
            Some((candidate, cosine(vector, candidate.vector())))
        })
        .max_by(|lhs, rhs| lhs.1.total_cmp(&rhs.1))
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
        return Ok(StreamOp::Ascending);
    }
    if lower == "descending" {
        return Ok(StreamOp::Descending);
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
