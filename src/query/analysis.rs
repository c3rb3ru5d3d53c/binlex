use super::filters::{
    is_sha256, parse_bool_query, parse_date_query, parse_float_query, parse_integer_query,
    parse_positive_count_query, parse_query_address, parse_query_vector, parse_score_query,
    parse_size_query,
};
use super::types::{
    QueryAnalysis, QueryCollection, QueryError, QueryExpr, QueryField, QueryTerm, SearchRoot,
};
use crate::Architecture;

pub(super) fn analyze_query_expr(
    expr: &QueryExpr,
    analysis: &mut QueryAnalysis,
    negated: bool,
    inside_or: bool,
) -> Result<(), QueryError> {
    match expr {
        QueryExpr::Term(term) => analyze_query_term(term, analysis, negated, inside_or),
        QueryExpr::Not(inner) => analyze_query_expr(inner, analysis, true, inside_or),
        QueryExpr::And(lhs, rhs) => {
            analyze_query_expr(lhs, analysis, negated, inside_or)?;
            analyze_query_expr(rhs, analysis, negated, inside_or)
        }
        QueryExpr::Or(lhs, rhs) => {
            analyze_query_expr(lhs, analysis, negated, true)?;
            analyze_query_expr(rhs, analysis, negated, true)
        }
    }
}

fn analyze_query_term(
    term: &QueryTerm,
    analysis: &mut QueryAnalysis,
    negated: bool,
    inside_or: bool,
) -> Result<(), QueryError> {
    match term.field {
        QueryField::Embedding => {
            if negated || inside_or {
                return Err(QueryError(
                    "embedding queries can only be combined with `|` filters".to_string(),
                ));
            }
            if !is_sha256(term.value.trim()) {
                return Err(QueryError(
                    "embedding must be 64 hexadecimal characters".to_string(),
                ));
            }
            set_search_root(
                analysis,
                SearchRoot::Embedding(term.value.trim().to_ascii_lowercase()),
            )
        }
        QueryField::Sha256 => {
            if inside_or && !negated {
                return Err(QueryError(
                    "sha256 queries can only be combined with `|` filters".to_string(),
                ));
            }
            if !is_sha256(term.value.trim()) {
                return Err(QueryError(
                    "sha256 must be 64 hexadecimal characters".to_string(),
                ));
            }
            if negated {
                return Ok(());
            }
            set_search_root(
                analysis,
                SearchRoot::Sha256(term.value.trim().to_ascii_lowercase()),
            )
        }
        QueryField::Vector => {
            if negated || inside_or {
                return Err(QueryError(
                    "vector queries can only be combined with `|` filters".to_string(),
                ));
            }
            let vector = parse_query_vector(term.value.trim()).ok_or_else(|| {
                QueryError("vector expects a JSON array with at least two numbers".to_string())
            })?;
            set_search_root(analysis, SearchRoot::Vector(vector))
        }
        QueryField::Embeddings => {
            if parse_positive_count_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "embeddings expects counts with optional comparisons like embeddings:>1k or embeddings:<=12m"
                        .to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Score => {
            if parse_score_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "score expects decimal comparisons like score:>0.95 or score:<=1.0".to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Corpus if !negated => push_unique_string(&mut analysis.corpora, &term.value),
        QueryField::Collection if !negated => {
            let collection = QueryCollection::parse(&term.value)
                .ok_or_else(|| QueryError(format!("invalid collection {}", term.value)))?;
            push_unique_collection(&mut analysis.collections, collection);
            Ok(())
        }
        QueryField::Architecture if !negated => {
            let architecture = Architecture::from_string(&term.value)
                .map_err(|_| QueryError(format!("invalid architecture {}", term.value)))?;
            push_unique_architecture(&mut analysis.architectures, architecture);
            Ok(())
        }
        QueryField::Username => {
            if term.value.trim().is_empty() {
                return Err(QueryError("username requires a value".to_string()));
            }
            Ok(())
        }
        QueryField::Address => {
            if parse_query_address(term.value.trim()).is_none() {
                return Err(QueryError(format!("invalid address {}", term.value)));
            }
            Ok(())
        }
        QueryField::Timestamp => {
            if parse_date_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "timestamp expects YYYY, YYYY-MM, YYYY-MM-DD, or comparisons like timestamp:>=2026-03-01"
                        .to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Size => {
            if parse_size_query(term.value.trim()).is_none() {
                return Err(QueryError(
                    "size expects bytes with optional comparisons like size:>64 or size:>=1mb"
                        .to_string(),
                ));
            }
            Ok(())
        }
        QueryField::Tag => {
            if term.value.trim().is_empty() {
                return Err(QueryError("tag requires a value".to_string()));
            }
            Ok(())
        }
        QueryField::Symbols
        | QueryField::Tags
        | QueryField::Comments
        | QueryField::CyclomaticComplexity
        | QueryField::NumberOfInstructions
        | QueryField::NumberOfBlocks => {
            if parse_integer_query(term.value.trim()).is_none() {
                return Err(QueryError(format!(
                    "{} expects integer comparisons like {}:>5",
                    match term.field {
                        QueryField::Symbols => "symbols",
                        QueryField::Tags => "tags",
                        QueryField::Comments => "comments",
                        QueryField::CyclomaticComplexity => "cyclomatic_complexity",
                        QueryField::NumberOfInstructions => "instructions",
                        _ => "blocks",
                    },
                    match term.field {
                        QueryField::Symbols => "symbols",
                        QueryField::Tags => "tags",
                        QueryField::Comments => "comments",
                        QueryField::CyclomaticComplexity => "cyclomatic_complexity",
                        QueryField::NumberOfInstructions => "instructions",
                        _ => "blocks",
                    }
                )));
            }
            Ok(())
        }
        QueryField::AverageInstructionsPerBlock
        | QueryField::Markov
        | QueryField::Entropy
        | QueryField::ChromosomeEntropy => {
            if parse_float_query(term.value.trim()).is_none() {
                return Err(QueryError(format!(
                    "{} expects decimal comparisons like {}:>1.5",
                    match term.field {
                        QueryField::AverageInstructionsPerBlock => "average_instructions_per_block",
                        QueryField::Markov => "markov",
                        QueryField::Entropy => "entropy",
                        _ => "chromosome.entropy",
                    },
                    match term.field {
                        QueryField::AverageInstructionsPerBlock => "average_instructions_per_block",
                        QueryField::Markov => "markov",
                        QueryField::Entropy => "entropy",
                        _ => "chromosome.entropy",
                    }
                )));
            }
            Ok(())
        }
        QueryField::Contiguous => {
            if parse_bool_query(term.value.trim()).is_none() {
                return Err(QueryError("contiguous expects true or false".to_string()));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn set_search_root(analysis: &mut QueryAnalysis, root: SearchRoot) -> Result<(), QueryError> {
    match (&analysis.root, &root) {
        (None, _) => {
            analysis.root = Some(root);
            Ok(())
        }
        (Some(SearchRoot::Embedding(lhs)), SearchRoot::Embedding(rhs)) if lhs == rhs => Ok(()),
        (Some(SearchRoot::Sha256(lhs)), SearchRoot::Sha256(rhs)) if lhs == rhs => Ok(()),
        (Some(SearchRoot::Vector(lhs)), SearchRoot::Vector(rhs))
            if lhs.len() == rhs.len()
                && lhs
                    .iter()
                    .zip(rhs.iter())
                    .all(|(left, right)| (*left - *right).abs() < f32::EPSILON) =>
        {
            Ok(())
        }
        _ => Err(QueryError(
            "only one primary search root is supported per query".to_string(),
        )),
    }
}

fn push_unique_string(values: &mut Vec<String>, value: &str) -> Result<(), QueryError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(QueryError("query values must not be empty".to_string()));
    }
    if !values.iter().any(|existing| existing == normalized) {
        values.push(normalized.to_string());
    }
    Ok(())
}

fn push_unique_collection(values: &mut Vec<QueryCollection>, value: QueryCollection) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_architecture(values: &mut Vec<Architecture>, value: Architecture) {
    if !values.contains(&value) {
        values.push(value);
    }
}
