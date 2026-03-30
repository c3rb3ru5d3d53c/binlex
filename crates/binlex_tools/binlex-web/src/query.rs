use binlex::Architecture;
use binlex::index::local;
use binlex::index::{Collection, LocalIndex, SearchResult};
use binlex::search::{
    Query, QueryCollection, QueryError, QueryExpr, QueryField, QueryTerm, query_date_matches,
    query_size_matches,
};

pub use binlex::search::SearchRoot;

#[derive(Clone, Debug)]
pub struct SearchPlan {
    pub query: Query,
    pub root: Option<SearchRoot>,
    pub corpora: Vec<String>,
    pub collections: Vec<Collection>,
    pub architectures: Vec<Architecture>,
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
    Ok(SearchPlan {
        root: analysis.root,
        corpora,
        collections,
        architectures: analysis.architectures,
        query,
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
    let corpora = index.corpora()?;
    if corpora.is_empty() {
        return Ok(vec![default_corpus.to_string()]);
    }
    Ok(corpora)
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
        QueryField::Corpus => result.corpus().eq_ignore_ascii_case(value),
        QueryField::Collection => result.collection().as_str().eq_ignore_ascii_case(value),
        QueryField::Architecture => result.architecture().eq_ignore_ascii_case(value),
        QueryField::Address => parse_query_address(value) == Some(result.address()),
        QueryField::Date => query_date_matches(value, result.date()),
        QueryField::Size => query_size_matches(value, result.size()),
        QueryField::Symbol => result
            .symbol()
            .map(|symbol| symbol.eq_ignore_ascii_case(value))
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
        let sha256 = index.put(b"web-corpus-sample").expect("store sample");
        let graph = {
            let mut graph = binlex::controlflow::Graph::new(Architecture::AMD64, Config::default());
            let mut instruction =
                binlex::controlflow::Instruction::create(0x1000, Architecture::AMD64, Config::default());
            instruction.bytes = vec![0xC3];
            instruction.pattern = "c3".to_string();
            instruction.is_return = true;
            graph.insert_instruction(instruction);
            assert!(graph.set_block(0x1000));
            assert!(graph.set_function(0x1000));
            graph
        };
        let function =
            binlex::controlflow::Function::new(0x1000, &graph).expect("build function");
        index
            .function(
                &["default".to_string()],
                &function,
                &[1.0; 64],
                &sha256,
                &[],
            )
            .expect("stage function");
        index.commit().expect("commit function");
        index.commit().expect("commit function");
        index
            .add_corpus(&sha256, "malware")
            .expect("add second corpus");

        let plan = build_search_plan(&index, "default", &[Collection::Function], "collection:function")
            .expect("build search plan");

        assert!(plan.corpora.iter().any(|corpus| corpus == "default"));
        assert!(plan.corpora.iter().any(|corpus| corpus == "malware"));

        let _ = std::fs::remove_dir_all(&root);
    }
}
