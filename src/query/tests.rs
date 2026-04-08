use super::*;
use chrono::{TimeZone, Utc};

#[test]
fn tokenizer_preserves_vector_json_array() {
    let query = Query::parse("vector: [0.1, -0.2, 0.3] | collection: functions").unwrap();
    match query.expr() {
        QueryExpr::And(lhs, _) => match lhs.as_ref() {
            QueryExpr::Term(term) => {
                assert_eq!(term.field, QueryField::Vector);
                assert_eq!(term.value, "[0.1, -0.2, 0.3]");
            }
            other => panic!("unexpected lhs: {:?}", other),
        },
        other => panic!("unexpected expr: {:?}", other),
    }
}

#[test]
fn tokenizer_supports_embedding_field() {
    let query =
        Query::parse("embedding: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    match query.expr() {
        QueryExpr::Term(term) => {
            assert_eq!(term.field, QueryField::Embedding);
            assert_eq!(
                term.value,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            );
        }
        other => panic!("unexpected token: {:?}", other),
    }
}

#[test]
fn tokenizer_accepts_terms_without_space_after_colon() {
    let query = Query::parse("collection:functions | architecture:amd64").unwrap();
    match query.expr() {
        QueryExpr::And(lhs, rhs) => {
            match lhs.as_ref() {
                QueryExpr::Term(term) => {
                    assert_eq!(term.field, QueryField::Collection);
                    assert_eq!(term.value, "functions");
                }
                other => panic!("unexpected lhs: {:?}", other),
            }
            match rhs.as_ref() {
                QueryExpr::Term(term) => {
                    assert_eq!(term.field, QueryField::Architecture);
                    assert_eq!(term.value, "amd64");
                }
                other => panic!("unexpected rhs: {:?}", other),
            }
        }
        other => panic!("unexpected expr: {:?}", other),
    }
}

#[test]
fn tokenizer_accepts_space_before_colon() {
    let query = Query::parse("collection : functions | architecture : amd64").unwrap();
    match query.expr() {
        QueryExpr::And(lhs, rhs) => {
            match lhs.as_ref() {
                QueryExpr::Term(term) => {
                    assert_eq!(term.field, QueryField::Collection);
                    assert_eq!(term.value, "functions");
                }
                other => panic!("unexpected lhs: {:?}", other),
            }
            match rhs.as_ref() {
                QueryExpr::Term(term) => {
                    assert_eq!(term.field, QueryField::Architecture);
                    assert_eq!(term.value, "amd64");
                }
                other => panic!("unexpected rhs: {:?}", other),
            }
        }
        other => panic!("unexpected expr: {:?}", other),
    }
}

#[test]
fn parser_gives_and_higher_precedence_than_or() {
    let query = Query::parse("symbol: \"a\" || symbol: \"b\" | corpus: default").unwrap();
    match query.expr() {
        QueryExpr::Or(_, rhs) => match rhs.as_ref() {
            QueryExpr::And(_, _) => {}
            other => panic!("unexpected rhs: {:?}", other),
        },
        other => panic!("unexpected expr: {:?}", other),
    }
}

#[test]
fn root_terms_are_rejected_inside_or() {
    let query = Query::parse(
        "lhs: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef || corpus: default",
    )
    .unwrap();
    let error = query.analyze().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sha256 queries can only be combined with `|`")
    );
}

#[test]
fn embedding_root_terms_are_rejected_inside_or() {
    let query = Query::parse(
        "embedding: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef || corpus: default",
    )
    .unwrap();
    let error = query.analyze().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("embedding queries can only be combined with `|`")
    );
}

#[test]
fn negated_sha256_is_allowed_with_vector_root() {
    let query = Query::parse(
        "vector: [0.1, 0.2] | collection: functions | architecture: amd64 | !lhs: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    let analysis = query.analyze().unwrap();
    assert!(matches!(analysis.root, Some(SearchRoot::Vector(_))));
}

#[test]
fn negated_sha256_or_group_is_allowed_with_vector_root() {
    let query = Query::parse(
        "vector: [0.1, 0.2] | collection: functions | architecture: amd64 | !(lhs: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef || rhs: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210)",
    )
    .unwrap();
    let analysis = query.analyze().unwrap();
    assert!(matches!(analysis.root, Some(SearchRoot::Vector(_))));
}

#[test]
fn symbol_requires_quoted_string() {
    let error = Query::parse("symbol: kernel32:CreateFileW").unwrap_err();
    assert!(error.to_string().contains("quoted string"));
}

#[test]
fn symbol_supports_escaped_quotes() {
    let query = Query::parse(r#"symbol:"a\"b""#).unwrap();
    match query.expr() {
        QueryExpr::Term(term) => {
            assert_eq!(term.field, QueryField::Symbol);
            assert_eq!(term.value, "a\"b");
        }
        other => panic!("unexpected expr: {:?}", other),
    }
}

#[test]
fn username_parses_as_simple_filter() {
    let query = Query::parse("username:anonymous").unwrap();
    match query.expr() {
        QueryExpr::Term(term) => {
            assert_eq!(term.field, QueryField::Username);
            assert_eq!(term.value, "anonymous");
        }
        other => panic!("unexpected expr: {:?}", other),
    }
}

#[test]
fn analyze_returns_language_level_filters() {
    let query = Query::parse(
        "embedding: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | corpus: default | collection:functions | architecture:amd64",
    )
    .unwrap();
    let analysis = query.analyze().unwrap();
    assert_eq!(analysis.corpora, vec!["default".to_string()]);
    assert_eq!(analysis.collections, vec![QueryCollection::Function]);
    assert_eq!(analysis.architectures, vec![crate::Architecture::AMD64]);
    assert!(matches!(analysis.root, Some(SearchRoot::Embedding(_))));
}

#[test]
fn embeddings_reject_invalid_count_syntax() {
    let query = Query::parse("embeddings:>>1k").unwrap();
    let error = query.analyze().unwrap_err();
    assert!(error.to_string().contains("embeddings expects counts"));
}

#[test]
fn embeddings_reject_zero_counts() {
    for raw in [
        "embeddings:0",
        "embeddings:=0",
        "embeddings:>0",
        "embeddings:<0",
    ] {
        let query = Query::parse(raw).unwrap();
        let error = query.analyze().unwrap_err();
        assert!(error.to_string().contains("embeddings expects counts"));
    }
}

#[test]
fn entity_count_filters_accept_zero_bounds() {
    for raw in [
        "symbols:>0",
        "symbols:>=0",
        "tags:>0",
        "tags:>=0",
        "comments:>=0",
    ] {
        Query::parse(raw).unwrap().analyze().unwrap();
    }
}

#[test]
fn date_accepts_supported_forms() {
    for raw in [
        "timestamp:2026",
        "timestamp:2026-03",
        "timestamp:2026-03-30",
        "timestamp:>=2026-03-01",
        "timestamp:<=2026-03-31",
    ] {
        Query::parse(raw).unwrap().analyze().unwrap();
    }
}

#[test]
fn date_rejects_invalid_forms() {
    for raw in [
        "timestamp:2026-3",
        "timestamp:2026-03-3",
        "timestamp:2026-13",
        "timestamp:bogus",
    ] {
        let query = Query::parse(raw).unwrap();
        let error = query.analyze().unwrap_err();
        assert!(error.to_string().contains("timestamp expects"));
    }
}

#[test]
fn date_filter_matches_exact_and_comparison_forms() {
    let actual = Utc
        .with_ymd_and_hms(2026, 3, 30, 18, 25, 0)
        .single()
        .unwrap();
    assert!(query_timestamp_matches("2026", actual));
    assert!(query_timestamp_matches("2026-03", actual));
    assert!(query_timestamp_matches("2026-03-30", actual));
    assert!(query_timestamp_matches(">=2026-03-01", actual));
    assert!(query_timestamp_matches("<=2026-03-31", actual));
    assert!(!query_timestamp_matches("<2026-03", actual));
    assert!(!query_timestamp_matches(">2026-03", actual));
    assert!(!query_timestamp_matches("2026-04", actual));
}

#[test]
fn size_accepts_supported_forms() {
    for raw in ["size:32", "size:>64", "size:>=1kb", "size:<1mb"] {
        Query::parse(raw).unwrap().analyze().unwrap();
    }
}

#[test]
fn size_rejects_invalid_forms() {
    let query = Query::parse("size:>1tb").unwrap();
    let error = query.analyze().unwrap_err();
    assert!(error.to_string().contains("size expects"));
}

#[test]
fn size_filter_matches_comparison_forms() {
    assert!(query_size_matches("32", 32));
    assert!(query_size_matches(">64", 65));
    assert!(query_size_matches(">=1kb", 1024));
    assert!(query_size_matches("<1mb", 1024));
    assert!(!query_size_matches(">1mb", 1024));
}

#[test]
fn score_accepts_supported_forms() {
    for raw in ["score:0.95", "score:>0.9", "score:>=1.0", "score:<0.5"] {
        Query::parse(raw).unwrap().analyze().unwrap();
    }
}

#[test]
fn score_rejects_invalid_forms() {
    let query = Query::parse("score:bogus").unwrap();
    let error = query.analyze().unwrap_err();
    assert!(error.to_string().contains("score expects"));
}

#[test]
fn score_filter_matches_comparison_forms() {
    assert!(query_score_matches("0.95", 0.95));
    assert!(query_score_matches(">0.9", 0.95));
    assert!(query_score_matches(">=0.95", 0.95));
    assert!(query_score_matches("<1.0", 0.95));
    assert!(!query_score_matches(">1.0", 0.95));
}

#[test]
fn structural_metric_filters_accept_supported_forms() {
    for raw in [
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | cyclomatic_complexity:1",
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | average_instructions_per_block:>0",
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | instructions:1",
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | blocks:1",
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | markov:>0",
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | entropy:>0",
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | contiguous:true",
        "sample:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | chromosome.entropy:>0",
    ] {
        Query::parse(raw).unwrap().analyze().unwrap();
    }
}

#[test]
fn address_rejects_invalid_syntax() {
    let query = Query::parse("address:xyz").unwrap();
    let error = query.analyze().unwrap_err();
    assert_eq!(error.to_string(), "invalid address xyz");
}

#[test]
fn incomplete_and_reports_specific_error() {
    let error = Query::parse("collection:functions |").unwrap_err();
    assert_eq!(error.to_string(), "expected a search term after |");
}

#[test]
fn incomplete_not_reports_specific_error() {
    let error = Query::parse("collection:functions | !").unwrap_err();
    assert_eq!(error.to_string(), "expected a search term after |");
}

#[test]
fn incomplete_parenthesis_reports_specific_error() {
    let error = Query::parse("collection:functions | !(").unwrap_err();
    assert_eq!(error.to_string(), "expected a search term after |");
}

#[test]
fn empty_parenthesis_reports_specific_error() {
    let error = Query::parse("collection:functions | !( )").unwrap_err();
    assert_eq!(error.to_string(), "expected a search term after |");
}

#[test]
fn bare_not_group_reports_specific_error() {
    let error = Query::parse("!(").unwrap_err();
    assert_eq!(error.to_string(), "expected a search term after !");
}

#[test]
fn consecutive_not_is_rejected() {
    let error = Query::parse("lhs:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef | ! !collection:functions")
        .unwrap_err();
    assert_eq!(error.to_string(), "expected a search term after |");
}
