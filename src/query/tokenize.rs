use super::types::{QueryError, QueryField, QueryTerm, QueryToken};
use winnow::Parser;
use winnow::ascii::{Caseless, multispace0};
use winnow::error::ContextError;
use winnow::token::take_while;

pub(super) fn tokenize_search_query(query: &str) -> Result<Vec<QueryToken>, QueryError> {
    let mut input = query;
    let mut tokens = Vec::new();
    while !input.is_empty() {
        skip_query_whitespace(&mut input);
        if input.is_empty() {
            break;
        }
        if let Some(remainder) = input.strip_prefix('(') {
            input = remainder;
            tokens.push(QueryToken::LParen);
            continue;
        }
        if let Some(remainder) = input.strip_prefix(')') {
            input = remainder;
            tokens.push(QueryToken::RParen);
            continue;
        }
        if let Some(operator) = parse_query_operator(&mut input) {
            tokens.push(operator);
            continue;
        }
        let head = parse_query_head(&mut input)?;
        skip_query_whitespace(&mut input);
        let colon_result: winnow::ModalResult<char, ContextError> = ':'.parse_next(&mut input);
        colon_result.map_err(|_| {
            QueryError(format!(
                "unexpected token {}. Use explicit fields like sample:, embedding:, embeddings:, or vector:",
                head
            ))
        })?;
        let field = parse_query_field(&head)?;
        skip_query_whitespace(&mut input);
        let value = match field {
            QueryField::Vector => parse_vector_token_value(&mut input)?,
            QueryField::Symbol => parse_quoted_query_value(&mut input)?,
            _ => parse_simple_query_value(&mut input)?,
        };
        if value.trim().is_empty() {
            return Err(QueryError(format!("{} requires a value", head)));
        }
        tokens.push(QueryToken::Term(QueryTerm { field, value }));
    }
    Ok(tokens)
}

fn parse_query_operator(input: &mut &str) -> Option<QueryToken> {
    if let Some(remainder) = input.strip_prefix("||") {
        *input = remainder;
        return Some(QueryToken::Or);
    }
    if let Some(remainder) = input.strip_prefix('|') {
        *input = remainder;
        return Some(QueryToken::And);
    }
    if let Some(remainder) = input.strip_prefix('!') {
        *input = remainder;
        return Some(QueryToken::Not);
    }
    for (label, token) in [
        ("AND", QueryToken::And),
        ("OR", QueryToken::Or),
        ("NOT", QueryToken::Not),
    ] {
        let checkpoint = *input;
        let keyword_result: winnow::ModalResult<&str, ContextError> =
            Caseless(label).parse_next(input);
        if keyword_result.is_ok() && is_query_boundary(input.chars().next()) {
            return Some(token);
        }
        *input = checkpoint;
    }
    None
}

fn parse_query_head(input: &mut &str) -> Result<String, QueryError> {
    let head_result: winnow::ModalResult<&str, ContextError> = take_while(1.., |ch: char| {
        !ch.is_whitespace()
            && ch != '('
            && ch != ')'
            && ch != ':'
            && ch != '|'
            && ch != '!'
            && ch != '~'
    })
    .parse_next(input);
    head_result
        .map(|head| head.to_string())
        .map_err(|_| QueryError("expected a search term".to_string()))
}

fn skip_query_whitespace(input: &mut &str) {
    let _: winnow::ModalResult<&str, ContextError> = multispace0.parse_next(input);
}

fn parse_simple_query_value(input: &mut &str) -> Result<String, QueryError> {
    let source = *input;
    let mut end = source.len();
    for (offset, ch) in source.char_indices() {
        if ch == '(' || ch == ')' || ch == '|' || ch == '~' {
            end = offset;
            break;
        }
        if ch.is_whitespace() {
            let remainder = &source[offset..];
            if next_query_operator_index(remainder).is_some() {
                end = offset;
                break;
            }
        }
    }
    *input = &source[end..];
    Ok(source[..end].trim().to_string())
}

fn next_query_operator_index(input: &str) -> Option<usize> {
    let mut remainder = input;
    let skipped = input.len() - input.trim_start_matches(char::is_whitespace).len();
    skip_query_whitespace(&mut remainder);
    let found = parse_query_operator(&mut remainder).is_some();
    if found { Some(skipped) } else { None }
}

fn parse_quoted_query_value(input: &mut &str) -> Result<String, QueryError> {
    if !input.starts_with('"') {
        return Err(QueryError(
            "symbol expects a quoted string like symbol:\"kernel32:CreateFileW\"".to_string(),
        ));
    }
    *input = &input[1..];
    let mut value = String::new();
    let mut escaped = false;
    let source = *input;
    let mut close_at = None;
    for (offset, ch) in source.char_indices() {
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => {
                close_at = Some(offset);
                break;
            }
            _ => value.push(ch),
        }
    }
    if let Some(offset) = close_at {
        *input = &source[offset + 1..];
        return Ok(value);
    }
    Err(QueryError("symbol expects a closing quote".to_string()))
}

fn parse_vector_token_value(input: &mut &str) -> Result<String, QueryError> {
    skip_query_whitespace(input);
    if !input.starts_with('[') {
        return Err(QueryError("vector expects a JSON array".to_string()));
    }
    let source = *input;
    let mut depth = 0usize;
    for (offset, ch) in source.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    let end = offset + ch.len_utf8();
                    *input = &source[end..];
                    return Ok(source[..end].to_string());
                }
            }
            _ => {}
        }
    }
    Err(QueryError(
        "vector expects a balanced JSON array".to_string(),
    ))
}

fn is_query_boundary(next: Option<char>) -> bool {
    match next {
        None => true,
        Some(ch) => ch.is_whitespace() || ch == '(' || ch == ')' || ch == '|',
    }
}

fn parse_query_field(value: &str) -> Result<QueryField, QueryError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "sample" => Ok(QueryField::Sha256),
        "lhs" => Ok(QueryField::Sha256),
        "rhs" => Ok(QueryField::Sha256),
        "sha256" => Ok(QueryField::Sha256),
        "embedding" => Ok(QueryField::Embedding),
        "embeddings" => Ok(QueryField::Embeddings),
        "vector" => Ok(QueryField::Vector),
        "score" => Ok(QueryField::Score),
        "corpus" => Ok(QueryField::Corpus),
        "collection" => Ok(QueryField::Collection),
        "architecture" => Ok(QueryField::Architecture),
        "username" => Ok(QueryField::Username),
        "address" => Ok(QueryField::Address),
        "timestamp" => Ok(QueryField::Timestamp),
        "size" => Ok(QueryField::Size),
        "symbol" => Ok(QueryField::Symbol),
        "tag" => Ok(QueryField::Tag),
        "symbols" => Ok(QueryField::Symbols),
        "tags" => Ok(QueryField::Tags),
        "comments" => Ok(QueryField::Comments),
        "cyclomatic_complexity" => Ok(QueryField::CyclomaticComplexity),
        "average_instructions_per_block" => Ok(QueryField::AverageInstructionsPerBlock),
        "instructions" => Ok(QueryField::NumberOfInstructions),
        "blocks" => Ok(QueryField::NumberOfBlocks),
        "markov" => Ok(QueryField::Markov),
        "entropy" => Ok(QueryField::Entropy),
        "contiguous" => Ok(QueryField::Contiguous),
        "chromosome.entropy" => Ok(QueryField::ChromosomeEntropy),
        other => Err(QueryError(format!("unknown search field {}", other))),
    }
}
