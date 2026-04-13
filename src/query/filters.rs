use chrono::{DateTime, Duration, Months, NaiveDate, TimeZone, Utc};

pub fn query_timestamp_matches(raw: &str, actual: DateTime<Utc>) -> bool {
    let Some(filter) = parse_date_query(raw) else {
        return false;
    };
    match filter.operator {
        DateOperator::Eq => actual >= filter.start && actual < filter.end,
        DateOperator::Gt => actual >= filter.end,
        DateOperator::Gte => actual >= filter.start,
        DateOperator::Lt => actual < filter.start,
        DateOperator::Lte => actual < filter.end,
    }
}

pub fn query_size_matches(raw: &str, actual: u64) -> bool {
    let Some((operator, expected)) = parse_size_query(raw) else {
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

pub fn query_score_matches(raw: &str, actual: f32) -> bool {
    query_float_matches(raw, actual as f64)
}

pub fn query_integer_matches(raw: &str, actual: u64) -> bool {
    let Some((operator, expected)) = parse_integer_query(raw) else {
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

pub fn query_float_matches(raw: &str, actual: f64) -> bool {
    let Some((operator, expected)) = parse_score_query(raw) else {
        return false;
    };
    match operator {
        ScoreOperator::Eq => (actual - expected as f64).abs() < f64::EPSILON,
        ScoreOperator::Gt => actual > expected as f64,
        ScoreOperator::Gte => actual >= expected as f64,
        ScoreOperator::Lt => actual < expected as f64,
        ScoreOperator::Lte => actual <= expected as f64,
    }
}

pub fn query_bool_matches(raw: &str, actual: bool) -> bool {
    parse_bool_query(raw) == Some(actual)
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(super) fn parse_query_vector(value: &str) -> Option<Vec<f32>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.starts_with('[') {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let values = parsed.as_array()?;
    if values.len() < 2 {
        return None;
    }
    values
        .iter()
        .map(|item| item.as_f64().map(|number| number as f32))
        .collect()
}

pub(super) fn parse_integer_query(raw: &str) -> Option<(CountOperator, u64)> {
    parse_count_query(raw)
}

pub(super) fn parse_positive_count_query(raw: &str) -> Option<(CountOperator, u64)> {
    let (operator, value) = parse_count_query(raw)?;
    if value == 0 {
        return None;
    }
    Some((operator, value))
}

pub(super) fn parse_float_query(raw: &str) -> Option<(ScoreOperator, f32)> {
    parse_score_query(raw)
}

pub(super) fn parse_bool_query(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CountOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DateOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum ScoreOperator {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DateFilter {
    operator: DateOperator,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

pub(super) fn parse_date_query(raw: &str) -> Option<DateFilter> {
    let trimmed = raw.trim();
    let (operator, remainder) = if let Some(value) = trimmed.strip_prefix(">=") {
        (DateOperator::Gte, value)
    } else if let Some(value) = trimmed.strip_prefix("<=") {
        (DateOperator::Lte, value)
    } else if let Some(value) = trimmed.strip_prefix('>') {
        (DateOperator::Gt, value)
    } else if let Some(value) = trimmed.strip_prefix('<') {
        (DateOperator::Lt, value)
    } else if let Some(value) = trimmed.strip_prefix('=') {
        (DateOperator::Eq, value)
    } else {
        (DateOperator::Eq, trimmed)
    };
    let value = remainder.trim();
    let (start, end) = parse_date_span(value)?;
    Some(DateFilter {
        operator,
        start,
        end,
    })
}

fn parse_date_span(raw: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let trimmed = raw.trim();
    if trimmed.len() == 4 {
        let year = trimmed.parse::<i32>().ok()?;
        let start = Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).single()?;
        let end = Utc.with_ymd_and_hms(year + 1, 1, 1, 0, 0, 0).single()?;
        return Some((start, end));
    }
    if trimmed.len() == 7 {
        let date = NaiveDate::parse_from_str(&format!("{trimmed}-01"), "%Y-%m-%d").ok()?;
        let start = Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?);
        let next = date.checked_add_months(Months::new(1))?;
        let end = Utc.from_utc_datetime(&next.and_hms_opt(0, 0, 0)?);
        return Some((start, end));
    }
    if trimmed.len() == 10 {
        let date = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").ok()?;
        let start = Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?);
        let end = start.checked_add_signed(Duration::days(1))?;
        return Some((start, end));
    }
    None
}

pub(super) fn parse_size_query(raw: &str) -> Option<(CountOperator, u64)> {
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
    parse_size_bytes(remainder).map(|value| (operator, value))
}

pub(super) fn parse_score_query(raw: &str) -> Option<(ScoreOperator, f32)> {
    let trimmed = raw.trim();
    let (operator, remainder) = if let Some(value) = trimmed.strip_prefix(">=") {
        (ScoreOperator::Gte, value)
    } else if let Some(value) = trimmed.strip_prefix("<=") {
        (ScoreOperator::Lte, value)
    } else if let Some(value) = trimmed.strip_prefix('>') {
        (ScoreOperator::Gt, value)
    } else if let Some(value) = trimmed.strip_prefix('<') {
        (ScoreOperator::Lt, value)
    } else if let Some(value) = trimmed.strip_prefix('=') {
        (ScoreOperator::Eq, value)
    } else {
        (ScoreOperator::Eq, trimmed)
    };
    let value = remainder.trim().parse::<f32>().ok()?;
    if !value.is_finite() {
        return None;
    }
    Some((operator, value))
}

fn parse_size_bytes(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, multiplier) = if let Some(value) = lower.strip_suffix("kb") {
        (value, 1024f64)
    } else if let Some(value) = lower.strip_suffix("mb") {
        (value, 1024f64 * 1024f64)
    } else if let Some(value) = lower.strip_suffix("gb") {
        (value, 1024f64 * 1024f64 * 1024f64)
    } else if let Some(value) = lower.strip_suffix('b') {
        (value, 1f64)
    } else {
        (lower.as_str(), 1f64)
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
