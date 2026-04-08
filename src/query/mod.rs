mod analysis;
mod filters;
mod parse;
#[cfg(test)]
mod tests;
mod tokenize;
mod types;

use analysis::analyze_query_expr;
use parse::parse_search_query;
use tokenize::tokenize_search_query;

pub use filters::{
    query_bool_matches, query_float_matches, query_integer_matches, query_score_matches,
    query_size_matches, query_timestamp_matches,
};
pub use types::{
    Query, QueryAnalysis, QueryCollection, QueryCompletionSpec, QueryError, QueryExpr, QueryField,
    QueryTerm, SearchRoot, query_architecture_values, query_collection_values,
    query_completion_specs,
};

impl Query {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, QueryError> {
        let raw = input.as_ref().to_string();
        let tokens = tokenize_search_query(&raw)?;
        let expr = parse_search_query(&tokens)?;
        Ok(Self { raw, expr })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn expr(&self) -> &QueryExpr {
        &self.expr
    }

    pub fn analyze(&self) -> Result<QueryAnalysis, QueryError> {
        let mut analysis = QueryAnalysis::default();
        analyze_query_expr(&self.expr, &mut analysis, false, false)?;
        Ok(analysis)
    }
}
