use super::types::{QueryError, QueryExpr, QueryToken};

pub(super) fn parse_search_query(tokens: &[QueryToken]) -> Result<QueryExpr, QueryError> {
    struct Parser<'a> {
        tokens: &'a [QueryToken],
        index: usize,
    }

    impl<'a> Parser<'a> {
        fn parse_or(&mut self) -> Result<QueryExpr, QueryError> {
            let mut expr = self.parse_and()?;
            while matches!(self.tokens.get(self.index), Some(QueryToken::Or)) {
                self.index += 1;
                let rhs = self
                    .parse_and()
                    .map_err(|_| QueryError("expected a search term after ||".to_string()))?;
                expr = QueryExpr::Or(Box::new(expr), Box::new(rhs));
            }
            Ok(expr)
        }

        fn parse_and(&mut self) -> Result<QueryExpr, QueryError> {
            let mut expr = self.parse_not()?;
            while matches!(self.tokens.get(self.index), Some(QueryToken::And)) {
                self.index += 1;
                let rhs = self
                    .parse_not()
                    .map_err(|_| QueryError("expected a search term after |".to_string()))?;
                expr = QueryExpr::And(Box::new(expr), Box::new(rhs));
            }
            Ok(expr)
        }

        fn parse_not(&mut self) -> Result<QueryExpr, QueryError> {
            if matches!(self.tokens.get(self.index), Some(QueryToken::Not)) {
                self.index += 1;
                if matches!(self.tokens.get(self.index), Some(QueryToken::Not)) {
                    return Err(QueryError(
                        "consecutive ! operators are not allowed".to_string(),
                    ));
                }
                return Ok(QueryExpr::Not(Box::new(self.parse_not().map_err(
                    |_| QueryError("expected a search term after !".to_string()),
                )?)));
            }
            self.parse_primary()
        }

        fn parse_primary(&mut self) -> Result<QueryExpr, QueryError> {
            match self.tokens.get(self.index) {
                Some(QueryToken::Term(term)) => {
                    self.index += 1;
                    Ok(QueryExpr::Term(term.clone()))
                }
                Some(QueryToken::LParen) => {
                    self.index += 1;
                    if matches!(self.tokens.get(self.index), Some(QueryToken::RParen) | None) {
                        return Err(QueryError(
                            "expected a search term inside parenthesis".to_string(),
                        ));
                    }
                    let expr = self.parse_or().map_err(|_| {
                        QueryError("expected a search term inside parenthesis".to_string())
                    })?;
                    match self.tokens.get(self.index) {
                        Some(QueryToken::RParen) => {
                            self.index += 1;
                            Ok(expr)
                        }
                        _ => Err(QueryError("unclosed parenthesis".to_string())),
                    }
                }
                Some(_) => Err(QueryError("expected a search term".to_string())),
                None if self.index == 0 => Err(QueryError("enter a search query".to_string())),
                None => Err(QueryError("expected a search term".to_string())),
            }
        }
    }

    let mut parser = Parser { tokens, index: 0 };
    let expr = parser.parse_or()?;
    if parser.index != tokens.len() {
        return Err(QueryError(
            "unexpected trailing tokens in query".to_string(),
        ));
    }
    Ok(expr)
}
