use super::expression::AstExpression;
use crate::ir::hir::HirTarget;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AstTarget {
    Direct(String),
    Indirect(Box<AstExpression>),
}

impl AstTarget {
    pub fn from_hir(target: &HirTarget) -> Self {
        match target {
            HirTarget::Direct(name) => Self::Direct(name.clone()),
            HirTarget::Indirect(expression) => {
                Self::Indirect(Box::new(AstExpression::from_hir(expression)))
            }
        }
    }
}
