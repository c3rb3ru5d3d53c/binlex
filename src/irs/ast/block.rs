use super::statement::AstStatement;
use crate::irs::hir::HirBlock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct AstBlock {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statements: Vec<AstStatement>,
}

impl AstBlock {
    pub fn from_hir(block: &HirBlock) -> Self {
        Self {
            statements: block
                .statements
                .iter()
                .map(AstStatement::from_hir)
                .collect(),
        }
    }
}
