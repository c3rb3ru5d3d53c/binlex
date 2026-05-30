use super::kind::AstType;
use crate::ir::hir::HirValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AstValue {
    Named { name: String, ty: AstType },
    Integer { value: i128, bits: u16 },
    Boolean(bool),
    Null { ty: AstType },
    Undef { ty: AstType },
}

impl AstValue {
    pub fn from_hir(value: &HirValue) -> Self {
        match value {
            HirValue::Named { name, ty } => Self::Named {
                name: name.clone(),
                ty: ty.clone(),
            },
            HirValue::Integer { value, bits } => Self::Integer {
                value: *value,
                bits: *bits,
            },
            HirValue::Boolean(value) => Self::Boolean(*value),
            HirValue::Null { ty } => Self::Null { ty: ty.clone() },
            HirValue::Undef { ty } => Self::Undef { ty: ty.clone() },
        }
    }

    pub fn ty(&self) -> AstType {
        match self {
            Self::Named { ty, .. } | Self::Null { ty } | Self::Undef { ty } => ty.clone(),
            Self::Integer { bits, .. } => AstType::integer(*bits),
            Self::Boolean(_) => AstType::integer(1),
        }
    }
}
