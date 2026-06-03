use super::expression::AstExpression;
use super::kind::{AstAddressSpace, AstType};
use crate::ir::hir::HirPlace;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AstPlace {
    Named {
        name: String,
        ty: AstType,
    },
    Dereference {
        pointer: Box<AstExpression>,
        ty: AstType,
    },
    Memory {
        address_space: AstAddressSpace,
        address: Box<AstExpression>,
        ty: AstType,
    },
    Index {
        base: Box<AstExpression>,
        index: Box<AstExpression>,
        ty: AstType,
    },
}

impl AstPlace {
    pub fn from_hir(place: &HirPlace) -> Self {
        match place {
            HirPlace::Named { name, ty } => Self::Named {
                name: name.clone(),
                ty: ty.clone(),
            },
            HirPlace::Dereference { pointer, ty } => Self::Dereference {
                pointer: Box::new(AstExpression::from_hir(pointer)),
                ty: ty.clone(),
            },
            HirPlace::Memory {
                address_space,
                address,
                ty,
            } => Self::Memory {
                address_space: address_space.clone(),
                address: Box::new(AstExpression::from_hir(address)),
                ty: ty.clone(),
            },
            HirPlace::Index { base, index, ty } => Self::Index {
                base: Box::new(AstExpression::from_hir(base)),
                index: Box::new(AstExpression::from_hir(index)),
                ty: ty.clone(),
            },
        }
    }
}
