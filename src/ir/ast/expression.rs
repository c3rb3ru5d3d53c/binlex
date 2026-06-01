use super::kind::{
    AstAddressSpace, AstBinaryOperation, AstCastOperation, AstCompareOperation,
    AstFloatCompareOperation, AstType, AstUnaryOperation,
};
use super::place::AstPlace;
use super::target::AstTarget;
use super::value::AstValue;
use crate::ir::hir::HirExpression;
use crate::ir::lir::LirAbi;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AstExpression {
    Value(AstValue),
    Unary {
        op: AstUnaryOperation,
        value: Box<AstExpression>,
        ty: AstType,
    },
    Binary {
        op: AstBinaryOperation,
        lhs: Box<AstExpression>,
        rhs: Box<AstExpression>,
        ty: AstType,
    },
    Select {
        condition: Box<AstExpression>,
        when_true: Box<AstExpression>,
        when_false: Box<AstExpression>,
        ty: AstType,
    },
    Concat {
        parts: Vec<AstExpression>,
        ty: AstType,
    },
    Extract {
        value: Box<AstExpression>,
        lsb: u16,
        ty: AstType,
    },
    Load {
        address_space: AstAddressSpace,
        address: Box<AstExpression>,
        ty: AstType,
    },
    Compare {
        op: AstCompareOperation,
        lhs: Box<AstExpression>,
        rhs: Box<AstExpression>,
        ty: AstType,
    },
    FloatCompare {
        op: AstFloatCompareOperation,
        lhs: Box<AstExpression>,
        rhs: Box<AstExpression>,
        ty: AstType,
    },
    Cast {
        op: AstCastOperation,
        value: Box<AstExpression>,
        ty: AstType,
    },
    Call {
        target: AstTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abi: Option<LirAbi>,
        arguments: Vec<AstExpression>,
        return_types: Vec<AstType>,
    },
    Intrinsic {
        name: String,
        arguments: Vec<AstExpression>,
        return_types: Vec<AstType>,
    },
    AddressOf {
        place: Box<AstPlace>,
        ty: AstType,
    },
    Deref {
        pointer: Box<AstExpression>,
        ty: AstType,
    },
    Index {
        base: Box<AstExpression>,
        index: Box<AstExpression>,
        ty: AstType,
    },
}

impl AstExpression {
    pub fn from_hir(expression: &HirExpression) -> Self {
        match expression {
            HirExpression::Value(value) => Self::Value(AstValue::from_hir(value)),
            HirExpression::Unary { op, value, ty } => Self::Unary {
                op: *op,
                value: Box::new(Self::from_hir(value)),
                ty: ty.clone(),
            },
            HirExpression::Binary { op, lhs, rhs, ty } => Self::Binary {
                op: *op,
                lhs: Box::new(Self::from_hir(lhs)),
                rhs: Box::new(Self::from_hir(rhs)),
                ty: ty.clone(),
            },
            HirExpression::Select {
                condition,
                when_true,
                when_false,
                ty,
            } => Self::Select {
                condition: Box::new(Self::from_hir(condition)),
                when_true: Box::new(Self::from_hir(when_true)),
                when_false: Box::new(Self::from_hir(when_false)),
                ty: ty.clone(),
            },
            HirExpression::Concat { parts, ty } => Self::Concat {
                parts: parts.iter().map(Self::from_hir).collect(),
                ty: ty.clone(),
            },
            HirExpression::Extract { value, lsb, ty } => Self::Extract {
                value: Box::new(Self::from_hir(value)),
                lsb: *lsb,
                ty: ty.clone(),
            },
            HirExpression::Load {
                address_space,
                address,
                ty,
            } => Self::Load {
                address_space: address_space.clone(),
                address: Box::new(Self::from_hir(address)),
                ty: ty.clone(),
            },
            HirExpression::Compare { op, lhs, rhs, ty } => Self::Compare {
                op: *op,
                lhs: Box::new(Self::from_hir(lhs)),
                rhs: Box::new(Self::from_hir(rhs)),
                ty: ty.clone(),
            },
            HirExpression::FloatCompare { op, lhs, rhs, ty } => Self::FloatCompare {
                op: *op,
                lhs: Box::new(Self::from_hir(lhs)),
                rhs: Box::new(Self::from_hir(rhs)),
                ty: ty.clone(),
            },
            HirExpression::Cast { op, value, ty } => Self::Cast {
                op: *op,
                value: Box::new(Self::from_hir(value)),
                ty: ty.clone(),
            },
            HirExpression::Call {
                target,
                abi,
                arguments,
                return_types,
            } => Self::Call {
                target: AstTarget::from_hir(target),
                abi: abi.clone(),
                arguments: arguments.iter().map(Self::from_hir).collect(),
                return_types: return_types.clone(),
            },
            HirExpression::Intrinsic {
                name,
                arguments,
                return_types,
            } => Self::Intrinsic {
                name: name.clone(),
                arguments: arguments.iter().map(Self::from_hir).collect(),
                return_types: return_types.clone(),
            },
            HirExpression::AddressOf { place, ty } => Self::AddressOf {
                place: Box::new(AstPlace::from_hir(place)),
                ty: ty.clone(),
            },
            HirExpression::Deref { pointer, ty } => Self::Deref {
                pointer: Box::new(Self::from_hir(pointer)),
                ty: ty.clone(),
            },
            HirExpression::Index { base, index, ty } => Self::Index {
                base: Box::new(Self::from_hir(base)),
                index: Box::new(Self::from_hir(index)),
                ty: ty.clone(),
            },
        }
    }
}
