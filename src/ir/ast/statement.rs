use super::block::AstBlock;
use super::expression::AstExpression;
use super::kind::AstType;
use super::place::AstPlace;
use super::target::AstTarget;
use super::value::AstValue;
use crate::ir::hir::{HirLocal, HirParameter, HirStatement, HirSwitchCase};
use crate::ir::storage::IrStorage;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AstParameter {
    pub name: String,
    pub ty: AstType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl AstParameter {
    pub fn from_hir(parameter: &HirParameter) -> Self {
        Self {
            name: parameter.name.clone(),
            ty: parameter.ty.clone(),
            comment: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AstLocal {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub ty: AstType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<AstExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<IrStorage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl AstLocal {
    pub fn from_hir(local: &HirLocal) -> Self {
        Self {
            name: local.name.clone(),
            display_name: None,
            ty: local.ty.clone(),
            init: local.init.as_ref().map(AstExpression::from_hir),
            storage: local.storage.clone(),
            comment: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AstSwitchCase {
    pub value: AstValue,
    pub body: AstBlock,
}

impl AstSwitchCase {
    pub fn from_hir(case: &HirSwitchCase) -> Self {
        Self {
            value: AstValue::from_hir(&case.value),
            body: AstBlock::from_hir(&case.body),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AstStatement {
    Comment(String),
    Assign {
        target: AstPlace,
        value: AstExpression,
    },
    Expr(AstExpression),
    If {
        condition: AstExpression,
        then_body: AstBlock,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        else_body: Option<AstBlock>,
    },
    While {
        condition: AstExpression,
        body: AstBlock,
    },
    Loop {
        body: AstBlock,
    },
    Switch {
        value: AstExpression,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        cases: Vec<AstSwitchCase>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default: Option<AstBlock>,
    },
    Break,
    Continue,
    Return {
        values: Vec<AstExpression>,
    },
    Label(String),
    Goto(AstTarget),
    Trap,
    Unreachable,
}

impl AstStatement {
    pub fn from_hir(statement: &HirStatement) -> Self {
        match statement {
            HirStatement::Assign { target, value } => Self::Assign {
                target: AstPlace::from_hir(target),
                value: AstExpression::from_hir(value),
            },
            HirStatement::Expr(value) => Self::Expr(AstExpression::from_hir(value)),
            HirStatement::If {
                condition,
                then_body,
                else_body,
            } => Self::If {
                condition: AstExpression::from_hir(condition),
                then_body: AstBlock::from_hir(then_body),
                else_body: else_body.as_ref().map(AstBlock::from_hir),
            },
            HirStatement::While { condition, body } => Self::While {
                condition: AstExpression::from_hir(condition),
                body: AstBlock::from_hir(body),
            },
            HirStatement::Loop { body } => Self::Loop {
                body: AstBlock::from_hir(body),
            },
            HirStatement::Switch {
                value,
                cases,
                default,
            } => Self::Switch {
                value: AstExpression::from_hir(value),
                cases: cases.iter().map(AstSwitchCase::from_hir).collect(),
                default: default.as_ref().map(AstBlock::from_hir),
            },
            HirStatement::Break => Self::Break,
            HirStatement::Continue => Self::Continue,
            HirStatement::Return { values } => Self::Return {
                values: values.iter().map(AstExpression::from_hir).collect(),
            },
            HirStatement::Label(label) => Self::Label(label.clone()),
            HirStatement::Goto(target) => Self::Goto(AstTarget::from_hir(target)),
            HirStatement::Trap => Self::Trap,
            HirStatement::Unreachable => Self::Unreachable,
        }
    }
}
