// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::expression::HirExpression;
use super::kind::HirType;
use super::place::HirPlace;
use super::target::HirTarget;
use super::value::HirValue;
use crate::irs::storage::IrStorage;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HirParameter {
    pub name: String,
    pub ty: HirType,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HirLocal {
    pub name: String,
    pub ty: HirType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<HirExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<IrStorage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HirSwitchCase {
    pub value: HirValue,
    pub body: super::block::HirBlock,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirStatement {
    Assign {
        target: HirPlace,
        value: HirExpression,
    },
    Expr(HirExpression),
    If {
        condition: HirExpression,
        then_body: super::block::HirBlock,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        else_body: Option<super::block::HirBlock>,
    },
    While {
        condition: HirExpression,
        body: super::block::HirBlock,
    },
    Loop {
        body: super::block::HirBlock,
    },
    Switch {
        value: HirExpression,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        cases: Vec<HirSwitchCase>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default: Option<super::block::HirBlock>,
    },
    Break,
    Continue,
    Return {
        values: Vec<HirExpression>,
    },
    Label(String),
    Goto(HirTarget),
    Trap,
    Unreachable,
}
