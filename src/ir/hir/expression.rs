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

use super::kind::{
    HirAddressSpace, HirBinaryOperation, HirCastOperation, HirCompareOperation,
    HirFloatCompareOperation, HirType, HirUnaryOperation,
};
use super::place::HirPlace;
use super::target::HirTarget;
use super::value::HirValue;
use crate::ir::lir::LirAbi;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirExpression {
    Value(HirValue),
    Unary {
        op: HirUnaryOperation,
        value: Box<HirExpression>,
        ty: HirType,
    },
    Binary {
        op: HirBinaryOperation,
        lhs: Box<HirExpression>,
        rhs: Box<HirExpression>,
        ty: HirType,
    },
    Select {
        condition: Box<HirExpression>,
        when_true: Box<HirExpression>,
        when_false: Box<HirExpression>,
        ty: HirType,
    },
    Concat {
        parts: Vec<HirExpression>,
        ty: HirType,
    },
    Extract {
        value: Box<HirExpression>,
        lsb: u16,
        ty: HirType,
    },
    Load {
        address_space: HirAddressSpace,
        address: Box<HirExpression>,
        ty: HirType,
    },
    Compare {
        op: HirCompareOperation,
        lhs: Box<HirExpression>,
        rhs: Box<HirExpression>,
        ty: HirType,
    },
    FloatCompare {
        op: HirFloatCompareOperation,
        lhs: Box<HirExpression>,
        rhs: Box<HirExpression>,
        ty: HirType,
    },
    Cast {
        op: HirCastOperation,
        value: Box<HirExpression>,
        ty: HirType,
    },
    Call {
        target: HirTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abi: Option<LirAbi>,
        arguments: Vec<HirExpression>,
        return_types: Vec<HirType>,
    },
    Intrinsic {
        name: String,
        arguments: Vec<HirExpression>,
        return_types: Vec<HirType>,
    },
    AddressOf {
        place: Box<HirPlace>,
        ty: HirType,
    },
    Deref {
        pointer: Box<HirExpression>,
        ty: HirType,
    },
    Index {
        base: Box<HirExpression>,
        index: Box<HirExpression>,
        ty: HirType,
    },
}

impl HirExpression {
    pub fn value(value: HirValue) -> Self {
        Self::Value(value)
    }
}
