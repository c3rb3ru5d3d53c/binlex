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

use super::kind::MirType;
use super::operation::MirOperation;
use super::terminator::MirTerminator;
use crate::ir::lir::LirBlock;
use crate::ir::mir::lower::{MirLowerError, lower_lir_block_to_mir};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MirBlockParameter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ty: MirType,
}

impl MirBlockParameter {
    pub fn new(name: Option<String>, ty: MirType) -> Self {
        Self { name, ty }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MirBlock {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<MirBlockParameter>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<MirOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminator: Option<MirTerminator>,
}

impl MirBlock {
    pub fn from_lir(name: Option<String>, lir: &LirBlock) -> Result<Self, MirLowerError> {
        lower_lir_block_to_mir(name, lir)
    }

    pub fn new(name: String) -> Self {
        Self {
            name,
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: None,
        }
    }

    pub fn append_parameter(&mut self, parameter: MirBlockParameter) {
        self.parameters.push(parameter);
    }

    pub fn append_operation(&mut self, operation: MirOperation) {
        self.operations.push(operation);
    }

    pub fn set_terminator(&mut self, terminator: MirTerminator) {
        self.terminator = Some(terminator);
    }
}
