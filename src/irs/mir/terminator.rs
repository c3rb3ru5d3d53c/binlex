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

use super::kind::MirTerminatorKind;
use super::target::MirControlTarget;
use super::value::MirValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirTerminator {
    Jump {
        target: MirControlTarget,
        arguments: Vec<MirValue>,
    },
    CondBr {
        condition: MirValue,
        then_target: MirControlTarget,
        then_arguments: Vec<MirValue>,
        else_target: MirControlTarget,
        else_arguments: Vec<MirValue>,
    },
    Return {
        values: Vec<MirValue>,
    },
    Trap,
    Unreachable,
}

impl MirTerminator {
    pub fn kind(&self) -> MirTerminatorKind {
        match self {
            Self::Jump { .. } => MirTerminatorKind::Jump,
            Self::CondBr { .. } => MirTerminatorKind::CondBr,
            Self::Return { .. } => MirTerminatorKind::Return,
            Self::Trap => MirTerminatorKind::Trap,
            Self::Unreachable => MirTerminatorKind::Unreachable,
        }
    }
}
