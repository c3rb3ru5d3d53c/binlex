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

use super::kind::HirType;
use crate::ir::mir::MirValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirValue {
    Named { name: String, ty: HirType },
    Integer { value: i128, bits: u16 },
    Boolean(bool),
    Null { ty: HirType },
    Undef { ty: HirType },
}

impl HirValue {
    pub fn from_mir(value: &MirValue) -> Self {
        match value {
            MirValue::Named { name, ty } => Self::Named {
                name: name.clone(),
                ty: ty.clone(),
            },
            MirValue::Integer { value, bits } => Self::Integer {
                value: *value,
                bits: *bits,
            },
            MirValue::Boolean(value) => Self::Boolean(*value),
            MirValue::Null { ty } => Self::Null { ty: ty.clone() },
            MirValue::Undef { ty } => Self::Undef { ty: ty.clone() },
        }
    }

    pub fn ty(&self) -> HirType {
        match self {
            Self::Named { ty, .. } | Self::Null { ty } | Self::Undef { ty } => ty.clone(),
            Self::Integer { bits, .. } => HirType::integer(*bits),
            Self::Boolean(_) => HirType::integer(1),
        }
    }
}
