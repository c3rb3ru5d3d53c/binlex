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
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirValue {
    Named { name: String, ty: MirType },
    Integer { value: i128, bits: u16 },
    Boolean(bool),
    Null { ty: MirType },
    Undef { ty: MirType },
}

impl MirValue {
    pub fn named(name: String, ty: MirType) -> Self {
        Self::Named { name, ty }
    }

    pub fn integer(value: i128, bits: u16) -> Self {
        Self::Integer { value, bits }
    }

    pub fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }

    pub fn null(ty: MirType) -> Self {
        Self::Null { ty }
    }

    pub fn undef(ty: MirType) -> Self {
        Self::Undef { ty }
    }
}
