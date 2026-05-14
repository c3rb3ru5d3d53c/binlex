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

use super::kind::{MirCastOperation, MirCompareOperation, MirType};
use super::memory::MirAddressSpace;
use super::value::MirValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MirCallClobber {
    pub register: String,
    pub ty: MirType,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirOperationKind {
    Add {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    Sub {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    Mul {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    And {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    Or {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    Xor {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    Shl {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    LShr {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    AShr {
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    Select {
        condition: MirValue,
        when_true: MirValue,
        when_false: MirValue,
        ty: MirType,
    },
    Extract {
        value: MirValue,
        lsb: u16,
        ty: MirType,
    },
    Not {
        value: MirValue,
        ty: MirType,
    },
    Popcount {
        value: MirValue,
        ty: MirType,
    },
    Load {
        address_space: MirAddressSpace,
        address: MirValue,
        ty: MirType,
    },
    Store {
        address_space: MirAddressSpace,
        address: MirValue,
        value: MirValue,
        ty: MirType,
    },
    Icmp {
        op: MirCompareOperation,
        lhs: MirValue,
        rhs: MirValue,
        ty: MirType,
    },
    Cast {
        op: MirCastOperation,
        value: MirValue,
        ty: MirType,
    },
    Call {
        target: String,
        arguments: Vec<MirValue>,
        result_types: Vec<MirType>,
        clobbers: Vec<MirCallClobber>,
        memory_effects: Vec<MirAddressSpace>,
    },
    Intrinsic {
        name: String,
        arguments: Vec<MirValue>,
        result_types: Vec<MirType>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MirOperation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    pub kind: MirOperationKind,
}

impl MirOperation {
    pub fn new(result: Option<String>, kind: MirOperationKind) -> Self {
        Self { result, kind }
    }
}
