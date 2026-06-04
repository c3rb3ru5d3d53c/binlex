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

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirAddressSpace {
    Default,
    Stack,
    Heap,
    Global,
    HeapObject { name: String },
    GlobalObject { name: String },
    Io,
    Local { name: String },
    Argument { name: String },
    Spill { name: String },
    Incoming { name: String },
    SavedFrame { name: String },
    ReturnAddress { name: String },
    Named { name: String },
}

impl MirAddressSpace {
    pub fn default_space() -> Self {
        Self::Default
    }

    pub fn stack() -> Self {
        Self::Stack
    }

    pub fn heap() -> Self {
        Self::Heap
    }

    pub fn global() -> Self {
        Self::Global
    }

    pub fn heap_object(name: String) -> Self {
        Self::HeapObject { name }
    }

    pub fn global_object(name: String) -> Self {
        Self::GlobalObject { name }
    }

    pub fn io() -> Self {
        Self::Io
    }

    pub fn local(name: String) -> Self {
        Self::Local { name }
    }

    pub fn argument(name: String) -> Self {
        Self::Argument { name }
    }

    pub fn spill(name: String) -> Self {
        Self::Spill { name }
    }

    pub fn incoming(name: String) -> Self {
        Self::Incoming { name }
    }

    pub fn saved_frame(name: String) -> Self {
        Self::SavedFrame { name }
    }

    pub fn return_address(name: String) -> Self {
        Self::ReturnAddress { name }
    }

    pub fn named(name: String) -> Self {
        Self::Named { name }
    }
}
