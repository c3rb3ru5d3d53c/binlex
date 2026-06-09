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
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Import,
    Export,
    Unknown,
}

impl SymbolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Import => "import",
            Self::Export => "export",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Represents a structure containing metadata about a function symbol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Symbol {
    /// Names associated with the function symbol.
    pub name: String,
    /// The file offset of the function symbol.
    pub file_offset: u64,
    /// The virtual address of the function symbol, if available.
    pub virtual_address: Option<u64>,
    /// The relative virtual address of the function symbol, if available.
    pub relative_virtual_address: Option<u64>,
    /// The kind of symbol.
    pub kind: SymbolKind,
}

impl Symbol {
    #[allow(dead_code)]
    pub fn new(
        file_offset: u64,
        virtual_address: Option<u64>,
        relative_virtual_address: Option<u64>,
        kind: SymbolKind,
        name: String,
    ) -> Self {
        Self {
            name,
            file_offset,
            virtual_address,
            relative_virtual_address,
            kind,
        }
    }

    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    pub fn virtual_address(&self) -> Option<u64> {
        self.virtual_address
    }

    pub fn relative_virtual_address(&self) -> Option<u64> {
        self.relative_virtual_address
    }

    /// Demangles a Microsoft Visual C++ (MSVC) mangled symbol name.
    ///
    /// # Arguments
    ///
    /// * `mangled_name` - A string slice representing the mangled symbol name to demangle.
    ///
    /// # Returns
    ///
    /// A `String` containing the demangled symbol name in the form `namespace::...::function_name`.
    /// If the input string does not start with the MSVC mangling prefix `?`, the original string
    /// is returned unchanged.
    #[allow(dead_code)]
    pub fn demangle_msvc_name(mangled_name: &str) -> String {
        if !mangled_name.starts_with('?') {
            return mangled_name.to_owned();
        }
        let parts = mangled_name
            .trim_start_matches('?')
            .split('@')
            .collect::<Vec<_>>();
        let function_name = parts.first().copied().unwrap_or(mangled_name);
        let mut namespaces: Vec<_> = parts
            .iter()
            .skip(1)
            .take_while(|s| !s.is_empty())
            .copied()
            .collect();
        namespaces.reverse();
        format!("{}::{}", namespaces.join("::"), function_name)
    }
}
