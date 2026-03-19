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

use crate::metadata::Attribute;
use serde::{Deserialize, Serialize};

/// Represents a JSON-serializable structure containing metadata about a tag.
#[derive(Serialize, Deserialize, Clone)]
pub struct TagJson {
    /// The type of this entity, always `"tag"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The tag value
    pub value: String,
}

#[derive(Clone)]
pub struct Tag {
    tag: String,
}

impl Tag {
    #[allow(dead_code)]
    pub fn new(tag: String) -> Self {
        Self { tag }
    }

    /// Processes the function signature into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns a `FunctionSymbolJson` struct containing metadata about the function symbol.
    pub fn process(&self) -> TagJson {
        TagJson {
            type_: "tag".to_string(),
            value: self.tag.clone(),
        }
    }

    /// Processes the tag into an `Attribute`.
    ///
    /// # Returns
    ///
    /// Returns a `Attribute` struct containing the tag.
    pub fn attribute(&self) -> Attribute {
        Attribute::Tag(self.process())
    }
}
