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

use crate::controlflow::Attribute;
use serde::{Deserialize, Serialize};
use std::io::Error;

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

    /// Prints the JSON representation of the function symbol to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }

    /// Converts the function symbol metadata into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }
}
