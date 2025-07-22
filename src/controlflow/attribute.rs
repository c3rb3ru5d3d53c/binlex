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

use crate::controlflow::SymbolJson;
use crate::controlflow::TagJson;
use crate::formats::file::FileJson;
use serde_json::json;
use serde_json::Value;
use std::io::Error;

#[derive(Clone)]
pub enum Attribute {
    File(FileJson),
    Symbol(SymbolJson),
    Tag(TagJson),
}

impl Attribute {
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Attribute::File(file_json) => serde_json::to_value(file_json).unwrap_or(json!({})),
            Attribute::Symbol(symbol_json) => {
                serde_json::to_value(symbol_json).unwrap_or(json!({}))
            }
            Attribute::Tag(tag_json) => serde_json::to_value(tag_json).unwrap_or(json!({})),
        }
    }
}

#[derive(Clone)]
pub struct Attributes {
    pub values: Vec<Attribute>,
}

impl Attributes {
    pub fn new() -> Self {
        Self {
            values: Vec::<Attribute>::new(),
        }
    }

    pub fn push(&mut self, attribute: Attribute) {
        self.values.push(attribute);
    }

    pub fn pop(&mut self) -> Option<Attribute> {
        self.values.pop()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn process(&self) -> Value {
        let json_list: Vec<Value> = self
            .values
            .iter()
            .map(|attribute| attribute.to_json_value())
            .collect();
        json!(json_list)
    }

    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }
}

impl Default for Attributes {
    fn default() -> Self {
        Self::new()
    }
}
