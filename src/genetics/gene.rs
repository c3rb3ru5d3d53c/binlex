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

use std::io::Error;
use std::io::ErrorKind;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Gene {
    pub kind: GeneKind,
    pub value: Option<u8>,
    pub number_of_mutations: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum GeneKind {
    Wildcard,
    Value,
}

#[allow(dead_code)]
impl Gene {
    pub fn is_wildcard(&self) -> bool {
        matches!(self.kind, GeneKind::Wildcard)
    }

    pub fn is_value(&self) -> bool {
        matches!(self.kind, GeneKind::Value)
    }

    pub fn from_wildcard() -> Self {
        Self {
            kind: GeneKind::Wildcard,
            value: None,
            number_of_mutations: 0,
        }
    }

    pub fn wildcard(&self) -> Option<String> {
        match self.kind {
            GeneKind::Wildcard => Some("?".to_string()),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<u8> {
        match self.kind {
            GeneKind::Value => self.value,
            _ => None,
        }
    }

    pub fn from_value(v: u8) -> Self {
        Self {
            kind: GeneKind::Value,
            value: Some(v),
            number_of_mutations: 0,
        }
    }

    pub fn mutate(&mut self, c: char) -> Result<(), Error> {
        match c {
            '?' => {
                self.kind = GeneKind::Wildcard;
                self.value = None;
                self.number_of_mutations += 1;
                Ok(())
            }
            '0'..='9' | 'a'..='f' | 'A'..='F' => {
                self.kind = GeneKind::Value;
                self.value = c.to_digit(16).map(|v| v as u8);
                self.number_of_mutations += 1;
                Ok(())
            }
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "invaid data to mutate gene",
            )),
        }
    }

    pub fn print(&self) {
        println!("{}", self.to_char());
    }

    pub fn to_char(&self) -> String {
        match self.kind {
            GeneKind::Wildcard => "?".to_string(),
            GeneKind::Value => {
                if let Some(v) = self.value {
                    format!("{:x}", v)
                } else {
                    panic!("Gene of kind Value is missing a value")
                }
            }
        }
    }

    pub fn from_char(c: char) -> Result<Self, std::io::Error> {
        match c {
            '?' => Ok(Self::from_wildcard()),
            '0'..='9' | 'a'..='f' | 'A'..='F' => c
                .to_digit(16)
                .map(|v| Self::from_value(v as u8))
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid hexadecimal digit")),
            _ => Err(Error::new(ErrorKind::InvalidInput, "invalid character")),
        }
    }
}
