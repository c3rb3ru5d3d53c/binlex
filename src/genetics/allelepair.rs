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

use crate::genetics::Gene;
use std::fmt;
use std::io::Error;
use std::io::ErrorKind;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct AllelePair {
    pub high: Gene,
    pub low: Gene,
    pub number_mutations: usize,
}

#[allow(dead_code)]
impl AllelePair {
    pub fn new(high: Gene, low: Gene) -> Self {
        Self {
            high,
            low,
            number_mutations: 0,
        }
    }

    pub fn number_of_mutations(&self) -> usize {
        self.number_mutations
    }

    pub fn mutate(&mut self, high: Gene, low: Gene) {
        self.high = high;
        self.low = low;
    }

    pub fn genes(&self) -> Vec<Gene> {
        vec![self.low, self.high]
    }

    pub fn from_string(pair: String) -> Result<Self, Error> {
        if pair.len() != 2 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "allele pair string must have a length of 2",
            ));
        }

        let mut chars = pair.chars();
        let high_char = chars.next().unwrap();
        let low_char = chars.next().unwrap();

        let high = Gene::from_char(high_char)?;
        let low = Gene::from_char(low_char)?;

        Ok(Self {
            high,
            low,
            number_mutations: 0,
        })
    }
}

impl fmt::Display for AllelePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.high.to_char(), self.low.to_char())
    }
}
