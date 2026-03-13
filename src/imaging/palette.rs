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

use clap::ValueEnum;
use std::fmt;
use std::io::{Error, ErrorKind};

#[derive(Debug, Clone, ValueEnum)]
pub enum Palette {
    Grayscale,
    Heatmap,
    Bluegreen,
    Redblack,
}

impl fmt::Display for Palette {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Palette::Grayscale => "grayscale",
                Palette::Heatmap => "heatmap",
                Palette::Bluegreen => "bluegreen",
                Palette::Redblack => "redblack",
            }
        )
    }
}

impl Palette {
    pub fn from_string(s: &str) -> Result<Self, Error> {
        match s.trim().to_lowercase().as_str() {
            "grayscale" => Ok(Palette::Grayscale),
            "heatmap" => Ok(Palette::Heatmap),
            "bluegreen" => Ok(Palette::Bluegreen),
            "redblack" => Ok(Palette::Redblack),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("'{}' is not a valid Palette", s),
            )),
        }
    }

    pub fn map_byte(&self, byte: u8) -> String {
        match self {
            Palette::Grayscale => format!("rgb({},{},{})", byte, byte, byte),
            Palette::Heatmap => {
                let r = (byte as f32 * 1.2).min(255.0) as u8;
                let g = 255 - byte;
                let b = (byte as f32 * 0.5).min(255.0) as u8;
                format!("rgb({},{},{})", r, g, b)
            }
            Palette::Bluegreen => {
                let r = (byte as f32 * 0.2).min(255.0) as u8;
                let g = (byte as f32 * 0.8).min(255.0) as u8;
                let b = 255 - byte;
                format!("rgb({},{},{})", r, g, b)
            }
            Palette::Redblack => {
                let r = byte;
                let g = 0;
                let b = 0;
                format!("rgb({},{},{})", r, g, b)
            }
        }
    }
}
