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

use binlex::imaging::{Palette, SVG};

#[test]
fn display_renders_metadata_and_cells() {
    let mut svg = SVG::new_with_options(&[0x10], Palette::Redblack, 3, 4);
    svg.add_metadata("Hash".to_string(), "sha256:test".to_string());

    let output = svg.to_string();

    assert!(output.contains("<metadata>"));
    assert!(output.contains("fill=\"rgb(16,0,0)\""));
    assert!(output.contains("width=\"12\" height=\"3\""));
}

#[test]
fn svg_string_is_a_document() {
    let svg = SVG::new_with_options(&[0x10], Palette::Redblack, 3, 4);

    let output = svg.to_string();

    assert!(output.starts_with("<svg "));
    assert!(output.ends_with("</svg>\n"));
}
