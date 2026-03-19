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

use binlex::Config;
use binlex::imaging::{Palette, SVG};
use std::io::Write;

#[test]
fn display_renders_metadata_and_cells() {
    let mut svg = SVG::with_options(&[0x10], Palette::Redblack, 3, 4, Config::default());
    svg.add_metadata("Hash".to_string(), "sha256:test".to_string());

    let output = svg.to_string();

    assert!(output.contains("<metadata>"));
    assert!(output.contains("fill=\"rgb(16,0,0)\""));
    assert!(output.contains("width=\"12\" height=\"3\""));
}

#[test]
fn svg_string_is_a_document() {
    let svg = SVG::with_options(&[0x10], Palette::Redblack, 3, 4, Config::default());

    let output = svg.to_string();

    assert!(output.starts_with("<svg "));
    assert!(output.ends_with("</svg>\n"));
}

#[test]
fn svg_terminal_output_matches_terminal_renderer() {
    use binlex::imaging::Terminal;

    let svg = SVG::with_options(
        &[0x00, 0x7f, 0xff],
        Palette::Grayscale,
        1,
        2,
        Config::default(),
    );
    let terminal = Terminal::with_options(
        &[0x00, 0x7f, 0xff],
        Palette::Grayscale,
        1,
        2,
        Config::default(),
    );
    let mut svg_buffer = Vec::new();
    let mut terminal_buffer = Vec::new();

    svg.write_terminal(&mut svg_buffer).unwrap();
    terminal.write(&mut terminal_buffer).unwrap();

    assert_eq!(svg_buffer, terminal_buffer);
}

#[test]
fn print_svg_writes_svg_document() {
    let svg = SVG::with_options(&[0x10], Palette::Redblack, 3, 4, Config::default());
    let mut buffer = Vec::new();

    write!(&mut buffer, "{}", svg).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert!(output.starts_with("<svg "));
    assert!(output.ends_with("</svg>\n"));
}
