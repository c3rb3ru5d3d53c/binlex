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
use binlex::imaging::{PNG, Palette};

#[test]
fn png_output_has_png_signature() {
    let png = PNG::with_options(&[0x00, 0xff], Palette::Grayscale, 2, 2, Config::default());
    let bytes = png.bytes().unwrap();

    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
}

#[test]
fn png_output_uses_render_dimensions() {
    let png = PNG::with_options(
        &[0x00, 0xff, 0x80],
        Palette::Grayscale,
        3,
        2,
        Config::default(),
    );
    let bytes = png.bytes().unwrap();

    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());

    assert_eq!(width, 6);
    assert_eq!(height, 6);
}

#[test]
fn png_output_rejects_empty_images() {
    let png = PNG::new(&[], Palette::Grayscale, Config::default());
    let error = png.bytes().unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn png_terminal_output_matches_terminal_renderer() {
    use binlex::imaging::Terminal;

    let png = PNG::with_options(
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
    let mut png_buffer = Vec::new();
    let mut terminal_buffer = Vec::new();

    png.write_terminal(&mut png_buffer).unwrap();
    terminal.write(&mut terminal_buffer).unwrap();

    assert_eq!(png_buffer, terminal_buffer);
}
