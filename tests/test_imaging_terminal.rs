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
use binlex::imaging::{Palette, Terminal};

#[test]
fn terminal_output_uses_rows_and_resets() {
    let terminal = Terminal::with_options(
        &[0x00, 0x7f, 0xff],
        Palette::Grayscale,
        1,
        2,
        Config::default(),
    );
    let mut buffer = Vec::new();

    terminal.write(&mut buffer).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert_eq!(output.matches('\n').count(), 2);
    assert!(output.ends_with("\x1b[0m"));
    assert_eq!(output.matches("\x1b[48;5;").count(), 3);
}

#[test]
fn terminal_output_maps_expected_ansi_colors() {
    let terminal = Terminal::with_options(
        &[0x00, 0x80, 0xff],
        Palette::Grayscale,
        1,
        16,
        Config::default(),
    );
    let mut buffer = Vec::new();

    terminal.write(&mut buffer).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert!(output.contains("\x1b[48;5;16m"));
    assert!(output.contains("\x1b[48;5;243m"));
    assert!(output.contains("\x1b[48;5;231m"));
}

#[test]
fn rgb_to_ansi256_maps_grayscale_and_color_cube() {
    assert_eq!(Terminal::rgb_to_ansi256(0, 0, 0), 16);
    assert_eq!(Terminal::rgb_to_ansi256(255, 255, 255), 231);
    assert_eq!(Terminal::rgb_to_ansi256(128, 128, 128), 243);
    assert_eq!(Terminal::rgb_to_ansi256(255, 0, 0), 196);
}
