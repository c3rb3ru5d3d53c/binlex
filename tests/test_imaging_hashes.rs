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
use binlex::imaging::{PNG, Palette, SVG, Terminal};

#[test]
fn imaging_hashes_match_across_renderers() {
    let data = [0x00, 0x22, 0x44, 0x88, 0xaa, 0xcc, 0xee, 0xff];
    let png = PNG::with_options(&data, Palette::Grayscale, 2, 4, Config::default());
    let svg = SVG::with_options(&data, Palette::Grayscale, 2, 4, Config::default());
    let terminal = Terminal::with_options(&data, Palette::Grayscale, 2, 4, Config::default());

    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        svg.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        terminal.sha256().and_then(|hash| hash.hexdigest())
    );

    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        svg.tlsh().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        terminal.tlsh().and_then(|hash| hash.hexdigest())
    );

    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        svg.minhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        terminal.minhash().and_then(|hash| hash.hexdigest())
    );

    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        terminal.ahash().and_then(|hash| hash.hexdigest())
    );

    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        terminal.dhash().and_then(|hash| hash.hexdigest())
    );

    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        terminal.phash().and_then(|hash| hash.hexdigest())
    );
}

#[test]
fn imaging_hashes_return_none_for_empty_images() {
    let png = PNG::new(&[], Palette::Grayscale, Config::default());
    let svg = SVG::new(&[], Palette::Grayscale, Config::default());
    let terminal = Terminal::new(&[], Palette::Grayscale, Config::default());

    assert!(png.sha256().is_none());
    assert!(png.tlsh().is_none());
    assert!(png.minhash().is_none());
    assert!(png.ahash().is_none());
    assert!(png.dhash().is_none());
    assert!(png.phash().is_none());

    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        svg.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        terminal.sha256().and_then(|hash| hash.hexdigest())
    );
}

#[test]
fn imaging_hashes_ignore_config_for_direct_accessors() {
    let mut config = Config::default();
    config.disable_hashing();

    let png = PNG::new(&[0x00, 0x7f, 0xff], Palette::Grayscale, config.clone());
    let svg = SVG::new(&[0x00, 0x7f, 0xff], Palette::Grayscale, config.clone());
    let terminal = Terminal::new(&[0x00, 0x7f, 0xff], Palette::Grayscale, config);

    assert!(png.sha256().is_some());
    assert!(png.tlsh().is_some());
    assert!(png.minhash().is_some());
    assert!(png.ahash().is_some());
    assert!(png.dhash().is_some());
    assert!(png.phash().is_some());

    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        svg.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.sha256().and_then(|hash| hash.hexdigest()),
        terminal.sha256().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        svg.tlsh().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.tlsh().and_then(|hash| hash.hexdigest()),
        terminal.tlsh().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        svg.minhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.minhash().and_then(|hash| hash.hexdigest()),
        terminal.minhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        svg.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.ahash().and_then(|hash| hash.hexdigest()),
        terminal.ahash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        svg.dhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.dhash().and_then(|hash| hash.hexdigest()),
        terminal.dhash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        svg.phash().and_then(|hash| hash.hexdigest())
    );
    assert_eq!(
        png.phash().and_then(|hash| hash.hexdigest()),
        terminal.phash().and_then(|hash| hash.hexdigest())
    );
}
