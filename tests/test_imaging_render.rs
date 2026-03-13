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

use binlex::imaging::{Palette, Render};

#[test]
fn render_computes_dimensions_and_cells() {
    let render = Render::new_with_options(&[0x00, 0x10, 0xff], Palette::Redblack, 3, 2);

    assert_eq!(render.total_width(), 6);
    assert_eq!(render.total_height(), 6);
    assert_eq!(render.total_cells(), 3);
    assert_eq!(render.fixed_width(), 2);

    let cells = render.cells();
    assert_eq!(cells.len(), 3);
    assert_eq!(cells[0].x(), 0);
    assert_eq!(cells[1].x(), 3);
    assert_eq!(cells[2].y(), 3);
    assert_eq!(cells[1].rgb(), (16, 0, 0));
}
