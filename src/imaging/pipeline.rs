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

use crate::config::Config;
use crate::imaging::renderers::Renderer;
use crate::imaging::{PNG, Palette, Render, SVG, Terminal};

#[derive(Clone)]
struct ImagingState {
    data: Vec<u8>,
    config: Config,
    renderer: Renderer,
    palette: Palette,
}

impl ImagingState {
    fn render(&self) -> Render {
        self.renderer.render(&self.data, self.palette.clone())
    }
}

#[derive(Clone)]
pub struct Imaging {
    state: ImagingState,
}

#[derive(Clone)]
pub struct ImagingRenderer {
    state: ImagingState,
}

#[derive(Clone)]
pub struct ImagingPalette {
    state: ImagingState,
}

impl Imaging {
    pub fn new(data: Vec<u8>, config: Config) -> Self {
        Self {
            state: ImagingState {
                data,
                config,
                renderer: Renderer::default(),
                palette: Palette::Grayscale,
            },
        }
    }

    pub fn linear(
        mut self,
        cell_size: Option<usize>,
        fixed_width: Option<usize>,
    ) -> ImagingRenderer {
        self.state.renderer = Renderer::linear(cell_size, fixed_width);
        ImagingRenderer { state: self.state }
    }
}

impl ImagingRenderer {
    pub fn grayscale(mut self) -> ImagingPalette {
        self.state.palette = Palette::Grayscale;
        ImagingPalette { state: self.state }
    }

    pub fn heatmap(mut self) -> ImagingPalette {
        self.state.palette = Palette::Heatmap;
        ImagingPalette { state: self.state }
    }

    pub fn bluegreen(mut self) -> ImagingPalette {
        self.state.palette = Palette::Bluegreen;
        ImagingPalette { state: self.state }
    }

    pub fn redblack(mut self) -> ImagingPalette {
        self.state.palette = Palette::Redblack;
        ImagingPalette { state: self.state }
    }
}

impl ImagingPalette {
    pub fn png(&self) -> PNG {
        PNG::from_render(self.state.render(), self.state.config.imaging.clone())
    }

    pub fn svg(&self) -> SVG {
        SVG::from_render(self.state.render(), self.state.config.imaging.clone())
    }

    pub fn terminal(&self) -> Terminal {
        Terminal::from_render(self.state.render(), self.state.config.imaging.clone())
    }
}
