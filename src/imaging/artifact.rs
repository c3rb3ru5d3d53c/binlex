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

use crate::config::ConfigImaging;
use crate::imaging::hash as render_hash;
use crate::imaging::render::Render;

#[derive(Clone)]
pub(crate) struct ImagingArtifact {
    hashing: ConfigImaging,
    render: Render,
}

impl ImagingArtifact {
    pub(crate) fn new(render: Render, hashing: ConfigImaging) -> Self {
        Self { hashing, render }
    }

    pub(crate) fn render(&self) -> &Render {
        &self.render
    }

    pub(crate) fn sha256(&self) -> Option<crate::hashing::SHA256<'static>> {
        render_hash::sha256(&self.render, &self.hashing)
    }

    pub(crate) fn tlsh(&self) -> Option<crate::hashing::TLSH<'static>> {
        render_hash::tlsh(&self.render, &self.hashing)
    }

    pub(crate) fn minhash(&self) -> Option<crate::hashing::MinHash32<'static>> {
        render_hash::minhash(&self.render, &self.hashing)
    }

    pub(crate) fn ahash(&self) -> Option<crate::hashing::AHash<'static>> {
        render_hash::ahash(&self.render, &self.hashing)
    }

    pub(crate) fn dhash(&self) -> Option<crate::hashing::DHash<'static>> {
        render_hash::dhash(&self.render, &self.hashing)
    }

    pub(crate) fn phash(&self) -> Option<crate::hashing::PHash<'static>> {
        render_hash::phash(&self.render, &self.hashing)
    }
}
