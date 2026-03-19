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

use crate::config::ConfigImagingHashing;
use crate::hashing::{AHash, DHash, MinHash32, PHash, SHA256, TLSH};
use crate::imaging::render::Render;
use image::ColorType;
use image::ImageEncoder;
use image::RgbaImage;
use image::codecs::png::PngEncoder;
use std::io;

pub(crate) fn encode_png(render: &Render) -> io::Result<Vec<u8>> {
    let width = u32::try_from(render.total_width())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "png width exceeds u32 range"))?;
    let height = u32::try_from(render.total_height())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "png height exceeds u32 range"))?;

    if width == 0 || height == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "png output requires non-empty image dimensions",
        ));
    }

    let mut rgba = RgbaImage::new(width, height);

    for cell in render.cells() {
        let (r, g, b) = cell.rgb();

        for y in cell.y()..(cell.y() + cell.height()) {
            for x in cell.x()..(cell.x() + cell.width()) {
                rgba.put_pixel(x as u32, y as u32, image::Rgba([r, g, b, 255]));
            }
        }
    }

    let mut encoded = Vec::new();
    let encoder = PngEncoder::new(&mut encoded);
    encoder
        .write_image(rgba.as_raw(), width, height, ColorType::Rgba8.into())
        .map_err(|error| io::Error::other(error.to_string()))?;

    Ok(encoded)
}

pub(crate) fn sha256(render: &Render, config: &ConfigImagingHashing) -> Option<String> {
    if !config.sha256.enabled {
        return None;
    }
    let bytes = encode_png(render).ok()?;
    SHA256::new(&bytes).hexdigest()
}

pub(crate) fn tlsh(render: &Render, config: &ConfigImagingHashing) -> Option<String> {
    if !config.tlsh.enabled {
        return None;
    }
    let bytes = encode_png(render).ok()?;
    TLSH::new(&bytes, config.tlsh.minimum_byte_size).hexdigest()
}

pub(crate) fn minhash(render: &Render, config: &ConfigImagingHashing) -> Option<String> {
    if !config.minhash.enabled {
        return None;
    }
    let bytes = encode_png(render).ok()?;
    if config.minhash.maximum_byte_size_enabled && bytes.len() > config.minhash.maximum_byte_size {
        return None;
    }
    MinHash32::new(
        &bytes,
        config.minhash.number_of_hashes,
        config.minhash.shingle_size,
        config.minhash.seed,
    )
    .hexdigest()
}

pub(crate) fn ahash(render: &Render, config: &ConfigImagingHashing) -> Option<String> {
    if !config.ahash.enabled {
        return None;
    }
    let bytes = encode_png(render).ok()?;
    AHash::new(&bytes).hexdigest()
}

pub(crate) fn dhash(render: &Render, config: &ConfigImagingHashing) -> Option<String> {
    if !config.dhash.enabled {
        return None;
    }
    let bytes = encode_png(render).ok()?;
    DHash::new(&bytes).hexdigest()
}

pub(crate) fn phash(render: &Render, config: &ConfigImagingHashing) -> Option<String> {
    if !config.phash.enabled {
        return None;
    }
    let bytes = encode_png(render).ok()?;
    PHash::new(&bytes).hexdigest()
}
