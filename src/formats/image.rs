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
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::io::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImagePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl ImagePermissions {
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    pub fn readable() -> Self {
        Self::new(true, false, false)
    }

    pub fn executable() -> Self {
        Self::new(true, false, true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImageSegmentData {
    Bytes(Vec<u8>),
    Zeroes,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageSegment {
    pub name: Option<String>,
    pub virtual_address: u64,
    pub size: u64,
    pub data: ImageSegmentData,
    pub permissions: ImagePermissions,
}

impl ImageSegment {
    pub fn bytes(
        name: Option<String>,
        virtual_address: u64,
        bytes: Vec<u8>,
        permissions: ImagePermissions,
    ) -> Self {
        Self {
            name,
            virtual_address,
            size: bytes.len() as u64,
            data: ImageSegmentData::Bytes(bytes),
            permissions,
        }
    }

    pub fn zeroes(
        name: Option<String>,
        virtual_address: u64,
        size: u64,
        permissions: ImagePermissions,
    ) -> Self {
        Self {
            name,
            virtual_address,
            size,
            data: ImageSegmentData::Zeroes,
            permissions,
        }
    }

    pub fn end(&self) -> u64 {
        self.virtual_address.saturating_add(self.size)
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.virtual_address && address < self.end()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Image {
    segments: Vec<ImageSegment>,
}

pub trait VirtualImage {
    fn read_virtual_address(&self, address: u64, size: usize) -> Result<Option<Vec<u8>>, Error>;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImageContext {
    image: Image,
}

impl PartialEq for ImageContext {
    fn eq(&self, other: &Self) -> bool {
        self.image == other.image
    }
}

impl Eq for ImageContext {}

impl Hash for ImageContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.image.hash(state);
    }
}

impl ImageContext {
    pub fn from_image(image: &Image) -> Self {
        Self {
            image: image.clone(),
        }
    }
}

impl VirtualImage for ImageContext {
    fn read_virtual_address(&self, address: u64, size: usize) -> Result<Option<Vec<u8>>, Error> {
        self.image.read_virtual_address(address, size)
    }
}

impl PartialEq for Image {
    fn eq(&self, other: &Self) -> bool {
        self.segments == other.segments
    }
}

impl Eq for Image {}

impl Hash for Image {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.segments.hash(state);
    }
}

impl Image {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_segments(segments: Vec<ImageSegment>) -> Self {
        let mut image = Self { segments };
        image.sort_segments();
        image
    }

    pub fn add_segment(&mut self, segment: ImageSegment) {
        if segment.size == 0 {
            return;
        }
        self.segments.push(segment);
        self.sort_segments();
    }

    pub fn segments(&self) -> &[ImageSegment] {
        &self.segments
    }

    pub fn mapped_size(&self) -> u64 {
        self.segments
            .iter()
            .fold(0u64, |total, segment| total.saturating_add(segment.size))
    }

    pub fn executable_virtual_address_ranges(&self) -> std::collections::BTreeMap<u64, u64> {
        self.segments
            .iter()
            .filter(|segment| segment.permissions.execute)
            .map(|segment| (segment.virtual_address, segment.end()))
            .collect()
    }

    pub fn virtual_min(&self) -> Option<u64> {
        self.segments
            .iter()
            .map(|segment| segment.virtual_address)
            .min()
    }

    pub fn virtual_max(&self) -> Option<u64> {
        self.segments.iter().map(ImageSegment::end).max()
    }

    pub fn base(&self) -> u64 {
        self.virtual_min().unwrap_or(0)
    }

    pub fn size(&self) -> Result<u64, Error> {
        Ok(self.mapped_size())
    }

    pub fn materialize(&self) -> Result<Option<(u64, Vec<u8>)>, Error> {
        let Some(start) = self.virtual_min() else {
            return Ok(None);
        };
        let Some(end) = self.virtual_max() else {
            return Ok(None);
        };
        let size = end.saturating_sub(start);
        let size = usize::try_from(size)
            .map_err(|_| Error::other("virtual image span does not fit in memory"))?;
        let mut bytes = vec![0; size];
        for segment in &self.segments {
            let offset = usize::try_from(segment.virtual_address.saturating_sub(start))
                .map_err(|_| Error::other("virtual image segment offset does not fit in memory"))?;
            let segment_size = usize::try_from(segment.size)
                .map_err(|_| Error::other("virtual image segment size does not fit in memory"))?;
            match &segment.data {
                ImageSegmentData::Bytes(segment_bytes) => {
                    let copy_size = segment_size.min(segment_bytes.len());
                    bytes[offset..offset + copy_size].copy_from_slice(&segment_bytes[0..copy_size]);
                }
                ImageSegmentData::Zeroes => {}
            }
        }
        Ok(Some((start, bytes)))
    }

    pub fn is_virtual_address(&self, address: u64) -> bool {
        self.segment_containing(address).is_some()
    }

    pub fn read_virtual_address(
        &self,
        address: u64,
        size: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        if size == 0 {
            return Ok(Some(Vec::new()));
        }

        let mut current = address;
        let mut remaining = size;
        let mut result = Vec::with_capacity(size);

        while remaining > 0 {
            let Some(segment) = self.segment_containing(current) else {
                break;
            };
            let segment_offset = current - segment.virtual_address;
            let available = remaining.min((segment.size - segment_offset) as usize);
            self.read_segment_bytes(segment, segment_offset, available, &mut result);
            current = current.saturating_add(available as u64);
            remaining -= available;
            if remaining > 0 && self.segment_starting_at(current).is_none() {
                break;
            }
        }

        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    fn sort_segments(&mut self) {
        self.segments
            .sort_by_key(|segment| (segment.virtual_address, segment.end()));
    }

    fn segment_containing(&self, address: u64) -> Option<&ImageSegment> {
        self.segments
            .iter()
            .find(|segment| segment.contains(address))
    }

    fn segment_starting_at(&self, address: u64) -> Option<&ImageSegment> {
        self.segments
            .iter()
            .find(|segment| segment.virtual_address == address)
    }

    fn read_segment_bytes(
        &self,
        segment: &ImageSegment,
        offset: u64,
        size: usize,
        result: &mut Vec<u8>,
    ) {
        match &segment.data {
            ImageSegmentData::Bytes(bytes) => {
                let start = offset as usize;
                let end = (start + size).min(bytes.len());
                if start < end {
                    result.extend_from_slice(&bytes[start..end]);
                }
                if end.saturating_sub(start) < size {
                    result.resize(result.len() + (size - end.saturating_sub(start)), 0);
                }
            }
            ImageSegmentData::Zeroes => {
                result.resize(result.len() + size, 0);
            }
        }
    }
}

impl VirtualImage for Image {
    fn read_virtual_address(&self, address: u64, size: usize) -> Result<Option<Vec<u8>>, Error> {
        self.read_virtual_address(address, size)
    }
}

#[cfg(test)]
mod tests {
    use super::{Image, ImagePermissions, ImageSegment};

    #[test]
    fn virtual_reads_stop_at_unmapped_gaps() {
        let mut image = Image::new();
        image.add_segment(ImageSegment::bytes(
            Some(".text".to_string()),
            0x1000,
            vec![1, 2, 3, 4],
            ImagePermissions::readable(),
        ));
        image.add_segment(ImageSegment::bytes(
            Some(".data".to_string()),
            0x2000,
            vec![5, 6],
            ImagePermissions::readable(),
        ));

        assert_eq!(
            image.read_virtual_address(0x1002, 8).unwrap(),
            Some(vec![3, 4])
        );
        assert_eq!(image.read_virtual_address(0x1004, 1).unwrap(), None);
    }

    #[test]
    fn virtual_reads_cross_adjacent_segments_and_zeroes() {
        let mut image = Image::new();
        image.add_segment(ImageSegment::bytes(
            Some(".data".to_string()),
            0x3000,
            vec![0xaa, 0xbb],
            ImagePermissions::readable(),
        ));
        image.add_segment(ImageSegment::zeroes(
            Some(".bss".to_string()),
            0x3002,
            3,
            ImagePermissions::readable(),
        ));

        assert_eq!(
            image.read_virtual_address(0x3000, 5).unwrap(),
            Some(vec![0xaa, 0xbb, 0, 0, 0])
        );
        assert!(image.is_virtual_address(0x3004));
        assert!(!image.is_virtual_address(0x3005));
    }
}
