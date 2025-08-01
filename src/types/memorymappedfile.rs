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

use memmap2::{Mmap, MmapMut};
use std::fs::OpenOptions;
use std::io::{self, Error, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[cfg(windows)]
use winapi::um::ioapiset::DeviceIoControl;

#[cfg(windows)]
use winapi::um::winioctl::FSCTL_SET_SPARSE;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(windows)]
use winapi::um::winnt::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};

/// A `MemoryMappedFile` struct that provides a memory-mapped file interface,
/// enabling file read/write operations with optional disk caching,
/// and automatic file cleanup on object drop.
pub struct MemoryMappedFile {
    /// Path to the file as a `String`.
    pub path: String,
    /// Handle to the file as an optional open file descriptor.
    pub handle: Option<std::fs::File>,
    /// Flag indicating whether the file is already cached (exists on disk).
    pub is_cached: bool,
    /// Flag to determine if the file should be cached. If `false`, the file will
    /// be deleted upon the object being dropped.
    pub cache: bool,
    mmap: Option<Mmap>,
    mmap_mut: Option<MmapMut>,
}

impl MemoryMappedFile {
    pub fn new(path: PathBuf, cache: bool) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let is_cached = path.is_file();

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);

        #[cfg(windows)]
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);

        let handle = options.open(&path)?;

        #[cfg(windows)]
        {
            let handle_raw = handle.as_raw_handle() as *mut winapi::ctypes::c_void;
            let mut bytes_returned = 0;

            let result = unsafe {
                DeviceIoControl(
                    handle_raw,
                    FSCTL_SET_SPARSE,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if result == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Self {
            path: path.to_string_lossy().into_owned(),
            handle: Some(handle),
            is_cached,
            cache,
            mmap: None,
            mmap_mut: None,
        })
    }

    pub fn seek_from_current(&mut self, offset: i64) -> Result<u64, io::Error> {
        if let Some(ref mut handle) = self.handle {
            let pos = handle.seek(SeekFrom::Current(offset))?;
            Ok(pos)
        } else {
            Err(io::Error::other("file handle is closed"))
        }
    }

    pub fn seek(&mut self, offset: u64) -> Result<u64, io::Error> {
        if let Some(ref mut handle) = self.handle {
            let pos = handle.seek(SeekFrom::Start(offset))?;
            Ok(pos)
        } else {
            Err(io::Error::other("file handle is closed"))
        }
    }

    pub fn seek_to_end(&mut self) -> Result<u64, io::Error> {
        if let Some(ref mut handle) = self.handle {
            let pos = handle.seek(SeekFrom::End(0))?;
            Ok(pos)
        } else {
            Err(io::Error::other("File handle is closed"))
        }
    }

    /// Explicitly closes the file handle.
    pub fn close(&mut self) {
        if let Some(file) = self.handle.take() {
            drop(file); // Explicitly drop the file to close the handle
        }
    }

    /// Checks if the file is cached (exists on disk).
    pub fn is_cached(&self) -> bool {
        self.is_cached
    }

    /// Retrieves the file path as a `String`.
    pub fn path(&self) -> String {
        self.path.clone()
    }

    /// Writes data from a reader to the file.
    pub fn write<R: Read>(&mut self, mut reader: R) -> Result<u64, Error> {
        if let Some(ref mut handle) = self.handle {
            if handle.metadata()?.permissions().readonly() {
                return Err(Error::other("File is read-only"));
            }

            let bytes_written = io::copy(&mut reader, handle)?;
            handle.flush()?;
            Ok(bytes_written)
        } else {
            Err(Error::other("File handle is closed"))
        }
    }

    /// Adds symbolic padding (increases the file size without writing data) to the end of the file.
    pub fn write_padding(&mut self, length: usize) -> Result<(), Error> {
        if let Some(ref mut handle) = self.handle {
            let current_size = handle.metadata()?.len();
            let new_size = current_size + length as u64;

            handle.set_len(new_size)?;
            handle.seek(SeekFrom::Start(new_size))?;
            Ok(())
        } else {
            Err(Error::other("File handle is closed"))
        }
    }

    pub fn mmap_mut(&mut self) -> Result<&mut MmapMut, Error> {
        if self.mmap_mut.is_none() {
            if let Some(ref handle) = self.handle {
                self.mmap_mut = Some(unsafe { MmapMut::map_mut(handle)? });
            } else {
                return Err(Error::other("File handle is closed"));
            }
        }
        self.mmap_mut
            .as_mut()
            .ok_or_else(|| Error::other("Failed to create mutable memory map"))
    }

    pub fn mmap(&mut self) -> Result<&Mmap, Error> {
        if self.mmap.is_none() {
            if let Some(ref handle) = self.handle {
                self.mmap = Some(unsafe { Mmap::map(handle)? });
            } else {
                return Err(Error::other("File handle is closed"));
            }
        }
        self.mmap
            .as_ref()
            .ok_or_else(|| Error::other("Failed to create memory map"))
    }

    pub fn unmap(&mut self) {
        self.mmap = None;
        self.mmap_mut = None;
    }

    /// Retrieves the size of the file in bytes.
    pub fn size(&self) -> Result<u64, Error> {
        if let Some(ref handle) = self.handle {
            Ok(handle.metadata()?.len())
        } else {
            Err(Error::other("File handle is closed"))
        }
    }
}

impl Drop for MemoryMappedFile {
    fn drop(&mut self) {
        self.unmap();

        // Ensure the file handle is dropped
        self.close();

        // Remove the file if caching is disabled
        if !self.cache {
            if let Err(error) = std::fs::remove_file(&self.path) {
                eprintln!("Failed to remove file {}: {}", self.path, error);
            }
        }
    }
}
