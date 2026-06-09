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

use crate::Configuration;
use crate::Magic;
use crate::entropy;
use crate::hashing::sha256::SHA256;
use crate::hashing::ssdeep::SSDeep;
use crate::hashing::tlsh::TLSH;
use std::fs::File as StdFile;
use std::io::ErrorKind;
use std::io::{Cursor, Error, Read, Seek, SeekFrom};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(windows)]
use std::fs::OpenOptions;

#[cfg(windows)]
use winapi::um::winnt::FILE_SHARE_READ;

pub trait FileHandle: Read + Seek + Send {}

impl<T: Read + Seek + Send> FileHandle for T {}

/// Represents a file with its contents and an optional file path.
pub struct File {
    /// The contents of the file as a byte vector.
    pub data: Vec<u8>,
    /// The path of the file, if available.
    pub path: Option<String>,
    /// The configuration `Configuration`
    pub config: Configuration,
    /// Handle to the file
    handle: Box<dyn FileHandle>,
}

impl File {
    /// Creates a new `File` instance with a given path.
    ///
    /// # Arguments
    ///
    /// * `path` - A `String` representing the path to the file.
    ///
    /// # Returns
    ///
    /// A `File` instance with the given path and empty data.
    pub fn new(path: String, config: Configuration) -> Result<Self, Error> {
        #[cfg(windows)]
        let handle = Box::new(
            OpenOptions::new()
                .read(true)
                .write(false)
                .share_mode(FILE_SHARE_READ)
                .open(&path)?,
        ) as Box<dyn FileHandle>;
        #[cfg(not(windows))]
        let handle = Box::new(StdFile::open(&path)?) as Box<dyn FileHandle>;
        Ok(Self {
            data: Vec::new(),
            path: Some(path),
            config,
            handle,
        })
    }

    /// Creates a new `File` instance from the provided byte data.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A `Vec<u8>` representing the byte data of the file.
    ///
    /// # Returns
    ///
    /// A `File` instance with the given byte data and no path.
    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>, config: Configuration) -> Self {
        let handle = Box::new(Cursor::new(bytes.clone())) as Box<dyn FileHandle>;
        Self {
            data: bytes,
            path: None,
            config,
            handle,
        }
    }

    /// Computes the TLSH (Trend Locality Sensitive Hashing) of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<TLSH>` containing the TLSH helper,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<TLSH<'_>> {
        if self.size() == 0 {
            return None;
        }
        Some(TLSH::new(
            &self.data,
            self.config.hashing.tlsh.minimum_byte_size,
        ))
    }

    /// Computes the SHA-256 hash of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<SHA256>` containing the SHA-256 helper,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<SHA256<'_>> {
        if self.size() == 0 {
            return None;
        }
        Some(SHA256::new(&self.data))
    }

    /// Computes the ssdeep hash of the file's data.
    #[allow(dead_code)]
    pub fn ssdeep(&self) -> Option<SSDeep<'_>> {
        if self.size() == 0 {
            return None;
        }
        Some(SSDeep::new(&self.data))
    }

    /// Computes the SHA-256 hash of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the hexadecimal representation of the SHA-256 hash,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn sha256_no_config(&self) -> Option<String> {
        if self.size() == 0 {
            return None;
        }
        SHA256::new(&self.data).hexdigest()
    }

    /// Returns the size of the file in bytes.
    ///
    /// # Returns
    ///
    /// The size of the file in bytes as a `u64`.
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Identifies the file type from the loaded file bytes.
    #[allow(dead_code)]
    pub fn magic(&self) -> Magic {
        Magic::new(&self.data)
    }

    /// Seeks to a specific offset in the file.
    ///
    /// # Arguments
    ///
    /// * `offset` - The position to seek to, specified as a `u64` (absolute offset from the start of the file).
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the seek operation, returning the new position.
    ///
    /// # Errors
    ///
    /// Returns an error if the file path is missing or the seek operation fails.
    pub fn seek(&mut self, offset: u64) -> Result<u64, Error> {
        let new_position = self.handle.seek(SeekFrom::Start(offset))?;
        Ok(new_position)
    }

    /// Gets the current position of the file cursor.
    /// # Returns
    ///
    /// A `Result<u64, Error>` with the current cursor position.
    pub fn current_position(&mut self) -> Result<u64, Error> {
        let position = self.handle.stream_position()?;
        Ok(position)
    }

    /// Reads the content of the file from the given path and stores it in `data`.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the operation.
    /// Returns `Ok(())` on success, or an `Err` with an `Error` if the file cannot be read.
    ///
    /// # Errors
    ///
    /// Returns an error if the file path is missing or the file cannot be opened or read.
    pub fn read(&mut self) -> Result<(), Error> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "missing file path to read"))?;

        let mut file = StdFile::open(path)?;
        file.read_to_end(&mut self.data)?;
        Ok(())
    }

    pub fn entropy(&self) -> Option<f64> {
        entropy::shannon(&self.data)
    }
}

impl Clone for File {
    fn clone(&self) -> Self {
        let handle = if let Some(path) = &self.path {
            #[cfg(windows)]
            let handle = Box::new(
                OpenOptions::new()
                    .read(true)
                    .write(false)
                    .share_mode(FILE_SHARE_READ)
                    .open(path)
                    .unwrap_or_else(|_| StdFile::open(path).unwrap()),
            ) as Box<dyn FileHandle>;
            #[cfg(not(windows))]
            let handle = Box::new(StdFile::open(path).unwrap()) as Box<dyn FileHandle>;
            handle
        } else {
            Box::new(Cursor::new(self.data.clone())) as Box<dyn FileHandle>
        };

        Self {
            data: self.data.clone(),
            path: self.path.clone(),
            config: self.config.clone(),
            handle,
        }
    }
}
