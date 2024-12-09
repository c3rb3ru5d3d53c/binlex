use std::fs::File as StdFile;
use std::io::{Read, SeekFrom, Seek, Error, Cursor};
use crate::hashing::sha256::SHA256;
use crate::hashing::tlsh::TLSH;
use crate::Binary;
use std::io::ErrorKind;
use serde::{Deserialize, Serialize};
use serde_json;
use crate::controlflow::Attribute;
use crate::Config;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(windows)]
use std::fs::OpenOptions;

#[cfg(windows)]
use winapi::um::winnt::{FILE_SHARE_READ};

pub trait FileHandle: Read + Seek + Send {}

impl<T: Read + Seek + Send> FileHandle for T {}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileJson {
    #[serde(rename = "type")]
    /// The type always `file`
    pub type_: String,
    /// The SHA-256 hash of the file, if available.
    pub sha256: Option<String>,
    /// The TLSH (Trend Micro Locality Sensitive Hash) of the file, if available.
    pub tlsh: Option<String>,
    /// The File Size,
    pub size: Option<u64>,
    // The File Entropy
    pub entropy: Option<f64>,
}

/// Represents a file with its contents and an optional file path.
pub struct File {
    /// The contents of the file as a byte vector.
    pub data: Vec<u8>,
    /// The path of the file, if available.
    pub path: Option<String>,
    /// The configuration `Config`
    pub config: Config,
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
    pub fn new(path: String, config: Config) -> Result<Self, Error> {
        #[cfg(windows)]
        let handle = Box::new(
            OpenOptions::new()
                .read(true)
                .write(false)
                .share_mode(FILE_SHARE_READ)
                .open(&path)?
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
    pub fn from_bytes(bytes: Vec<u8>, config: Config) -> Self {
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
    /// An `Option<String>` containing the hexadecimal representation of the TLSH,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<String> {
        if !self.config.formats.file.hashing.tlsh.enabled { return None; }
        if self.size() <= 0 { return None; }
        TLSH::new(&self.data, 50).hexdigest()
    }

    /// Computes the SHA-256 hash of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the hexadecimal representation of the SHA-256 hash,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<String> {
        if !self.config.formats.file.hashing.sha256.enabled { return None; }
        if self.size() <= 0 { return None; }
        SHA256::new(&self.data).hexdigest()
    }

    /// Computes the SHA-256 hash of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the hexadecimal representation of the SHA-256 hash,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn sha256_no_config(&self) -> Option<String> {
        if self.size() <= 0 { return None; }
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
        let position = self.handle.seek(SeekFrom::Current(0))?;
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
        if self.path.is_none() { return Err(Error::new(ErrorKind::InvalidInput, "missing file path to read")); }
        let mut file = StdFile::open(&self.path.clone().unwrap())?;
        file.read_to_end(&mut self.data)?;
        Ok(())
    }

    /// Prints the JSON representation of the file metadata to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }

    /// Processes the file metadata into a JSON-serializable `FileJson` structure.
    ///
    /// # Returns
    ///
    /// Returns a `FileJson` struct containing the file's SHA-256 hash, TLSH hash, and size.
    pub fn process(&self) -> FileJson {
        FileJson {
            type_: "file".to_string(),
            sha256: self.sha256(),
            tlsh: self.tlsh(),
            size: Some(self.size()),
            entropy: self.entropy(),
        }
    }

    pub fn entropy(&self) -> Option<f64> {
        if !self.config.formats.file.heuristics.entropy.enabled { return None; }
        Binary::entropy(&self.data)
    }

    /// Gets attribute information about a file
    ///
    /// # Returns
    ///
    /// Returns a `Attribute` struct containing the file's SHA-256 hash, TLSH hash, and size.
    pub fn attribute(&self) -> Attribute {
        Attribute::File(self.process())
    }

    /// Converts the file metadata into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation of the file metadata,
    /// or an `Err` if serialization fails.
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

}
