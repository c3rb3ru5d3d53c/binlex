use memmap2::{Mmap, MmapMut};
use std::fs::OpenOptions;
use std::io::{self, Error, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(windows)]
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE};

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
}

impl MemoryMappedFile {
    /// Creates a new `MemoryMappedFile` instance.
    ///
    /// This function opens a file at the specified path, with options to append and/or cache the file.
    /// If the file's parent directories do not exist, they are created.
    ///
    /// # Arguments
    ///
    /// * `path` - The `PathBuf` specifying the file's location.
    /// * `append` - If `true`, opens the file in append mode.
    /// * `cache` - If `true`, retains the file on disk after the `MemoryMappedFile` instance is dropped.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `MemoryMappedFile` on success, or an `io::Error` if file creation fails.
    pub fn new(path: PathBuf, cache: bool) -> Result<Self, Error> {
        // if let Some(parent) = path.parent() {
        //     std::fs::create_dir_all(parent)?;
        // }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to create parent directories for '{}': {}",
                            path.display(), e)
                )
            })?;
        }

        let is_cached = path.is_file();

        let mut options = OpenOptions::new();

        options.read(true).write(true).create(true);

        #[cfg(windows)]
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);

        //let handle = options.open(&path)?;

        let handle = options.open(&path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to open file '{}': {}", path.display(), e)
            )
        })?;

        Ok(Self {
            path: path.to_string_lossy().into_owned(),
            handle: Some(handle),
            is_cached,
            cache,
        })
    }

    pub fn seek_to_end(&mut self) -> Result<u64, io::Error> {
        if let Some(ref mut handle) = self.handle {
            let pos = handle.seek(SeekFrom::End(0))?;
            Ok(pos)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "File handle is closed"))
        }
    }

    /// Creates a new `MemoryMappedFile` instance in read-only mode.
    ///
    /// # Arguments
    ///
    /// * `path` - The `PathBuf` specifying the file's location.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `MemoryMappedFile` on success, or an `Error` if file creation fails.
    pub fn new_readonly(path: PathBuf) -> Result<Self, Error> {
        let mut options = OpenOptions::new();
        options.read(true).write(false).create(false);

        #[cfg(windows)]
        options.share_mode(FILE_SHARE_READ);

        let handle = options.open(&path)?;

        Ok(Self {
            path: path.to_string_lossy().into_owned(),
            handle: Some(handle),
            is_cached: false,
            cache: false,
        })
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
                return Err(Error::new(io::ErrorKind::Other, "File is read-only"));
            }

            let bytes_written = io::copy(&mut reader, handle)?;
            handle.flush()?;
            Ok(bytes_written)
        } else {
            Err(Error::new(io::ErrorKind::Other, "File handle is closed"))
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
            Err(Error::new(io::ErrorKind::Other, "File handle is closed"))
        }
    }

    /// Maps the file into memory as mutable using `mmap2`.
    pub fn mmap_mut(&self) -> Result<MmapMut, Error> {
        if let Some(ref handle) = self.handle {
            unsafe { MmapMut::map_mut(handle) }
        } else {
            Err(Error::new(io::ErrorKind::Other, "File handle is closed"))
        }
    }

    /// Retrieves the size of the file in bytes.
    pub fn size(&self) -> Result<u64, Error> {
        if let Some(ref handle) = self.handle {
            Ok(handle.metadata()?.len())
        } else {
            Err(Error::new(io::ErrorKind::Other, "File handle is closed"))
        }
    }

    /// Maps the file into memory using `mmap`.
    pub fn mmap(&self) -> Result<Mmap, Error> {
        if let Some(ref handle) = self.handle {
            unsafe { Mmap::map(handle) }
        } else {
            Err(Error::new(io::ErrorKind::Other, "File handle is closed"))
        }
    }
}

/// Automatically handles cleanup for the `MemoryMappedFile` when it goes out of scope.
///
/// If caching is disabled, this `Drop` implementation deletes the file from disk
/// when the `MemoryMappedFile` instance is dropped, provided there were no errors in file removal.
impl Drop for MemoryMappedFile {
    fn drop(&mut self) {
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
