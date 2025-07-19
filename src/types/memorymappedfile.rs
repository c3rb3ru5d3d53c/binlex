//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

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
                eprintln!("Failed to remove file {}: {error}", self.path);
            }
        }
    }
}
