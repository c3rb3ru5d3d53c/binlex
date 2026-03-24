# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Binary format wrappers for files and executable containers."""

from binlex_bindings.binlex.formats import ELF as _ELFBinding
from binlex_bindings.binlex.formats import File as _FileBinding
from binlex_bindings.binlex.formats import Image as _ImageBinding
from binlex_bindings.binlex.formats import MACHO as _MACHOBinding
from binlex_bindings.binlex.formats import PE as _PEBinding

from binlex.architecture import Architecture
from binlex.hashing import SHA256, TLSH
from binlex.magic import Magic


class Image:
    """Writable binary image helper backed by the native image implementation."""

    def __init__(self, path, cache):
        """Open or create an image file at `path`."""
        self._inner = _ImageBinding(path, cache)

    @classmethod
    def from_binding(cls, binding):
        """Wrap an existing native image binding in the Python helper class."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def is_cached(self):
        """Return whether the image is backed by a cache file."""
        return self._inner.is_cached()

    def path(self):
        """Return the filesystem path backing the image."""
        return self._inner.path()

    def write(self, data):
        """Write raw bytes at the current file position."""
        return self._inner.write(data)

    def write_padding(self, length):
        """Write `length` bytes of padding at the current file position."""
        return self._inner.write_padding(length)

    def seek_to_end(self):
        """Seek to the end of the image and return the resulting offset."""
        return self._inner.seek_to_end()

    def seek(self, offset):
        """Seek to an absolute offset in the image."""
        return self._inner.seek(offset)

    def size(self):
        """Return the current size of the image in bytes."""
        return self._inner.size()

    def mmap(self):
        """Return a read-only memory view over the image bytes."""
        return self._inner.mmap()

    def mmap_mut(self):
        """Return a writable memory view over the image bytes."""
        return self._inner.mmap_mut()


class ELF:
    """Executable and Linkable Format wrapper with address translation helpers."""

    def __init__(self, path, config):
        """Open an ELF image from `path` using the supplied binlex configuration."""
        self._inner = _ELFBinding(path, config)

    @classmethod
    def from_bytes(cls, bytes, config):
        """Parse an ELF image from an in-memory byte sequence."""
        result = cls.__new__(cls)
        result._inner = _ELFBinding.from_bytes(bytes, config)
        return result

    def architecture(self):
        """Return the architecture declared by the ELF image."""
        return Architecture.from_binding(self._inner.architecture())

    def executable_virtual_address_ranges(self):
        """Return executable virtual address ranges as `{start: end}` mappings."""
        return self._inner.executable_virtual_address_ranges()

    def relative_virtual_address_to_virtual_address(self, relative_virtual_address):
        """Translate a relative virtual address into a virtual address."""
        return self._inner.relative_virtual_address_to_virtual_address(
            relative_virtual_address
        )

    def file_offset_to_virtual_address(self, file_offset):
        """Translate a file offset into a virtual address when a mapping exists."""
        return self._inner.file_offset_to_virtual_address(file_offset)

    def entrypoint_virtual_addresses(self):
        """Return all discovered entrypoint virtual addresses."""
        return self._inner.entrypoint_virtual_addresses()

    def entrypoint_virtual_address(self):
        """Return the primary ELF entrypoint virtual address."""
        return self._inner.entrypoint_virtual_address()

    def image(self):
        """Return an `Image` wrapper over the ELF contents."""
        return Image.from_binding(self._inner.image())

    def tlsh(self):
        """Return the TLSH helper for the image when available."""
        return self._inner.tlsh()

    def sha256(self):
        """Return the SHA-256 helper for the image when available."""
        return self._inner.sha256()

    def size(self):
        """Return the ELF image size in bytes."""
        return self._inner.size()

    def export_virtual_addresses(self):
        """Return exported symbol virtual addresses."""
        return self._inner.export_virtual_addresses()

    def entropy(self):
        """Return the image entropy, or `None` when it cannot be computed."""
        return self._inner.entropy()

    def file(self):
        """Return the associated `binlex.formats.File` wrapper."""
        return File.from_binding(self._inner.file())

    def __getattr__(self, name):
        """Delegate unknown attributes to the underlying native ELF object."""
        return getattr(self._inner, name)


class File:
    """High-level wrapper around a file binding with typed helpers."""

    def __init__(self, path, config):
        """Open a file using the supplied binlex configuration."""
        self._inner = _FileBinding(path, config)

    @classmethod
    def from_binding(cls, binding):
        """Wrap an existing native file binding in the Python helper class."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def magic(self):
        """Return the detected file type as a `binlex.Magic` value."""
        return Magic.from_binding(self._inner.magic())

    def __getattr__(self, name):
        """Delegate unknown attributes to the underlying native file object."""
        return getattr(self._inner, name)


class PE:
    """Portable Executable wrapper with address translation helpers."""

    def __init__(self, path, config):
        """Open a PE image from disk."""
        self._inner = _PEBinding(path, config)

    @classmethod
    def from_bytes(cls, bytes, config):
        """Construct a PE image from an in-memory byte sequence."""
        result = cls.__new__(cls)
        result._inner = _PEBinding.from_bytes(bytes, config)
        return result

    def architecture(self):
        """Return the architecture declared by the PE image."""
        return Architecture.from_binding(self._inner.architecture())

    def file(self):
        """Return the associated `binlex.formats.File` wrapper."""
        return File.from_binding(self._inner.file())

    def __getattr__(self, name):
        """Delegate unknown attributes to the underlying native PE object."""
        return getattr(self._inner, name)


class MACHO:
    """Mach-O wrapper for single-arch and fat binaries with slice-aware helpers."""

    def __init__(self, path, config):
        """Open a Mach-O image from disk using the supplied binlex configuration."""
        self._inner = _MACHOBinding(path, config)

    @classmethod
    def from_bytes(cls, bytes, config):
        """Parse a Mach-O image from an in-memory byte sequence."""
        result = cls.__new__(cls)
        result._inner = _MACHOBinding.from_bytes(bytes, config)
        return result

    def relative_virtual_address_to_virtual_address(
        self, relative_virtual_address, slice
    ):
        """Translate a slice-relative virtual address into a virtual address."""
        return self._inner.relative_virtual_address_to_virtual_address(
            relative_virtual_address, slice
        )

    def file_offset_to_virtual_address(self, file_offset, slice):
        """Translate a file offset into a virtual address for `slice` when possible."""
        return self._inner.file_offset_to_virtual_address(file_offset, slice)

    def number_of_slices(self):
        """Return the number of slices contained in the Mach-O image."""
        return self._inner.number_of_slices()

    def entrypoint_virtual_address(self, slice):
        """Return the primary entrypoint virtual address for `slice`."""
        return self._inner.entrypoint_virtual_address(slice)

    def imagebase(self, slice):
        """Return the image base for `slice` when available."""
        return self._inner.imagebase(slice)

    def sizeofheaders(self, slice):
        """Return the header size for `slice` when available."""
        return self._inner.sizeofheaders(slice)

    def architecture(self, slice):
        """Return the architecture declared for `slice`, if present."""
        architecture = self._inner.architecture(slice)
        if architecture is None:
            return None
        return Architecture.from_binding(architecture)

    def entrypoint_virtual_addresses(self, slice):
        """Return all discovered entrypoint virtual addresses for `slice`."""
        return self._inner.entrypoint_virtual_addresses(slice)

    def export_virtual_addresses(self, slice):
        """Return exported symbol virtual addresses for `slice`."""
        return self._inner.export_virtual_addresses(slice)

    def executable_virtual_address_ranges(self, slice):
        """Return executable virtual address ranges for `slice` as `{start: end}`."""
        return self._inner.executable_virtual_address_ranges(slice)

    def image(self, slice):
        """Return an `Image` wrapper over the contents of `slice`."""
        return Image.from_binding(self._inner.image(slice))

    def size(self):
        """Return the full Mach-O container size in bytes."""
        return self._inner.size()

    def tlsh(self):
        """Return the TLSH helper for the image when available."""
        return self._inner.tlsh()

    def sha256(self):
        """Return the SHA-256 helper for the image when available."""
        return self._inner.sha256()

    def entropy(self):
        """Return the image entropy, or `None` when it cannot be computed."""
        return self._inner.entropy()

    def file(self):
        """Return the associated `binlex.formats.File` wrapper."""
        return File.from_binding(self._inner.file())

    def __getattr__(self, name):
        """Delegate unknown attributes to the underlying native Mach-O object."""
        return getattr(self._inner, name)

__all__ = ["ELF", "File", "Image", "MACHO", "PE"]
