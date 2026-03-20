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

"""SVG rendering helpers for binary visualization output."""

from binlex_bindings.binlex.imaging import SVG as _SVGBinding
from binlex import Config
from binlex.hashing import AHash, DHash, PHash

from .palette import Palette


class SVG:
    """Render binary data into an SVG image."""

    @classmethod
    def from_binding(cls, binding):
        """Wrap an existing native SVG binding."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def __init__(
        self,
        data: bytes,
        palette: Palette,
        config: Config,
        cell_size: int = 1,
        fixed_width: int = 16,
    ) -> None:
        """Create an SVG renderer for `data` using the given palette."""
        self._inner = _SVGBinding(
            data,
            palette.to_binding(),
            config,
            cell_size,
            fixed_width,
        )

    def add_metadata(self, key: str, value: str) -> None:
        """Attach an SVG metadata field to the generated document."""
        self._inner.add_metadata(key, value)

    def to_string(self) -> str:
        """Return the generated SVG document as a string."""
        return self._inner.to_string()

    def write(self, file_path: str) -> None:
        """Write the SVG document to `file_path`."""
        self._inner.write(file_path)

    def print(self) -> None:
        """Write the rendered terminal preview to stdout."""
        self._inner.print()

    def print_svg(self) -> None:
        """Print the generated SVG document to stdout."""
        self._inner.print_svg()

    def sha256(self) -> str | None:
        return self._inner.sha256()

    def tlsh(self) -> str | None:
        return self._inner.tlsh()

    def minhash(self) -> str | None:
        return self._inner.minhash()

    def ahash(self) -> AHash | None:
        return self._inner.ahash()

    def dhash(self) -> DHash | None:
        return self._inner.dhash()

    def phash(self) -> PHash | None:
        return self._inner.phash()

    def __str__(self) -> str:
        return self.to_string()

__all__ = ["SVG"]
