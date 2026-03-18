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

"""Terminal rendering helpers for ANSI-colored binary output."""

from binlex_bindings.binlex.imaging import Terminal as _TerminalBinding

from .palette import Palette


class Terminal:
    """Render binary data as ANSI-colored terminal output."""

    def __init__(
        self,
        data: bytes,
        palette: Palette,
        cell_size: int = 1,
        fixed_width: int = 16,
    ) -> None:
        """Create a terminal renderer for `data` using the given palette."""
        self._inner = _TerminalBinding(
            data,
            palette.to_binding(),
            cell_size,
            fixed_width,
        )

    def print(self) -> None:
        """Write the rendered terminal view to stdout."""
        self._inner.print()

    @staticmethod
    def rgb_to_ansi256(r: int, g: int, b: int) -> int:
        """Convert an RGB triplet into the nearest ANSI 256-color index."""
        return _TerminalBinding.rgb_to_ansi256(r, g, b)


__all__ = ["Terminal"]
