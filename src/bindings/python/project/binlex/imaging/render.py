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

from binlex_bindings.binlex.imaging import Render as _RenderBinding
from binlex_bindings.binlex.imaging import RenderCell as _RenderCellBinding

from .palette import Palette


class RenderCell:
    def __init__(self, inner: _RenderCellBinding) -> None:
        self._inner = inner

    @property
    def index(self) -> int:
        return self._inner.index

    @property
    def address(self) -> int:
        return self._inner.address

    @property
    def x(self) -> int:
        return self._inner.x

    @property
    def y(self) -> int:
        return self._inner.y

    @property
    def width(self) -> int:
        return self._inner.width

    @property
    def height(self) -> int:
        return self._inner.height

    @property
    def rgb(self) -> tuple[int, int, int]:
        return self._inner.rgb


class Render:
    def __init__(
        self,
        data: bytes,
        palette: Palette,
        cell_size: int = 1,
        fixed_width: int = 16,
    ) -> None:
        self._inner = _RenderBinding(
            data,
            palette.to_binding(),
            cell_size,
            fixed_width,
        )

    @property
    def total_width(self) -> int:
        return self._inner.total_width

    @property
    def total_height(self) -> int:
        return self._inner.total_height

    @property
    def total_cells(self) -> int:
        return self._inner.total_cells

    @property
    def fixed_width(self) -> int:
        return self._inner.fixed_width

    @property
    def cells(self) -> list[RenderCell]:
        return [RenderCell(cell) for cell in self._inner.cells]


__all__ = ["Render", "RenderCell"]
