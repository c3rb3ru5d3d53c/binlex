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

"""Fluent imaging pipeline helpers for visualization output."""

from typing import Literal

from binlex_bindings.binlex.imaging import Imaging as _ImagingBinding

from .png import PNG
from .svg import SVG
from .terminal import Terminal

DigraphIntensity = Literal["linear", "log", "sqrt"]


class Imaging:
    """Select a renderer for a visualization pipeline."""

    @classmethod
    def _from_binding(cls, binding):
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def __init__(self, data, config):
        self._inner = _ImagingBinding(data, config)

    def linear(self, cell_size=1, fixed_width=16):
        """Select the linear renderer."""
        return ImagingRenderer._from_binding(
            self._inner.linear(cell_size, fixed_width)
        )

    def bitmap(self, cell_size=1, fixed_width=16):
        """Select the bitmap renderer."""
        return ImagingRenderer._from_binding(
            self._inner.bitmap(cell_size, fixed_width)
        )

    def digraph(
        self,
        cell_size=1,
        axis_size=256,
        stride=1,
        offset=0,
        window_size=None,
        intensity: DigraphIntensity = "log",
    ):
        """Select the digraph renderer.

        Defaults:
            cell_size=1
            axis_size=256
            stride=1
            offset=0
            window_size=None
            intensity="log"

        Intensity options:
            "linear", "log", "sqrt"
        """
        return ImagingRenderer._from_binding(
            self._inner.digraph(
                cell_size, axis_size, stride, offset, window_size, intensity
            )
        )

    def entropy(self, window_size=64, cell_size=1, fixed_width=64):
        """Select the entropy renderer."""
        return ImagingRenderer._from_binding(
            self._inner.entropy(window_size, cell_size, fixed_width)
        )

    def hilbert(self, cell_size=1):
        """Select the Hilbert renderer."""
        return ImagingRenderer._from_binding(self._inner.hilbert(cell_size))


class ImagingRenderer:
    """Configure renderer-level options such as palette and sizing."""

    @classmethod
    def _from_binding(cls, binding):
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def grayscale(self):
        """Select the grayscale palette."""
        return ImagingPalette._from_binding(self._inner.grayscale())

    def heatmap(self):
        """Select the heatmap palette."""
        return ImagingPalette._from_binding(self._inner.heatmap())

    def bluegreen(self):
        """Select the bluegreen palette."""
        return ImagingPalette._from_binding(self._inner.bluegreen())

    def redblack(self):
        """Select the redblack palette."""
        return ImagingPalette._from_binding(self._inner.redblack())

class ImagingPalette:
    """Configure palette-adjusted output options and materialize formats."""

    @classmethod
    def _from_binding(cls, binding):
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def png(self):
        """Materialize the pipeline as a PNG image."""
        return PNG._from_binding(self._inner.png())

    def svg(self):
        """Materialize the pipeline as an SVG image."""
        return SVG._from_binding(self._inner.svg())

    def terminal(self):
        """Materialize the pipeline as a terminal renderer."""
        return Terminal._from_binding(self._inner.terminal())


__all__ = ["DigraphIntensity", "Imaging", "ImagingPalette", "ImagingRenderer"]
