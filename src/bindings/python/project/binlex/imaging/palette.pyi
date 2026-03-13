from __future__ import annotations

from enum import Enum

class Palette(str, Enum):
    GRAYSCALE: Palette
    HEATMAP: Palette
    BLUEGREEN: Palette
    REDBLACK: Palette

__all__ = ["Palette"]
