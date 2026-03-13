from __future__ import annotations

from enum import Enum

class Palette(str, Enum):
    GRAYSCALE: str
    HEATMAP: str
    BLUEGREEN: str
    REDBLACK: str

__all__ = ["Palette"]
