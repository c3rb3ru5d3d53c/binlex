from __future__ import annotations

from .palette import Palette

class SVG:
    def __init__(
        self,
        data: bytes,
        palette: Palette,
        cell_size: int = 1,
        fixed_width: int = 16,
    ) -> None: ...
    def add_metadata(self, key: str, value: str) -> None: ...
    def to_string(self) -> str: ...
    def write(self, file_path: str) -> None: ...
    def print(self) -> None: ...

__all__ = ["SVG"]
