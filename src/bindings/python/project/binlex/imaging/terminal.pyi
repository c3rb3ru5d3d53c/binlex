from __future__ import annotations

from .palette import Palette

class Terminal:
    def __init__(
        self,
        data: bytes,
        palette: Palette,
        cell_size: int = 1,
        fixed_width: int = 16,
    ) -> None: ...
    def print(self) -> None: ...
    @staticmethod
    def rgb_to_ansi256(r: int, g: int, b: int) -> int: ...

__all__ = ["Terminal"]
