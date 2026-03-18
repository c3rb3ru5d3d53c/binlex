from __future__ import annotations

from .palette import Palette

class PNG:
    def __init__(
        self,
        data: bytes,
        palette: Palette,
        cell_size: int = 1,
        fixed_width: int = 16,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def write(self, file_path: str) -> None: ...

__all__ = ["PNG"]
