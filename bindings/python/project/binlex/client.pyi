from __future__ import annotations

from binlex.config import Config
from binlex.core.architecture import Architecture
from binlex.controlflow import Graph
from binlex.core.magic import Magic

class Client:
    def __init__(
        self,
        config: Config,
        url: str | None = None,
        verify: bool | None = None,
        compression: bool | None = None,
    ) -> None: ...
    @property
    def url(self) -> str: ...
    @property
    def verify(self) -> bool: ...
    @property
    def compression(self) -> bool: ...
    def health(self) -> dict[str, str]: ...
    def analyze_file(
        self,
        path: str,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
    ) -> Graph: ...
    def analyze_bytes(
        self,
        data: bytes,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
    ) -> Graph: ...

__all__ = ["Client"]
