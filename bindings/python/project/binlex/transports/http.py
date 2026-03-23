"""High-level binlex-server client bindings."""

from __future__ import annotations

from binlex._global import Config
from binlex.architecture import Architecture, _coerce_architecture
from binlex.controlflow import Graph
from binlex.magic import Magic, _coerce_magic
from binlex_bindings.binlex.transports.http import Client as _ClientBinding


class Client:
    """Binary-oriented client for the binlex HTTP server."""

    def __init__(
        self,
        config: Config,
        url: str | None = None,
        verify: bool | None = None,
        compression: bool | None = None,
    ) -> None:
        self._inner = _ClientBinding(config, url, verify, compression)

    @property
    def url(self) -> str:
        return self._inner.url

    @property
    def verify(self) -> bool:
        return self._inner.verify

    @property
    def compression(self) -> bool:
        return self._inner.compression

    def health(self) -> dict[str, str]:
        return self._inner.health()

    def analyze_file(
        self,
        path: str,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
    ) -> Graph:
        native_magic = None if magic is None else str(_coerce_magic(magic))
        native_architecture = (
            None if architecture is None else str(_coerce_architecture(architecture))
        )
        return Graph.from_binding(
            self._inner.analyze_file(path, native_magic, native_architecture)
        )

    def analyze_bytes(
        self,
        data: bytes,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
        name: str | None = None,
    ) -> Graph:
        native_magic = None if magic is None else str(_coerce_magic(magic))
        native_architecture = (
            None if architecture is None else str(_coerce_architecture(architecture))
        )
        return Graph.from_binding(
            self._inner.analyze_bytes(data, native_magic, native_architecture, name)
        )


__all__ = ["Client"]
