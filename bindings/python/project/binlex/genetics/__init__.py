"""Genetic-inspired pattern and similarity types exposed by binlex."""

from __future__ import annotations

from typing import Any

from binlex import Configuration
from binlex_bindings.binlex.genetics import AllelePair, Gene
from binlex_bindings.binlex.genetics import Chromosome as _ChromosomeBinding


def _coerce_byte_buffer(data: bytes | bytearray | memoryview, parameter: str) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    raise TypeError(f"{parameter} must be bytes, bytearray, or memoryview")


def _parse_pattern(pattern: str, wildcard: str) -> tuple[bytes, bytes]:
    if len(wildcard) != 1:
        raise ValueError("wildcard must be a single character")
    normalized = pattern if wildcard == "?" else pattern.replace(wildcard, "?")
    if len(normalized) % 2 != 0:
        raise ValueError("pattern length must be even")

    raw_bytes = bytearray()
    wildcard_mask = bytearray()
    for offset in range(0, len(normalized), 2):
        pair = normalized[offset : offset + 2]
        value = 0
        mask = 0
        for index, character in enumerate(pair):
            shift = 4 if index == 0 else 0
            if character == "?":
                mask |= 0xF << shift
                continue
            try:
                nibble = int(character, 16)
            except ValueError as error:
                raise ValueError(f"invalid hexadecimal digit: {character!r}") from error
            value |= nibble << shift
        raw_bytes.append(value)
        wildcard_mask.append(mask)
    return bytes(raw_bytes), bytes(wildcard_mask)


class Chromosome:
    """Represent a chromosome pattern and its derived similarity features."""

    def __init__(
        self,
        data: str | bytes | bytearray | memoryview,
        configuration: Configuration,
        wildcard: str = "?",
        wildcard_mask: bytes | bytearray | memoryview | None = None,
        _inner: _ChromosomeBinding | None = None,
    ) -> None:
        self._configuration = configuration
        if _inner is not None:
            self._inner = _inner
            return

        if isinstance(data, str):
            raw_bytes, mask = _parse_pattern(data, wildcard)
        else:
            raw_bytes = _coerce_byte_buffer(data, "data")
            if wildcard_mask is None:
                raise TypeError("wildcard_mask is required when constructing a chromosome from bytes")
            mask = _coerce_byte_buffer(wildcard_mask, "wildcard_mask")

        self._inner = _ChromosomeBinding(raw_bytes, mask, configuration)

    def mutate(
        self,
        data: str | bytes | bytearray | memoryview,
        wildcard: str = "?",
        wildcard_mask: bytes | bytearray | memoryview | None = None,
    ) -> None:
        if isinstance(data, str):
            raw_bytes, mask = _parse_pattern(data, wildcard)
        else:
            raw_bytes = _coerce_byte_buffer(data, "data")
            if wildcard_mask is None:
                raise TypeError("wildcard_mask is required when mutating a chromosome from bytes")
            mask = _coerce_byte_buffer(wildcard_mask, "wildcard_mask")
        self._inner.mutate(raw_bytes, mask)

    def to_binding(self) -> _ChromosomeBinding:
        return self._inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __str__(self) -> str:
        return str(self._inner)


__all__ = ["AllelePair", "Chromosome", "Gene"]
