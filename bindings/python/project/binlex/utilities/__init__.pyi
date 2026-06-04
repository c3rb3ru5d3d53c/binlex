from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")
U = TypeVar("U")
D = TypeVar("D")


class Maybe(Generic[T]):
    def then(self, fn: Callable[[T], U | None]) -> Maybe[U]: ...
    def get(self, default: D | None = None) -> T | D | None: ...


def maybe(value: T | None) -> Maybe[T]: ...

from .hexdump import hexdump


__all__ = ["Maybe", "maybe", "hexdump"]
