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

"""Small Python-side utility helpers for binlex."""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")
U = TypeVar("U")


class Maybe(Generic[T]):
    """Fluent None-propagating wrapper for typed optional chains."""

    __slots__ = ("_value",)

    def __init__(self, value: T | None) -> None:
        self._value = value

    def then(self, fn: Callable[[T], U | None]) -> "Maybe[U]":
        """Apply `fn` when a value is present and wrap the result."""
        if self._value is None:
            return Maybe(None)
        return Maybe(fn(self._value))

    def get(self, default: U | T | None = None):
        """Return the wrapped value or `default` when empty."""
        if self._value is None:
            return default
        return self._value

    def __repr__(self) -> str:
        return f"Maybe({self._value!r})"


def maybe(value: T | None) -> Maybe[T]:
    """Wrap `value` in a fluent None-propagating helper."""
    return Maybe(value)


__all__ = ["Maybe", "maybe"]
