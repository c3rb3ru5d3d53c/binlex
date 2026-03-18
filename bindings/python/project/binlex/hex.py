"""Hexadecimal encoding and decoding helpers."""

from binlex_bindings.binlex.hex import decode as _decode
from binlex_bindings.binlex.hex import encode as _encode


def encode(bytes):
    """Return a lowercase hexadecimal string for the supplied byte sequence."""
    return _encode(bytes)


def decode(value):
    """Decode a hexadecimal string into raw bytes.

    Raises `ValueError` when `value` is not valid hexadecimal input.
    """
    return bytes(_decode(value))


__all__ = ["decode", "encode"]
