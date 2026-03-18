"""Hexdump rendering helpers."""

from binlex_bindings.binlex.hexdump import hexdump as _hexdump


def hexdump(bytes, address):
    """Render a byte sequence as a hexdump starting at `address`."""
    return _hexdump(bytes, address)


__all__ = ["hexdump"]
