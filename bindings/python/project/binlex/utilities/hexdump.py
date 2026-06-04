"""Hexdump rendering helpers."""

from binlex_bindings.binlex.utilities.hexdump import hexdump as _hexdump


def hexdump(address, data):
    """Render a byte sequence as a hexdump starting at `address`."""
    return _hexdump(address, data)


__all__ = ["hexdump"]
