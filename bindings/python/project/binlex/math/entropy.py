"""Entropy-related helpers for binary data."""

from binlex_bindings.binlex.entropy import shannon as _shannon


def shannon(bytes):
    """Return the Shannon entropy for a byte sequence.

    The return value is `None` when the entropy cannot be computed for the
    supplied data.
    """
    return _shannon(bytes)


__all__ = ["shannon"]
