"""Direct SQLite database helper."""

from binlex_bindings.binlex import databases as _databases_binding

_SQLiteBinding = _databases_binding.sqlite.SQLite


SQLite = _SQLiteBinding

__all__ = ["SQLite"]
