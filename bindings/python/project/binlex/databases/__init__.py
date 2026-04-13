"""Database backends and search-oriented types."""

from importlib import import_module

from .localdb import (
    CollectionCommentRecord,
    CollectionTagRecord,
    LocalDB,
    RoleRecord,
    SampleCommentRecord,
    SampleStatus,
    SampleStatusRecord,
    TokenRecord,
    UserRecord,
)

_LAZY_EXPORTS = {
    "LanceDB": ".lancedb",
    "Milvus": ".milvus",
    "SQLite": ".sqlite",
}


def __getattr__(name):
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_name, __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


__all__ = [
    "LanceDB",
    "LocalDB",
    "Milvus",
    "SampleStatus",
    "SampleStatusRecord",
    "SQLite",
    "CollectionCommentRecord",
    "CollectionTagRecord",
    "SampleCommentRecord",
    "RoleRecord",
    "TokenRecord",
    "UserRecord",
]
