"""Milvus indexing backend."""

from binlex_bindings.binlex.indexing.milvus import Client as _MilvusBinding


class Milvus:
    def __init__(self, uri, token=None):
        self._inner = _MilvusBinding(uri, token)

    @property
    def uri(self):
        return self._inner.uri

    @property
    def token(self):
        return self._inner.token

    def ensure_collection(self, database, collection, fields):
        return self._inner.ensure_collection(database, collection, fields)

    def upsert(self, database, collection, row):
        return self._inner.upsert(database, collection, row)


__all__ = ["Milvus"]
