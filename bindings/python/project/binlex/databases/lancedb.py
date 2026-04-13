"""LanceDB indexing backend."""

from binlex.core.architecture import _coerce_architecture
from binlex.indexing.local import Collection
from binlex_bindings.binlex import databases as _databases_binding

_LanceDBBinding = _databases_binding.lancedb.LanceDB


class LanceDB:
    def __init__(self, root):
        self._inner = _LanceDBBinding(root)

    @property
    def root(self):
        return self._inner.root

    def upsert(
        self,
        corpus,
        collection,
        architecture,
        object_id,
        vector,
        occurrences,
        sha256=None,
        address=None,
    ):
        return self._inner.upsert(
            corpus,
            collection,
            _coerce_architecture(architecture),
            object_id,
            vector,
            occurrences,
            sha256,
            address,
        )

    def upsert_rows(self, corpus, collection, architecture, rows):
        return self._inner.upsert_rows(
            corpus,
            collection,
            _coerce_architecture(architecture),
            rows,
        )

    def search(self, corpus, collection, architecture, vector, limit=10):
        return self._inner.search(
            corpus,
            collection,
            _coerce_architecture(architecture),
            vector,
            limit,
        )


__all__ = ["LanceDB", "Collection"]
