"""Filesystem-backed object storage helpers."""

from binlex_bindings.binlex.storage.object_store import ObjectStore as _ObjectStoreBinding


class ObjectStore:
    def __init__(self, root):
        self._inner = _ObjectStoreBinding(root)

    @property
    def root(self):
        return self._inner.root

    def put_bytes(self, key, payload):
        return self._inner.put_bytes(key, payload)

    def get_bytes(self, key):
        return self._inner.get_bytes(key)

    def exists(self, key):
        return self._inner.exists(key)

    def put_json(self, key, value):
        return self._inner.put_json(key, value)

    def get_json(self, key):
        return self._inner.get_json(key)

    def list_json_prefix(self, prefix):
        return self._inner.list_json_prefix(prefix)

    def delete_prefix(self, prefix):
        return self._inner.delete_prefix(prefix)


__all__ = ["ObjectStore"]
