"""MinIO object storage backend."""

from binlex_bindings.binlex.storage.minio import Client as _MinIOBinding


class MinIO:
    def __init__(self, endpoint, access_key, secret_key, secure=False):
        self._inner = _MinIOBinding(endpoint, access_key, secret_key, secure)

    @property
    def endpoint(self):
        return self._inner.endpoint

    @property
    def access_key(self):
        return self._inner.access_key

    @property
    def secret_key(self):
        return self._inner.secret_key

    @property
    def secure(self):
        return self._inner.secure

    def ensure_bucket(self, bucket):
        return self._inner.ensure_bucket(bucket)

    def put_object(self, bucket, key, payload, content_type="application/octet-stream"):
        return self._inner.put_object(bucket, key, payload, content_type)


__all__ = ["MinIO"]
