class Client:
    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        secure: bool = False,
    ) -> None: ...
    @property
    def endpoint(self) -> str: ...
    @property
    def access_key(self) -> str: ...
    @property
    def secret_key(self) -> str: ...
    @property
    def secure(self) -> bool: ...
    def ensure_bucket(self, bucket: str) -> None: ...
    def put_object(
        self,
        bucket: str,
        key: str,
        payload: bytes,
        content_type: str = "application/octet-stream",
    ) -> None: ...

__all__ = ["Client"]
