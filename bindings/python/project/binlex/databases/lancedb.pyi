from binlex.core.architecture import Architecture
from binlex.indexing.local import Collection


class LanceDB:
    def __init__(self, root: str) -> None: ...
    @property
    def root(self) -> str: ...
    def upsert(
        self,
        corpus: str,
        collection: Collection,
        architecture: Architecture,
        object_id: str,
        vector: list[float],
        occurrences: object,
    ) -> None: ...
    def upsert_rows(
        self,
        corpus: str,
        collection: Collection,
        architecture: Architecture,
        rows: list[dict[str, object]],
    ) -> None: ...
    def search(
        self,
        corpus: str,
        collection: Collection,
        architecture: Architecture,
        vector: list[float],
        limit: int = 10,
    ) -> list[dict[str, object]]: ...
