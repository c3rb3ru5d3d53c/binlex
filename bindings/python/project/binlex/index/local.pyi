from binlex.architecture import Architecture
from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.metadata import Attribute


class Collection:
    Instruction: "Collection"
    Block: "Collection"
    Function: "Collection"


Entity = Collection


class SearchResult:
    def corpus(self) -> str: ...
    def score(self) -> float: ...
    def sha256(self) -> str: ...
    def address(self) -> int: ...
    def object_id(self) -> str: ...
    def symbol(self) -> str | None: ...
    def attributes(self) -> list[dict]: ...
    def architecture(self) -> str: ...
    def collection(self) -> Collection: ...
    def graph(self) -> Graph: ...
    def function(self) -> Function | None: ...
    def block(self) -> Block | None: ...
    def instruction(self) -> Instruction | None: ...


class LocalIndex:
    def __init__(
        self,
        config: object,
        directory: str | None = None,
        dimensions: int | None = None,
    ) -> None: ...
    def put(self, data: bytes) -> str: ...
    def get(self, sha256: str) -> bytes: ...
    def index_graph(
        self,
        sha256: str,
        graph: Graph,
        corpus: str | None = None,
        corpora: list[str] | None = None,
        attributes: list[Attribute] | None = None,
        selector: str | None = None,
        collections: list[Collection] | None = None,
    ) -> None: ...
    def index_instruction(
        self,
        architecture: Architecture,
        vector: list[float],
        sha256: str,
        address: int,
        attributes: list[Attribute] | None = None,
        corpus: str | None = None,
        corpora: list[str] | None = None,
    ) -> None: ...
    def index_block(
        self,
        architecture: Architecture,
        vector: list[float],
        sha256: str,
        address: int,
        attributes: list[Attribute] | None = None,
        corpus: str | None = None,
        corpora: list[str] | None = None,
    ) -> None: ...
    def index_function(
        self,
        architecture: Architecture,
        vector: list[float],
        sha256: str,
        address: int,
        attributes: list[Attribute] | None = None,
        corpus: str | None = None,
        corpora: list[str] | None = None,
    ) -> None: ...
    def vector(
        self,
        collection: Collection,
        architecture: Architecture,
        vector: list[float],
        sha256: str,
        address: int,
        corpus: str | None = None,
        corpora: list[str] | None = None,
    ) -> None: ...
    def commit(self) -> None: ...
    def clear(self) -> None: ...
    def load(self, corpus: str, sha256: str) -> Graph: ...
    def corpora(self) -> list[str]: ...
    def delete(self, corpus: str, sha256: str) -> None: ...
    def delete_corpus(self, corpus: str) -> None: ...
    def search(
        self,
        corpora: list[str],
        vector: list[float],
        collections: list[Collection] | None = None,
        architectures: list[Architecture] | None = None,
        limit: int = 10,
    ) -> list[SearchResult]: ...


__all__ = ["Collection", "Entity", "LocalIndex", "SearchResult"]
