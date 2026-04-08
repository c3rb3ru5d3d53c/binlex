from datetime import datetime

from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.core.architecture import Architecture
from binlex.databases.localdb import (
    CollectionCommentRecord,
    CollectionTagRecord,
    SampleStatus,
    SampleStatusRecord,
)
from binlex.metadata import Attribute


class Collection:
    Instruction: "Collection"
    Block: "Collection"
    Function: "Collection"


Entity = Collection


class TagRecord:
    def sha256(self) -> str: ...
    def tag(self) -> str: ...
    def timestamp(self) -> datetime: ...


class CommentRecord:
    def sha256(self) -> str: ...
    def comment(self) -> str: ...
    def timestamp(self) -> datetime: ...


class TagSearchPage:
    def items(self) -> list[TagRecord]: ...
    def page(self) -> int: ...
    def page_size(self) -> int: ...
    def has_next(self) -> bool: ...


class CollectionTagSearchPage:
    def items(self) -> list[CollectionTagRecord]: ...
    def page(self) -> int: ...
    def page_size(self) -> int: ...
    def has_next(self) -> bool: ...


class CollectionCommentSearchPage:
    def items(self) -> list[CollectionCommentRecord]: ...
    def page(self) -> int: ...
    def page_size(self) -> int: ...
    def has_next(self) -> bool: ...


class CommentSearchPage:
    def items(self) -> list[CommentRecord]: ...
    def page(self) -> int: ...
    def page_size(self) -> int: ...
    def has_next(self) -> bool: ...


class SearchResult:
    def corpus(self) -> str: ...
    def corpora(self) -> list[str]: ...
    def score(self) -> float: ...
    def sha256(self) -> str: ...
    def embedding(self) -> str: ...
    def embeddings(self) -> int: ...
    def address(self) -> int: ...
    def size(self) -> int: ...
    def timestamp(self) -> datetime: ...
    def object_id(self) -> str: ...
    def symbol(self) -> str | None: ...
    def attributes(self) -> list[dict]: ...
    def architecture(self) -> str: ...
    def username(self) -> str: ...
    def collection(self) -> Collection: ...
    def graph(self) -> Graph: ...
    def function(self) -> Function | None: ...
    def block(self) -> Block | None: ...
    def instruction(self) -> Instruction | None: ...


class QueryResult:
    def lhs(self) -> SearchResult | None: ...
    def rhs(self) -> SearchResult | None: ...
    def score(self) -> float: ...


class LocalIndex:
    def __init__(
        self,
        config: object,
        directory: str | None = None,
        dimensions: int | None = None,
    ) -> None: ...
    def sample_put(self, data: bytes) -> str: ...
    def sample_get(self, sha256: str) -> bytes: ...
    def graph(
        self,
        sha256: str,
        graph: Graph,
        attributes: list[Attribute] | None = None,
        selector: str | None = None,
        collections: list[Collection] | None = None,
        corpora: list[str] | None = None,
        username: str | None = None,
    ) -> None: ...
    def instruction(
        self,
        instruction: Instruction,
        vector: list[float],
        sha256: str,
        attributes: list[Attribute] | None = None,
        corpora: list[str] | None = None,
        username: str | None = None,
    ) -> None: ...
    def block(
        self,
        block: Block,
        vector: list[float],
        sha256: str,
        attributes: list[Attribute] | None = None,
        corpora: list[str] | None = None,
        username: str | None = None,
    ) -> None: ...
    def function(
        self,
        function: Function,
        vector: list[float],
        sha256: str,
        attributes: list[Attribute] | None = None,
        corpora: list[str] | None = None,
        username: str | None = None,
    ) -> None: ...
    def commit(self) -> None: ...
    def clear(self) -> None: ...
    def sample_load(self, corpus: str, sha256: str) -> Graph: ...
    def corpus_list(self) -> list[str]: ...
    def sample_delete(self, corpus: str, sha256: str) -> None: ...
    def corpus_delete(self, corpus: str) -> None: ...
    def symbol_add(self, sha256: str, address: int, name: str) -> None: ...
    def symbol_remove(self, sha256: str, address: int, name: str) -> None: ...
    def symbol_replace(self, sha256: str, address: int, name: str) -> None: ...
    def corpus_add(self, sha256: str, corpus: str) -> None: ...
    def corpus_replace(self, sha256: str, corpus: str) -> None: ...
    def corpus_rename(self, old_name: str, new_name: str) -> None: ...
    def sample_comment_add(
        self,
        sha256: str,
        comment: str,
        timestamp: datetime | None = None,
    ) -> None: ...
    def sample_comment_remove(self, sha256: str, comment: str) -> None: ...
    def sample_comment_replace(
        self,
        sha256: str,
        comments: list[str],
        timestamp: datetime | None = None,
    ) -> None: ...
    def sample_comment_search(
        self,
        query: str,
        page: int = 1,
        page_size: int = 50,
    ) -> CommentSearchPage: ...
    def sample_status_get(self, sha256: str) -> SampleStatusRecord | None: ...
    def sample_status_set(
        self,
        sha256: str,
        status: SampleStatus,
        timestamp: datetime | None = None,
        id: str | None = None,
        error_message: str | None = None,
    ) -> None: ...
    def collection_tag_add(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tag: str,
    ) -> None: ...
    def collection_tag_remove(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tag: str,
    ) -> None: ...
    def collection_tag_replace(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tags: list[str],
    ) -> None: ...
    def collection_comment_add(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        comment: str,
        timestamp: datetime | None = None,
    ) -> None: ...
    def collection_comment_remove(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        comment: str,
    ) -> None: ...
    def collection_comment_replace(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        comments: list[str],
        timestamp: datetime | None = None,
    ) -> None: ...
    def collection_tag_search(
        self,
        query: str,
        collection: Collection | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> CollectionTagSearchPage: ...
    def collection_comment_search(
        self,
        query: str,
        collection: Collection | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> CollectionCommentSearchPage: ...
    def collection_tag_list(
        self,
        sha256: str,
        collection: Collection,
        address: int,
    ) -> list[str]: ...
    def sample_status_delete(self, sha256: str) -> None: ...
    def search(
        self,
        query: str,
        top_k: int = 16,
        page: int = 1,
    ) -> list[QueryResult]: ...
    def nearest(
        self,
        corpora: list[str],
        vector: list[float],
        collections: list[Collection] | None = None,
        architectures: list[Architecture] | None = None,
        limit: int = 10,
    ) -> list[SearchResult]: ...


__all__ = [
    "Collection",
    "CollectionCommentRecord",
    "CollectionCommentSearchPage",
    "CollectionTagRecord",
    "CollectionTagSearchPage",
    "CommentRecord",
    "CommentSearchPage",
    "Entity",
    "LocalIndex",
    "QueryResult",
    "SampleStatusRecord",
    "SearchResult",
    "TagRecord",
    "TagSearchPage",
]
