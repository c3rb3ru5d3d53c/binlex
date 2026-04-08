from __future__ import annotations

from binlex.config import Config
from binlex.controlflow import Graph
from binlex.core.architecture import Architecture, _coerce_architecture
from binlex.core.magic import Magic, _coerce_magic
from binlex.indexing import Collection
from binlex_bindings.binlex.clients import Server as _ServerBinding
from binlex_bindings.binlex.clients import QueryResult as _QueryResultBinding
from binlex_bindings.binlex.clients import SearchResult as _SearchResultBinding
from binlex_bindings.binlex.clients import Web as _WebBinding


class SearchResult:
    def __init__(self, binding):
        self._inner = binding

    def corpus(self):
        return self._inner.corpus()

    def corpora(self):
        return self._inner.corpora()

    def score(self):
        return self._inner.score()

    def sha256(self):
        return self._inner.sha256()

    def address(self):
        return self._inner.address()

    def size(self):
        return self._inner.size()

    def timestamp(self):
        return self._inner.timestamp()

    def symbol(self):
        return self._inner.symbol()

    def architecture(self):
        return self._inner.architecture()

    def embedding(self):
        return self._inner.embedding()

    def embeddings(self):
        return self._inner.embeddings()

    def collection(self):
        return self._inner.collection()

    def vector(self):
        return self._inner.vector()

    def json(self):
        return self._inner.json()


class QueryResult:
    def __init__(self, binding):
        self._inner = binding

    def lhs(self):
        result = self._inner.lhs()
        return None if result is None else SearchResult(result)

    def rhs(self):
        result = self._inner.rhs()
        return None if result is None else SearchResult(result)

    def score(self):
        return self._inner.score()


class Server:
    def __init__(
        self,
        config: Config,
        url: str | None = None,
        verify: bool | None = None,
        compression: bool | None = None,
    ) -> None:
        self._inner = _ServerBinding(config, url, verify, compression)

    def url(self):
        return self._inner.url()

    def verify(self):
        return self._inner.verify()

    def compression(self):
        return self._inner.compression()

    def health(self):
        return self._inner.health()

    def analyze_file(
        self,
        path: str,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
    ) -> Graph:
        native_magic = None if magic is None else str(_coerce_magic(magic))
        native_architecture = (
            None if architecture is None else str(_coerce_architecture(architecture))
        )
        return Graph._from_binding(
            self._inner.analyze_file(path, native_magic, native_architecture)
        )

    def analyze_bytes(
        self,
        data: bytes,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
    ) -> Graph:
        native_magic = None if magic is None else str(_coerce_magic(magic))
        native_architecture = (
            None if architecture is None else str(_coerce_architecture(architecture))
        )
        return Graph._from_binding(
            self._inner.analyze_bytes(data, native_magic, native_architecture)
        )


class Web:
    def __init__(
        self,
        config: Config,
        url: str | None = None,
        verify: bool | None = None,
        api_key: str | None = None,
    ) -> None:
        self._inner = _WebBinding(config, url, verify, api_key)

    def url(self):
        return self._inner.url()

    def verify(self):
        return self._inner.verify()

    def api_key(self):
        return self._inner.api_key()

    def set_api_key(self, api_key: str | None) -> None:
        self._inner.set_api_key(api_key)

    def index_graph(
        self,
        sha256: str,
        graph: Graph,
        collections: list[Collection] | None = None,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_graph(sha256, graph, collections, corpora)

    def index_function(
        self,
        sha256: str,
        function,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_function(sha256, function, corpora)

    def index_block(
        self,
        sha256: str,
        block,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_block(sha256, block, corpora)

    def index_instruction(
        self,
        sha256: str,
        instruction,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_instruction(sha256, instruction, corpora)

    def commit_index(self) -> bool:
        return self._inner.commit_index()

    def clear_index(self) -> bool:
        return self._inner.clear_index()

    def collection_tags(
        self,
        sha256: str,
        collection: Collection,
        address: int,
    ) -> list[str]:
        return self._inner.collection_tags(sha256, collection, address)

    def add_collection_tag(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tag: str,
    ) -> bool:
        return self._inner.add_collection_tag(sha256, collection, address, tag)

    def remove_collection_tag(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tag: str,
    ) -> bool:
        return self._inner.remove_collection_tag(sha256, collection, address, tag)

    def replace_collection_tags(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tags: list[str],
    ) -> bool:
        return self._inner.replace_collection_tags(sha256, collection, address, tags)

    def search(self, query: str, top_k: int = 10, page: int = 1):
        return [QueryResult(item) for item in self._inner.search(query, top_k, page)]


__all__ = ["QueryResult", "SearchResult", "Server", "Web"]
