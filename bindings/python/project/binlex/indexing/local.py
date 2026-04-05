"""Local binlex index wrapper."""

from binlex.databases.localdb import (
    CollectionCommentRecord,
    CollectionTagRecord,
    SampleStatusRecord,
)
from binlex_bindings.binlex.indexing.local import Collection as _CollectionBinding
from binlex_bindings.binlex.indexing.local import (
    CollectionCommentSearchPage as _CollectionCommentSearchPageBinding,
)
from binlex_bindings.binlex.indexing.local import CommentRecord as _CommentRecordBinding
from binlex_bindings.binlex.indexing.local import CommentSearchPage as _CommentSearchPageBinding
from binlex_bindings.binlex.indexing.local import (
    CollectionTagSearchPage as _CollectionTagSearchPageBinding,
)
from binlex_bindings.binlex.indexing.local import LocalIndex as _LocalIndexBinding
from binlex_bindings.binlex.indexing.local import QueryResult as _QueryResultBinding
from binlex_bindings.binlex.indexing.local import TagRecord as _TagRecordBinding
from binlex_bindings.binlex.indexing.local import TagSearchPage as _TagSearchPageBinding

from binlex.core.architecture import _coerce_architecture
from binlex.controlflow import Block, Function, Graph, Instruction


class Collection:
    Instruction = _CollectionBinding.Instruction
    Block = _CollectionBinding.Block
    Function = _CollectionBinding.Function


Entity = Collection


TagRecord = _TagRecordBinding
CommentRecord = _CommentRecordBinding
TagSearchPage = _TagSearchPageBinding
CollectionCommentSearchPage = _CollectionCommentSearchPageBinding
CollectionTagSearchPage = _CollectionTagSearchPageBinding
CommentSearchPage = _CommentSearchPageBinding

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

    def object_id(self):
        return self._inner.object_id()

    def symbol(self):
        return self._inner.symbol()

    def attributes(self):
        return self._inner.attributes()

    def architecture(self):
        return self._inner.architecture()

    def username(self):
        return self._inner.username()

    def embedding(self):
        return self._inner.embedding()

    def embeddings(self):
        return self._inner.embeddings()

    def collection(self):
        return self._inner.collection()

    def graph(self):
        return Graph._from_binding(self._inner.graph())

    def function(self):
        result = self._inner.function()
        return None if result is None else Function._from_binding(result)

    def block(self):
        result = self._inner.block()
        return None if result is None else Block._from_binding(result)

    def instruction(self):
        result = self._inner.instruction()
        return None if result is None else Instruction._from_binding(result)


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


class LocalIndex:
    def __init__(self, config, directory=None, dimensions=None):
        self._inner = _LocalIndexBinding(config, directory, dimensions)

    def sample_put(self, data):
        return self._inner.sample_put(data)

    def sample_get(self, sha256):
        return self._inner.sample_get(sha256)

    def _resolve_corpora(self, corpora=None):
        if corpora is None:
            return ["default"]
        return list(corpora)

    def _resolve_collections(self, collections=None, default=None):
        if collections is not None:
            return list(collections)
        return list(default or ())

    def graph(self, *args, **kwargs):
        sha256 = kwargs.pop("sha256", None)
        graph = kwargs.pop("graph", None)
        attributes = kwargs.pop("attributes", None)
        selector = kwargs.pop("selector", None)
        collections = self._resolve_collections(
            collections=kwargs.pop("collections", None),
            default=(Collection.Block, Collection.Function),
        )
        corpora = kwargs.pop("corpora", None)
        if kwargs:
            raise TypeError(f"unexpected keyword arguments: {', '.join(kwargs)}")

        if len(args) == 2:
            sha256, graph = args
        elif len(args) == 0 and sha256 is not None and graph is not None:
            pass
        else:
            raise TypeError("graph expects (sha256, graph)")

        return self._inner.graph(
            sha256,
            graph._inner,
            attributes,
            selector,
            collections,
            self._resolve_corpora(corpora=corpora),
        )

    def instruction(self, *args, **kwargs):
        return self._index_collection(Collection.Instruction, self._inner.instruction, *args, **kwargs)

    def block(self, *args, **kwargs):
        return self._index_collection(Collection.Block, self._inner.block, *args, **kwargs)

    def function(self, *args, **kwargs):
        return self._index_collection(Collection.Function, self._inner.function, *args, **kwargs)

    def _index_collection(self, expected_collection, binding, *args, **kwargs):
        collection = kwargs.pop("collection", expected_collection)
        entity = kwargs.pop("entity", None)
        vector = kwargs.pop("vector", None)
        sha256 = kwargs.pop("sha256", None)
        attributes = kwargs.pop("attributes", None)
        corpora = kwargs.pop("corpora", None)
        if kwargs:
            raise TypeError(f"unexpected keyword arguments: {', '.join(kwargs)}")

        if collection != expected_collection:
            raise ValueError("collection does not match the selected method")

        if len(args) == 4:
            entity, vector, sha256, attributes = args
        elif len(args) == 3:
            entity, vector, sha256 = args
        elif (
            len(args) == 0
            and entity is not None
            and vector is not None
            and sha256 is not None
        ):
            pass
        else:
            raise TypeError(
                "method expects (entity, vector, sha256[, attributes])"
            )

        return binding(
            entity._inner,
            vector,
            sha256,
            attributes,
            self._resolve_corpora(corpora=corpora),
        )

    def commit(self):
        return self._inner.commit()

    def clear(self):
        return self._inner.clear()

    def sample_load(self, corpus, sha256):
        return Graph._from_binding(self._inner.sample_load(corpus, sha256))

    def corpus_list(self):
        return self._inner.corpus_list()

    def sample_delete(self, corpus, sha256):
        return self._inner.sample_delete(corpus, sha256)

    def corpus_delete(self, corpus):
        return self._inner.corpus_delete(corpus)

    def symbol_add(self, sha256, address, name):
        return self._inner.symbol_add(sha256, address, name)

    def symbol_remove(self, sha256, address, name):
        return self._inner.symbol_remove(sha256, address, name)

    def symbol_replace(self, sha256, address, name):
        return self._inner.symbol_replace(sha256, address, name)

    def corpus_add(self, sha256, corpus):
        return self._inner.corpus_add(sha256, corpus)

    def corpus_replace(self, sha256, corpus):
        return self._inner.corpus_replace(sha256, corpus)

    def corpus_rename(self, old_name, new_name):
        return self._inner.corpus_rename(old_name, new_name)

    def sample_tag_add(self, sha256, tag):
        return self._inner.sample_tag_add(sha256, tag)

    def sample_tag_remove(self, sha256, tag):
        return self._inner.sample_tag_remove(sha256, tag)

    def sample_tag_replace(self, sha256, tags):
        return self._inner.sample_tag_replace(sha256, list(tags))

    def sample_tag_search(self, query, page=1, page_size=50):
        return self._inner.sample_tag_search(query, page, page_size)

    def sample_tag_list(self, sha256):
        return self._inner.sample_tag_list(sha256)

    def sample_comment_add(self, sha256, comment, timestamp=None):
        return self._inner.sample_comment_add(sha256, comment, timestamp)

    def sample_comment_remove(self, sha256, comment):
        return self._inner.sample_comment_remove(sha256, comment)

    def sample_comment_replace(self, sha256, comments, timestamp=None):
        return self._inner.sample_comment_replace(sha256, list(comments), timestamp)

    def sample_comment_search(self, query, page=1, page_size=50):
        return self._inner.sample_comment_search(query, page, page_size)

    def sample_status_get(self, sha256):
        return self._inner.sample_status_get(sha256)

    def sample_status_set(
        self,
        sha256,
        status,
        timestamp=None,
        id=None,
        error_message=None,
    ):
        return self._inner.sample_status_set(
            sha256,
            status,
            timestamp,
            id,
            error_message,
        )

    def collection_tag_add(self, sha256, collection, address, tag):
        return self._inner.collection_tag_add(sha256, collection, address, tag)

    def collection_tag_remove(self, sha256, collection, address, tag):
        return self._inner.collection_tag_remove(sha256, collection, address, tag)

    def collection_tag_replace(self, sha256, collection, address, tags):
        return self._inner.collection_tag_replace(
            sha256,
            collection,
            address,
            list(tags),
        )

    def collection_comment_add(
        self,
        sha256,
        collection,
        address,
        comment,
        timestamp=None,
    ):
        return self._inner.collection_comment_add(
            sha256,
            collection,
            address,
            comment,
            timestamp,
        )

    def collection_comment_remove(self, sha256, collection, address, comment):
        return self._inner.collection_comment_remove(
            sha256,
            collection,
            address,
            comment,
        )

    def collection_comment_replace(
        self,
        sha256,
        collection,
        address,
        comments,
        timestamp=None,
    ):
        return self._inner.collection_comment_replace(
            sha256,
            collection,
            address,
            list(comments),
            timestamp,
        )

    def collection_tag_search(self, query, collection=None, page=1, page_size=50):
        return self._inner.collection_tag_search(query, collection, page, page_size)

    def collection_comment_search(self, query, collection=None, page=1, page_size=50):
        return self._inner.collection_comment_search(query, collection, page, page_size)

    def collection_tag_list(self, sha256, collection, address):
        return self._inner.collection_tag_list(sha256, collection, address)

    def sample_status_delete(self, sha256):
        return self._inner.sample_status_delete(sha256)

    def search(
        self,
        query,
        top_k=16,
        page=1,
    ):
        return [QueryResult(item) for item in self._inner.search(query, top_k, page)]

    def nearest(
        self,
        corpora,
        vector,
        collections=None,
        architectures=None,
        limit=10,
    ):
        corpora = list(corpora)
        collections = self._resolve_collections(
            collections=collections,
            default=(Collection.Block, Collection.Function),
        )
        architectures = [] if architectures is None else list(architectures)
        return [
            SearchResult(result)
            for result in self._inner.nearest(
                corpora,
                vector,
                collections,
                [_coerce_architecture(architecture) for architecture in architectures],
                limit,
            )
        ]


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
