"""Local binlex index wrapper."""

from binlex_bindings.binlex.index.local import Collection as _CollectionBinding
from binlex_bindings.binlex.index.local import LocalIndex as _LocalIndexBinding

from binlex.core.architecture import _coerce_architecture
from binlex.controlflow import Block, Function, Graph, Instruction


class Collection:
    Instruction = _CollectionBinding.Instruction
    Block = _CollectionBinding.Block
    Function = _CollectionBinding.Function


Entity = Collection

class SearchResult:
    def __init__(self, binding):
        self._inner = binding

    def corpus(self):
        return self._inner.corpus()

    def score(self):
        return self._inner.score()

    def sha256(self):
        return self._inner.sha256()

    def address(self):
        return self._inner.address()

    def object_id(self):
        return self._inner.object_id()

    def symbol(self):
        return self._inner.symbol()

    def attributes(self):
        return self._inner.attributes()

    def architecture(self):
        return self._inner.architecture()

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


class LocalIndex:
    def __init__(self, config, directory=None, dimensions=None):
        self._inner = _LocalIndexBinding(config, directory, dimensions)

    def put(self, data):
        return self._inner.put(data)

    def get(self, sha256):
        return self._inner.get(sha256)

    def _resolve_corpora(self, corpus=None, corpora=None):
        if corpus is not None and corpora is not None:
            raise ValueError("provide either corpus or corpora, not both")
        if corpora is not None:
            return list(corpora), True
        if corpus is not None:
            return [corpus], False
        raise ValueError("either corpus or corpora must be provided")

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
        corpus = kwargs.pop("corpus", None)
        corpora = kwargs.pop("corpora", None)
        if kwargs:
            raise TypeError(f"unexpected keyword arguments: {', '.join(kwargs)}")

        if len(args) == 3:
            corpus = args[0] if corpus is None and corpora is None else corpus
            sha256 = args[1]
            graph = args[2]
        elif len(args) == 2:
            sha256, graph = args
        elif len(args) == 0 and sha256 is not None and graph is not None:
            pass
        else:
            raise TypeError(
                "graph expects either (corpus, sha256, graph) or (sha256, graph)"
            )

        resolved_corpora, is_many = self._resolve_corpora(corpus=corpus, corpora=corpora)
        if is_many:
            return self._inner.graph_many(
                resolved_corpora,
                sha256,
                graph._inner,
                attributes,
                selector,
                collections,
            )
        return self._inner.graph(
            resolved_corpora[0],
            sha256,
            graph._inner,
            attributes,
            selector,
            collections,
        )

    def instruction(self, *args, **kwargs):
        return self._index_collection(Collection.Instruction, self._inner.instruction, *args, **kwargs)

    def block(self, *args, **kwargs):
        return self._index_collection(Collection.Block, self._inner.block, *args, **kwargs)

    def function(self, *args, **kwargs):
        return self._index_collection(Collection.Function, self._inner.function, *args, **kwargs)

    def _index_collection(self, expected_collection, binding, *args, **kwargs):
        collection = kwargs.pop("collection", expected_collection)
        architecture = kwargs.pop("architecture", None)
        vector = kwargs.pop("vector", None)
        sha256 = kwargs.pop("sha256", None)
        address = kwargs.pop("address", None)
        attributes = kwargs.pop("attributes", None)
        corpus = kwargs.pop("corpus", None)
        corpora = kwargs.pop("corpora", None)
        if kwargs:
            raise TypeError(f"unexpected keyword arguments: {', '.join(kwargs)}")

        if collection != expected_collection:
            raise ValueError("collection does not match the selected method")

        if len(args) == 5:
            architecture, vector, sha256, address, attributes = args
        elif len(args) == 4:
            architecture, vector, sha256, address = args
        elif (
            len(args) == 0
            and architecture is not None
            and vector is not None
            and sha256 is not None
            and address is not None
        ):
            pass
        else:
            raise TypeError(
                "method expects (architecture, vector, sha256, address[, attributes])"
            )

        resolved_corpora, _ = self._resolve_corpora(corpus=corpus, corpora=corpora)
        architecture = _coerce_architecture(architecture)
        return binding(
            resolved_corpora,
            architecture,
            vector,
            sha256,
            address,
            attributes,
        )

    def vector(self, *args, **kwargs):
        collection = kwargs.pop("collection", None)
        architecture = kwargs.pop("architecture", None)
        vector = kwargs.pop("vector", None)
        sha256 = kwargs.pop("sha256", None)
        address = kwargs.pop("address", None)
        corpus = kwargs.pop("corpus", None)
        corpora = kwargs.pop("corpora", None)
        if kwargs:
            raise TypeError(f"unexpected keyword arguments: {', '.join(kwargs)}")

        if len(args) == 6:
            corpus = args[0] if corpus is None and corpora is None else corpus
            collection, architecture, vector, sha256, address = args[1:]
        elif len(args) == 5:
            collection, architecture, vector, sha256, address = args
        elif (
            len(args) == 0
            and collection is not None
            and architecture is not None
            and vector is not None
            and sha256 is not None
            and address is not None
        ):
            pass
        else:
            raise TypeError(
                "vector expects either (corpus, collection, architecture, vector, sha256, address) "
                "or (collection, architecture, vector, sha256, address)"
            )

        resolved_corpora, is_many = self._resolve_corpora(corpus=corpus, corpora=corpora)
        architecture = _coerce_architecture(architecture)
        if is_many:
            return self._inner.vector_many(
                resolved_corpora,
                collection,
                architecture,
                vector,
                sha256,
                address,
            )
        return self._inner.vector(
            resolved_corpora[0],
            collection,
            architecture,
            vector,
            sha256,
            address,
        )

    def commit(self):
        return self._inner.commit()

    def clear(self):
        return self._inner.clear()

    def load(self, corpus, sha256):
        return Graph._from_binding(self._inner.load(corpus, sha256))

    def corpora(self):
        return self._inner.corpora()

    def delete(self, corpus, sha256):
        return self._inner.delete(corpus, sha256)

    def delete_corpus(self, corpus):
        return self._inner.delete_corpus(corpus)

    def search(
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
            for result in self._inner.search(
                corpora,
                vector,
                collections,
                [_coerce_architecture(architecture) for architecture in architectures],
                limit,
            )
        ]


__all__ = ["Collection", "Entity", "LocalIndex", "SearchResult"]
