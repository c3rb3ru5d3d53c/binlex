from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import ida_kernwin
import ida_nalt
import idautils
import idc

from binlex.index import Collection, LocalIndex

from .config import build_binlex_config, effective_index_root, is_meaningful_name, require_embeddings
from .context import resolve_block_context, resolve_function_context
from .disassembly import disassemble_graph
from .metadata import MetadataStore


@dataclass
class IndexRequest:
    corpora: list[str]
    threads: int
    dimensions: int
    index_blocks: bool
    include_names: bool


def _format_corpora(corpora: list[str]) -> str:
    return ", ".join(f"'{corpus}'" for corpus in corpora)


def _store_graph_for_corpora(store, corpora: list[str], sha256: str, graph, collections: list) -> None:
    for corpus in corpora:
        try:
            store.delete(corpus, sha256)
        except Exception:
            pass
        store.graph(
            corpus=corpus,
            sha256=sha256,
            graph=graph,
            attributes=[],
            selector="processors.embeddings.vector",
            collections=collections,
        )


def _record_names_for_corpora(metadata: MetadataStore, corpora: list[str], collection: str, sha256: str, items) -> None:
    for corpus in corpora:
        if isinstance(items, dict):
            metadata.record_many(
                corpus=corpus,
                collection=collection,
                sha256=sha256,
                items=items,
            )
        else:
            address, names = items
            metadata.record_names(
                corpus=corpus,
                collection=collection,
                sha256=sha256,
                address=address,
                names=names,
            )


def _input_file_bytes() -> bytes:
    path = ida_nalt.get_input_file_path()
    if not path:
        raise RuntimeError("IDA did not provide an input file path")
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"input file not found: {file_path}")
    return file_path.read_bytes()


def _function_names() -> dict[int, list[str]]:
    result: dict[int, list[str]] = {}
    for address in idautils.Functions():
        name = idc.get_func_name(address)
        if is_meaningful_name(name):
            result[address] = [name]
    return result


def index_block(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(plugin_config, threads=request.threads, dimensions=request.dimensions)
    require_embeddings(config, target="block")
    context = resolve_block_context(config)
    index_root = effective_index_root(plugin_config)
    store = LocalIndex(config, directory=index_root)
    sha256 = store.put(_input_file_bytes())
    _store_graph_for_corpora(store, request.corpora, sha256, context.graph, [Collection.Block])
    store.commit()

    if request.include_names and context.function_address is not None and is_meaningful_name(context.function_name):
        _record_names_for_corpora(
            MetadataStore(index_root),
            request.corpora,
            "block",
            sha256,
            (context.address, [context.function_name]),
        )

    return f"indexed block {hex(context.address)} into corpora {_format_corpora(request.corpora)}"


def index_function(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(plugin_config, threads=request.threads, dimensions=request.dimensions)
    require_embeddings(config, target="function")
    if request.index_blocks:
        require_embeddings(config, target="block")
    context = resolve_function_context(config)
    index_root = effective_index_root(plugin_config)
    store = LocalIndex(config, directory=index_root)
    sha256 = store.put(_input_file_bytes())
    collections = [Collection.Function]
    if request.index_blocks:
        collections.append(Collection.Block)
    _store_graph_for_corpora(store, request.corpora, sha256, context.graph, collections)
    store.commit()

    if request.include_names and is_meaningful_name(context.function_name):
        metadata = MetadataStore(index_root)
        _record_names_for_corpora(
            metadata,
            request.corpora,
            "function",
            sha256,
            {context.address: [context.function_name]},
        )
        if request.index_blocks:
            block_items = {}
            for block in context.entity.blocks():
                block_items[block.address()] = [context.function_name]
            _record_names_for_corpora(
                metadata,
                request.corpora,
                "block",
                sha256,
                block_items,
            )

    return f"indexed function {hex(context.address)} into corpora {_format_corpora(request.corpora)}"


def index_functions(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(plugin_config, threads=request.threads, dimensions=request.dimensions)
    require_embeddings(config, target="function")
    if request.index_blocks:
        require_embeddings(config, target="block")
    graph = disassemble_graph(list(idautils.Functions()), config)
    index_root = effective_index_root(plugin_config)
    store = LocalIndex(config, directory=index_root)
    sha256 = store.put(_input_file_bytes())
    collections = [Collection.Function]
    if request.index_blocks:
        collections.append(Collection.Block)
    _store_graph_for_corpora(store, request.corpora, sha256, graph, collections)
    store.commit()

    if request.include_names:
        metadata = MetadataStore(index_root)
        function_items = _function_names()
        _record_names_for_corpora(
            metadata,
            request.corpora,
            "function",
            sha256,
            function_items,
        )
        if request.index_blocks:
            block_items: dict[int, list[str]] = {}
            for function_address, names in function_items.items():
                function = next((item for item in graph.functions() if item.address() == function_address), None)
                if function is None:
                    continue
                for block in function.blocks():
                    block_items[block.address()] = names
            _record_names_for_corpora(
                metadata,
                request.corpora,
                "block",
                sha256,
                block_items,
            )

    return f"indexed {len(list(idautils.Functions()))} functions into corpora {_format_corpora(request.corpora)}"
