from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import ida_kernwin
import ida_nalt
import idautils
import idc

from binlex.index import Collection, LocalIndex

from .config import build_binlex_config, is_meaningful_name
from .context import resolve_block_context, resolve_function_context
from .metadata import MetadataStore


@dataclass
class IndexRequest:
    corpus: str
    threads: int
    dimensions: int
    index_blocks: bool
    include_names: bool


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
    context = resolve_block_context(config)
    store = LocalIndex(config, directory=plugin_config.index_root)
    sha256 = store.put(_input_file_bytes())
    store.graph(
        corpus=request.corpus,
        sha256=sha256,
        graph=context.graph,
        attributes=[],
        selector="processors.embeddings.vector",
        collections=[Collection.Block],
    )
    store.commit()

    if request.include_names and context.function_address is not None and is_meaningful_name(context.function_name):
        MetadataStore(plugin_config.index_root).record_names(
            corpus=request.corpus,
            collection="block",
            sha256=sha256,
            address=context.address,
            names=[context.function_name],
        )

    return f"indexed block {hex(context.address)} into corpus '{request.corpus}'"


def index_function(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(plugin_config, threads=request.threads, dimensions=request.dimensions)
    context = resolve_function_context(config)
    store = LocalIndex(config, directory=plugin_config.index_root)
    sha256 = store.put(_input_file_bytes())
    collections = [Collection.Function]
    if request.index_blocks:
        collections.append(Collection.Block)
    store.graph(
        corpus=request.corpus,
        sha256=sha256,
        graph=context.graph,
        attributes=[],
        selector="processors.embeddings.vector",
        collections=collections,
    )
    store.commit()

    if request.include_names and is_meaningful_name(context.function_name):
        metadata = MetadataStore(plugin_config.index_root)
        metadata.record_many(
            corpus=request.corpus,
            collection="function",
            sha256=sha256,
            items={context.address: [context.function_name]},
        )
        if request.index_blocks:
            block_items = {}
            for block in context.entity.blocks():
                block_items[block.address()] = [context.function_name]
            metadata.record_many(
                corpus=request.corpus,
                collection="block",
                sha256=sha256,
                items=block_items,
            )

    return f"indexed function {hex(context.address)} into corpus '{request.corpus}'"


def index_functions(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(plugin_config, threads=request.threads, dimensions=request.dimensions)
    from binlex.disassemblers.ida import IDA

    ida = IDA()
    graph = ida.disassemble_controlflow(config)
    store = LocalIndex(config, directory=plugin_config.index_root)
    sha256 = store.put(_input_file_bytes())
    collections = [Collection.Function]
    if request.index_blocks:
        collections.append(Collection.Block)
    store.graph(
        corpus=request.corpus,
        sha256=sha256,
        graph=graph,
        attributes=[],
        selector="processors.embeddings.vector",
        collections=collections,
    )
    store.commit()

    if request.include_names:
        metadata = MetadataStore(plugin_config.index_root)
        function_items = _function_names()
        metadata.record_many(
            corpus=request.corpus,
            collection="function",
            sha256=sha256,
            items=function_items,
        )
        if request.index_blocks:
            block_items: dict[int, list[str]] = {}
            for function_address, names in function_items.items():
                function = ida.function(function_address)
                if function is None:
                    continue
                for block in function.blocks():
                    block_items[block.address()] = names
            metadata.record_many(
                corpus=request.corpus,
                collection="block",
                sha256=sha256,
                items=block_items,
            )

    return f"indexed {len(list(idautils.Functions()))} functions into corpus '{request.corpus}'"
