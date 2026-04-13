from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import ida_nalt
import idautils
import idc

from binlex.indexing import Collection

from .config import build_binlex_config, build_web_client, is_meaningful_name, require_embeddings
from .disassembly import architecture_for_current_ida, disassemble_graph
from .context import resolve_block_context, resolve_function_context


@dataclass
class IndexRequest:
    corpora: list[str]
    threads: int
    dimensions: int
    index_blocks: bool


def _format_corpora(corpora: list[str]) -> str:
    return ", ".join(f"'{corpus}'" for corpus in corpora)


def _input_file_bytes() -> bytes:
    path = ida_nalt.get_input_file_path()
    if not path:
        raise RuntimeError("IDA did not provide an input file path")
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"input file not found: {file_path}")
    return file_path.read_bytes()


def _sample_sha256() -> str:
    return hashlib.sha256(_input_file_bytes()).hexdigest()


def _architecture_string() -> str:
    return str(architecture_for_current_ida())


def _meaningful_function_names() -> dict[int, str]:
    result: dict[int, str] = {}
    for address in idautils.Functions():
        name = idc.get_func_name(address)
        if is_meaningful_name(name):
            result[address] = name
    return result


def _publish_symbol(web, sha256: str, collection, architecture: str, address: int, symbol: str) -> None:
    try:
        web.add_collection_symbol(sha256, collection, architecture, address, symbol)
    except Exception:
        # Symbols are a quality-of-life enhancement for remote rename workflows.
        # Indexing should still succeed if a duplicate or race makes the symbol call fail.
        pass


def index_block(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(
        plugin_config,
        threads=request.threads,
        dimensions=request.dimensions,
    )
    require_embeddings(config, target="block")
    context = resolve_block_context(config)
    sha256 = _sample_sha256()
    architecture = _architecture_string()
    web = build_web_client(plugin_config, config)

    if not web.index_block(sha256, context.entity, corpora=request.corpora):
        raise RuntimeError("binlex-web refused block indexing request")
    if not web.commit_index():
        raise RuntimeError("binlex-web refused block index commit")

    if context.function_address is not None and is_meaningful_name(context.function_name):
        _publish_symbol(
            web,
            sha256,
            Collection.Block,
            architecture,
            context.address,
            context.function_name,
        )

    return f"indexed block {hex(context.address)} into corpora {_format_corpora(request.corpora)}"


def index_function(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(
        plugin_config,
        threads=request.threads,
        dimensions=request.dimensions,
    )
    require_embeddings(config, target="function")
    if request.index_blocks:
        require_embeddings(config, target="block")
    context = resolve_function_context(config)
    sha256 = _sample_sha256()
    architecture = _architecture_string()
    web = build_web_client(plugin_config, config)

    if request.index_blocks:
        collections = [Collection.Function, Collection.Block]
        if not web.index_graph(sha256, context.graph, collections=collections, corpora=request.corpora):
            raise RuntimeError("binlex-web refused graph indexing request")
    else:
        if not web.index_function(sha256, context.entity, corpora=request.corpora):
            raise RuntimeError("binlex-web refused function indexing request")
    if not web.commit_index():
        raise RuntimeError("binlex-web refused function index commit")

    if is_meaningful_name(context.function_name):
        _publish_symbol(
            web,
            sha256,
            Collection.Function,
            architecture,
            context.address,
            context.function_name,
        )
        if request.index_blocks:
            for block in context.entity.blocks():
                _publish_symbol(
                    web,
                    sha256,
                    Collection.Block,
                    architecture,
                    block.address(),
                    context.function_name,
                )

    return f"indexed function {hex(context.address)} into corpora {_format_corpora(request.corpora)}"


def index_functions(plugin_config, request: IndexRequest) -> str:
    config = build_binlex_config(
        plugin_config,
        threads=request.threads,
        dimensions=request.dimensions,
    )
    require_embeddings(config, target="function")
    if request.index_blocks:
        require_embeddings(config, target="block")
    graph = disassemble_graph(list(idautils.Functions()), config)
    sha256 = _sample_sha256()
    architecture = _architecture_string()
    web = build_web_client(plugin_config, config)
    collections = [Collection.Function]
    if request.index_blocks:
        collections.append(Collection.Block)

    if not web.index_graph(sha256, graph, collections=collections, corpora=request.corpora):
        raise RuntimeError("binlex-web refused graph indexing request")
    if not web.commit_index():
        raise RuntimeError("binlex-web refused graph index commit")

    for function_address, function_name in _meaningful_function_names().items():
        _publish_symbol(
            web,
            sha256,
            Collection.Function,
            architecture,
            function_address,
            function_name,
        )
        if not request.index_blocks:
            continue
        function = next(
            (item for item in graph.functions() if item.address() == function_address),
            None,
        )
        if function is None:
            continue
        for block in function.blocks():
            _publish_symbol(
                web,
                sha256,
                Collection.Block,
                architecture,
                block.address(),
                function_name,
            )

    return f"indexed {len(list(idautils.Functions()))} functions into corpora {_format_corpora(request.corpora)}"
