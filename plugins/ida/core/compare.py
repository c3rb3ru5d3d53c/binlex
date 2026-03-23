from __future__ import annotations

from dataclasses import dataclass

import ida_kernwin
import idaapi
import idc

from binlex.disassemblers.ida import IDA
from binlex.index import Collection, LocalIndex

from .config import build_binlex_config, is_meaningful_name
from .context import resolve_block_context, resolve_function_context, vector_for_context
from .metadata import MetadataStore


@dataclass
class CompareRequest:
    corpora: list[str]
    limit: int


def _display_names(metadata: MetadataStore, *, corpus: str, collection: str, sha256: str, address: int) -> list[str]:
    names = metadata.names_for(corpus=corpus, collection=collection, sha256=sha256, address=address)
    return names or [""]


def _local_function_name(address: int | None) -> str:
    if address is None:
        return ""
    return idc.get_func_name(address) or ""


def _row(
    *,
    local_address: int,
    local_name: str,
    local_function_address: int | None,
    score: float,
    match_address: int,
    match_name: str,
    sha256: str,
    corpus: str,
    collection: str,
) -> dict:
    return {
        "local_address": local_address,
        "local_name": local_name,
        "local_function_address": local_function_address or local_address,
        "score": score,
        "match_address": match_address,
        "match_name": match_name,
        "sha256": sha256,
        "corpus": corpus,
        "collection": collection,
    }


def compare_block(plugin_config, request: CompareRequest) -> list[dict]:
    config = build_binlex_config(plugin_config)
    context = resolve_block_context(config)
    vector = vector_for_context(context)
    if not vector:
        raise RuntimeError("embeddings vector is not available for this block or selection")

    store = LocalIndex(config, directory=plugin_config.index_root)
    metadata = MetadataStore(plugin_config.index_root)
    rows: list[dict] = []
    for hit in store.search(
        corpora=request.corpora,
        vector=vector,
        collections=[Collection.Block],
        limit=request.limit,
    ):
        for match_name in _display_names(
            metadata,
            corpus=hit.corpus(),
            collection="block",
            sha256=hit.sha256(),
            address=hit.address(),
        ):
            rows.append(
                _row(
                    local_address=context.address,
                    local_name=context.function_name,
                    local_function_address=context.function_address,
                    score=hit.score(),
                    match_address=hit.address(),
                    match_name=match_name,
                    sha256=hit.sha256(),
                    corpus=hit.corpus(),
                    collection="block",
                )
            )
    return rows


def compare_function(plugin_config, request: CompareRequest) -> list[dict]:
    config = build_binlex_config(plugin_config)
    context = resolve_function_context(config)
    vector = vector_for_context(context)
    if not vector:
        raise RuntimeError("embeddings vector is not available for this function")

    store = LocalIndex(config, directory=plugin_config.index_root)
    metadata = MetadataStore(plugin_config.index_root)
    rows: list[dict] = []
    for hit in store.search(
        corpora=request.corpora,
        vector=vector,
        collections=[Collection.Function],
        limit=request.limit,
    ):
        for match_name in _display_names(
            metadata,
            corpus=hit.corpus(),
            collection="function",
            sha256=hit.sha256(),
            address=hit.address(),
        ):
            rows.append(
                _row(
                    local_address=context.address,
                    local_name=context.function_name,
                    local_function_address=context.address,
                    score=hit.score(),
                    match_address=hit.address(),
                    match_name=match_name,
                    sha256=hit.sha256(),
                    corpus=hit.corpus(),
                    collection="function",
                )
            )
    return rows


def compare_functions(plugin_config, request: CompareRequest) -> list[dict]:
    config = build_binlex_config(plugin_config)
    ida = IDA()
    graph = ida.disassemble_controlflow(config)
    store = LocalIndex(config, directory=plugin_config.index_root)
    metadata = MetadataStore(plugin_config.index_root)
    rows: list[dict] = []

    for function in graph.functions():
        processor = function.processor("embeddings")
        if not isinstance(processor, dict):
            continue
        vector = processor.get("vector")
        if not isinstance(vector, list) or not vector:
            continue
        local_name = _local_function_name(function.address())
        for hit in store.search(
            corpora=request.corpora,
            vector=vector,
            collections=[Collection.Function],
            limit=request.limit,
        ):
            for match_name in _display_names(
                metadata,
                corpus=hit.corpus(),
                collection="function",
                sha256=hit.sha256(),
                address=hit.address(),
            ):
                rows.append(
                    _row(
                        local_address=function.address(),
                        local_name=local_name,
                        local_function_address=function.address(),
                        score=hit.score(),
                        match_address=hit.address(),
                        match_name=match_name,
                        sha256=hit.sha256(),
                        corpus=hit.corpus(),
                        collection="function",
                    )
                )
    return rows


def apply_match_rows(rows: list[dict]) -> tuple[int, list[str]]:
    grouped: dict[int, set[str]] = {}
    first_rows: dict[int, dict] = {}
    conflicts: list[str] = []

    for row in rows:
        match_name = row.get("match_name", "").strip()
        if not match_name:
            continue
        function_address = int(row["local_function_address"])
        grouped.setdefault(function_address, set()).add(match_name)
        first_rows.setdefault(function_address, row)

    applied = 0
    for function_address, names in grouped.items():
        if len(names) != 1:
            conflicts.append(f"{hex(function_address)} has conflicting match names")
            continue
        row = first_rows[function_address]
        current_name = idc.get_func_name(function_address) or ""
        new_name = next(iter(names))
        if is_meaningful_name(current_name) and current_name != new_name:
            result = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_NO,
                f"Overwrite existing function name '{current_name}' at {hex(function_address)} with '{new_name}'?",
            )
            if result != ida_kernwin.ASKBTN_YES:
                conflicts.append(f"skipped {hex(function_address)}")
                continue
        idaapi.set_name(function_address, new_name, idaapi.SN_FORCE)
        comment = (
            "Binlex match\n"
            f"name: {new_name}\n"
            f"score: {row['score']:.6f}\n"
            f"sha256: {row['sha256']}\n"
            f"corpus: {row['corpus']}\n"
            f"match_address: {hex(int(row['match_address']))}\n"
        )
        function = idaapi.get_func(function_address)
        if function is not None:
            idaapi.set_func_cmt(function, comment, True)
        applied += 1
    return applied, conflicts
