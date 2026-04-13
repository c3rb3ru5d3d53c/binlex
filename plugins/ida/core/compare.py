from __future__ import annotations

import json
from dataclasses import dataclass

import ida_kernwin
import idaapi
import idc

from binlex.indexing import Collection

from .config import build_binlex_config, build_web_client, is_meaningful_name, require_embeddings
from .context import resolve_block_context, resolve_function_context, vector_for_context
from .disassembly import architecture_for_current_ida


@dataclass
class CompareRequest:
    corpora: list[str]
    limit: int


def _architecture_string() -> str:
    return str(architecture_for_current_ida())


def _query_for_vector(vector: list[float], *, corpus: str, collection: Collection, architecture: str) -> str:
    vector_json = json.dumps(vector, separators=(",", ":"))
    return (
        f"vector:{vector_json} | "
        f"collection:{collection.as_str()} | "
        f"corpus:{corpus} | "
        f"architecture:{architecture}"
    )


def _symbol_names_for_hit(web, hit, *, architecture: str) -> list[str]:
    symbol = hit.symbol()
    if symbol:
        return [symbol]

    try:
        payload = web.collection_symbols(
            hit.sha256(),
            hit.collection(),
            architecture,
            hit.address(),
        )
    except Exception:
        return [""]

    symbols = payload.get("symbols", [])
    names = []
    for item in symbols:
        name = str(item.get("name", "")).strip()
        if name:
            names.append(name)
    return names or [""]


def _dedupe_rows(rows: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        key = (
            int(row["local_address"]),
            int(row["local_function_address"]),
            int(row["match_address"]),
            str(row["match_name"]),
            str(row["sha256"]),
            str(row["corpus"]),
            str(row["collection"]),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


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


def _search_rows(
    *,
    plugin_config,
    vector: list[float],
    collection: Collection,
    local_address: int,
    local_name: str,
    local_function_address: int | None,
    corpora: list[str],
    limit: int,
) -> list[dict]:
    architecture = _architecture_string()
    web = build_web_client(plugin_config)
    rows: list[dict] = []

    for corpus in corpora:
        query = _query_for_vector(
            vector,
            corpus=corpus,
            collection=collection,
            architecture=architecture,
        )
        for item in web.search(query, top_k=limit, page=1):
            hit = item.lhs() or item.rhs()
            if hit is None:
                continue
            for match_name in _symbol_names_for_hit(web, hit, architecture=architecture):
                rows.append(
                    _row(
                        local_address=local_address,
                        local_name=local_name,
                        local_function_address=local_function_address,
                        score=item.score(),
                        match_address=hit.address(),
                        match_name=match_name,
                        sha256=hit.sha256(),
                        corpus=hit.corpus(),
                        collection=hit.collection().as_str(),
                    )
                )
    return _dedupe_rows(rows)


def compare_block(plugin_config, request: CompareRequest) -> list[dict]:
    config = build_binlex_config(plugin_config)
    require_embeddings(config, target="block")
    context = resolve_block_context(config)
    vector = vector_for_context(context)
    if not vector:
        raise RuntimeError("embeddings vector is not available for this block or selection")

    return _search_rows(
        plugin_config=plugin_config,
        vector=vector,
        collection=Collection.Block,
        local_address=context.address,
        local_name=context.function_name,
        local_function_address=context.function_address,
        corpora=request.corpora,
        limit=request.limit,
    )


def compare_function(plugin_config, request: CompareRequest) -> list[dict]:
    config = build_binlex_config(plugin_config)
    require_embeddings(config, target="function")
    context = resolve_function_context(config)
    vector = vector_for_context(context)
    if not vector:
        raise RuntimeError("embeddings vector is not available for this function")

    return _search_rows(
        plugin_config=plugin_config,
        vector=vector,
        collection=Collection.Function,
        local_address=context.address,
        local_name=context.function_name,
        local_function_address=context.address,
        corpora=request.corpora,
        limit=request.limit,
    )


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
