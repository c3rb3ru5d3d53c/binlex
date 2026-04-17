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
class SearchRequest:
    corpora: list[str]
    limit: int


def _architecture_string() -> str:
    arch = architecture_for_current_ida()
    # Convert Architecture enum to simple string (e.g., Architecture.AMD64 -> "amd64")
    arch_str = str(arch).split('.')[-1].lower()
    return arch_str


def _query_for_vector(vector: list[float], *, corpus: str, collection: Collection, architecture: str) -> str:
    import ida_kernwin
    collection_str = str(collection)
    ida_kernwin.msg(f"[*] Collection type: {type(collection)}, str: '{collection_str}'\n")

    vector_json = json.dumps(vector, separators=(",", ":"))
    query = (
        f"vector:{vector_json} | "
        f"collection:{collection_str} | "
        f"corpus:{corpus} | "
        f"architecture:{architecture}"
    )

    ida_kernwin.msg(f"[*] Full query length: {len(query)} chars\n")
    ida_kernwin.msg(f"[*] Query (last 200 chars): ...{query[-200:]}\n")

    return query


def _symbol_names_for_hit(web, hit, *, architecture: str) -> list[str]:
    symbol = hit.symbol()
    if symbol:
        return [symbol]

    try:
        response = web.collection_symbols(
            hit.sha256(),
            hit.collection(),
            architecture,
            hit.address(),
        )
        # response is a SymbolsResponse object with .symbols() method
        symbols = response.symbols()  # Returns list of MetadataItem objects
        names = []
        for item in symbols:
            # MetadataItem has .name() method
            name = item.name().strip() if hasattr(item, 'name') else str(item).strip()
            if name:
                names.append(name)
        return names
    except Exception:
        return []


def _corpora_for_hit(web, sha256: str, collection, address: int, search_corpus: str) -> list[str]:
    """Get corpora for a hit - for now just use the search corpus."""
    # Note: entity_corpora API method doesn't exist yet
    # For now, we know the entity is in the corpus we searched
    return [search_corpus] if search_corpus else []


def _tags_for_hit(web, sha256: str, collection, address: int) -> list[str]:
    """Fetch all tags for a specific entity."""
    try:
        response = web.collection_tags(sha256, collection, address)
        # response is a TagsResponse object with .tags() method
        tags = response.tags()  # Returns list of MetadataItem objects
        return [tag.name() for tag in tags]
    except Exception:
        return []


def _comments_for_hit(web, sha256: str, collection, address: int) -> list[dict]:
    """Fetch all comments for a specific entity."""
    try:
        response = web.entity_comments(sha256, collection, address)
        # response is an EntityCommentsResponse object with .items() method
        comments = response.items()  # Returns list of EntityComment objects
        result = []
        for comment in comments:
            user = comment.user()  # Returns MetadataUser object
            result.append({
                "username": user.username(),
                "comment": comment.body(),
                "timestamp": str(comment.timestamp()),  # This might need special handling
            })
        return result
    except Exception:
        return []


def _dedupe_rows(rows: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        # Use first symbol or empty string for deduplication
        first_symbol = row.get("symbols", [""])[0] if row.get("symbols") else ""
        # Use sorted corpora as tuple for consistent deduplication
        corpora_tuple = tuple(sorted(row.get("corpora", [])))
        key = (
            int(row["local_address"]),
            int(row["local_function_address"]),
            int(row["match_address"]),
            str(first_symbol),
            str(row["sha256"]),
            corpora_tuple,
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
    sha256: str,
    corpora: list[str],
    collection: str,
    tags: list[str],
    comments: list[dict],
    symbols: list[str],
    architecture: str,
) -> dict:
    return {
        "local_address": local_address,
        "local_name": local_name,
        "local_function_address": local_function_address or local_address,
        "score": score,
        "match_address": match_address,
        "sha256": sha256,
        "corpora": corpora,
        "collection": collection,
        "tags": tags,
        "comments": comments,
        "symbols": symbols,
        "architecture": architecture,
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

        # Debug: print query
        import ida_kernwin
        ida_kernwin.msg(f"[*] Search query: {query[:200]}...\n")

        try:
            search_results = web.search(query, top_k=limit, page=1)
            result_count = 0

            for item in search_results:
                result_count += 1
                hit = item.lhs() or item.rhs()
                if hit is None:
                    continue

                # Fetch metadata
                symbols = _symbol_names_for_hit(web, hit, architecture=architecture)
                corpora = _corpora_for_hit(web, hit.sha256(), hit.collection(), hit.address(), corpus)
                tags = _tags_for_hit(web, hit.sha256(), hit.collection(), hit.address())
                comments = _comments_for_hit(web, hit.sha256(), hit.collection(), hit.address())

                rows.append(
                    _row(
                        local_address=local_address,
                        local_name=local_name,
                        local_function_address=local_function_address,
                        score=item.score(),
                        match_address=hit.address(),
                        sha256=hit.sha256(),
                        corpora=corpora,
                        collection=str(hit.collection()),
                        tags=tags,
                        comments=comments,
                        symbols=symbols,
                        architecture=architecture,
                    )
                )

            ida_kernwin.msg(f"[*] Search returned {result_count} results from corpus '{corpus}'\n")

        except Exception as e:
            ida_kernwin.msg(f"[!] Search error for corpus '{corpus}': {e}\n")
            import traceback
            traceback.print_exc()

    return _dedupe_rows(rows)


def search_block(plugin_config, request: SearchRequest) -> list[dict]:
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


def search_function(plugin_config, request: SearchRequest) -> list[dict]:
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


def apply_search_results(rows: list[dict]) -> tuple[int, list[str]]:
    grouped: dict[int, set[str]] = {}
    first_rows: dict[int, dict] = {}
    conflicts: list[str] = []

    for row in rows:
        # Get the first symbol if available, otherwise skip
        symbols = row.get("symbols", [])
        if not symbols:
            continue
        match_name = symbols[0].strip()
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
            f"corpora: {', '.join(row.get('corpora', []))}\n"
            f"match_address: {hex(int(row['match_address']))}\n"
        )
        function = idaapi.get_func(function_address)
        if function is not None:
            idaapi.set_func_cmt(function, comment, True)
        applied += 1
    return applied, conflicts
