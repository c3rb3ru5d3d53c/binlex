from __future__ import annotations

import ida_kernwin

from core.compare import CompareRequest
from core.config import PluginConfig
from core.indexing import IndexRequest


def _parse_corpora(value: str) -> list[str]:
    corpora = []
    seen = set()
    for item in value.split(","):
        corpus = item.strip()
        if not corpus or corpus in seen:
            continue
        corpora.append(corpus)
        seen.add(corpus)
    return corpora


def _ask_text(default: str, prompt: str) -> str | None:
    return ida_kernwin.ask_str(default, 0, prompt)


def _ask_int(default: int, prompt: str, minimum: int, maximum: int) -> int | None:
    value = ida_kernwin.ask_long(default, prompt)
    if value is None:
        return None
    if value < minimum or value > maximum:
        raise RuntimeError(
            f"value out of range for '{prompt}': expected {minimum}-{maximum}, got {value}"
        )
    return value


def _ask_bool(default: bool, prompt: str) -> bool | None:
    button = ida_kernwin.ASKBTN_YES if default else ida_kernwin.ASKBTN_NO
    result = ida_kernwin.ask_yn(button, prompt)
    if result == ida_kernwin.ASKBTN_CANCEL:
        return None
    return result == ida_kernwin.ASKBTN_YES


def prompt_config(plugin_config: PluginConfig) -> PluginConfig | None:
    web_url = _ask_text(plugin_config.web_url, "Binlex config: binlex-web URL")
    if web_url is None:
        return None
    web_api_key = _ask_text(plugin_config.web_api_key, "Binlex config: binlex-web API key")
    if web_api_key is None:
        return None
    verify_tls = _ask_bool(
        plugin_config.web_verify_tls,
        "Verify TLS certificates when connecting to binlex-web?",
    )
    if verify_tls is None:
        return None
    default_corpora = _ask_text(
        plugin_config.default_corpus,
        "Binlex config: default corpora (comma-separated)",
    )
    if default_corpora is None:
        return None
    default_threads = _ask_int(
        plugin_config.default_threads,
        "Binlex config: default threads",
        1,
        128,
    )
    if default_threads is None:
        return None
    default_dimensions = _ask_int(
        plugin_config.default_embedding_dimensions,
        "Binlex config: default embedding dimensions",
        1,
        4096,
    )
    if default_dimensions is None:
        return None
    default_compare_limit = _ask_int(
        plugin_config.default_compare_limit,
        "Binlex config: default compare result limit",
        1,
        256,
    )
    if default_compare_limit is None:
        return None
    default_index_blocks = _ask_bool(
        plugin_config.default_index_blocks_with_functions,
        "Index blocks together with functions?",
    )
    if default_index_blocks is None:
        return None

    return PluginConfig(
        web_url=web_url.strip() or plugin_config.web_url,
        web_api_key=web_api_key.strip(),
        web_verify_tls=verify_tls,
        default_corpus=", ".join(_parse_corpora(default_corpora)) or "default",
        default_threads=default_threads,
        default_embedding_dimensions=default_dimensions,
        default_compare_limit=default_compare_limit,
        default_index_blocks_with_functions=default_index_blocks,
    )


def prompt_index(
    title: str,
    plugin_config: PluginConfig,
    *,
    allow_index_blocks: bool,
) -> IndexRequest | None:
    corpora_text = _ask_text(
        plugin_config.default_corpus,
        f"{title}: corpus names (comma-separated)",
    )
    if corpora_text is None:
        return None
    threads = _ask_int(plugin_config.default_threads, f"{title}: threads", 1, 128)
    if threads is None:
        return None
    dimensions = _ask_int(
        plugin_config.default_embedding_dimensions,
        f"{title}: embedding dimensions",
        1,
        4096,
    )
    if dimensions is None:
        return None
    index_blocks = False
    if allow_index_blocks:
        index_blocks = _ask_bool(
            plugin_config.default_index_blocks_with_functions,
            f"{title}: index blocks too?",
        )
        if index_blocks is None:
            return None

    return IndexRequest(
        corpora=_parse_corpora(corpora_text) or ["default"],
        threads=threads,
        dimensions=dimensions,
        index_blocks=index_blocks,
    )


def prompt_compare(title: str, plugin_config: PluginConfig) -> CompareRequest | None:
    corpora_text = _ask_text(
        plugin_config.default_corpus,
        f"{title}: corpus names (comma-separated)",
    )
    if corpora_text is None:
        return None
    limit = _ask_int(plugin_config.default_compare_limit, f"{title}: result limit", 1, 256)
    if limit is None:
        return None
    corpora = _parse_corpora(corpora_text)
    return CompareRequest(corpora=corpora or ["default"], limit=limit)


def show_error(message: str, parent=None) -> None:
    del parent
    ida_kernwin.warning(message)


def show_info(message: str, parent=None) -> None:
    del parent
    ida_kernwin.msg(f"[*] {message}\n")
