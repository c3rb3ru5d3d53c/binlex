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


def _ask_multiline(default: str, prompt: str) -> str | None:
    ask_text = getattr(ida_kernwin, "ask_text", None)
    if ask_text is not None:
        return ask_text(65535, default, prompt)
    return _ask_text(default.replace("\n", "; "), prompt)


def _ask_int(default: int, prompt: str, minimum: int, maximum: int) -> int | None:
    value = ida_kernwin.ask_long(default, prompt)
    if value is None:
        return None
    if value < minimum or value > maximum:
        raise RuntimeError(f"value out of range for '{prompt}': expected {minimum}-{maximum}, got {value}")
    return value


def _ask_bool(default: bool, prompt: str) -> bool | None:
    button = ida_kernwin.ASKBTN_YES if default else ida_kernwin.ASKBTN_NO
    result = ida_kernwin.ask_yn(button, prompt)
    if result == ida_kernwin.ASKBTN_CANCEL:
        return None
    return result == ida_kernwin.ASKBTN_YES


def _parse_bool(value: str, key: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"invalid boolean value for '{key}': {value}")


def _parse_index_overrides(text: str, *, allow_index_blocks: bool) -> IndexRequest:
    values: dict[str, str] = {}
    for raw_line in text.replace(";", "\n").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise RuntimeError(f"invalid override line: {raw_line}")
        key, value = [part.strip() for part in line.split("=", 1)]
        values[key.lower()] = value

    corpora = _parse_corpora(values.get("corpora", "default")) or ["default"]
    threads = int(values.get("threads", "4"))
    dimensions = int(values.get("dimensions", "64"))
    include_names = _parse_bool(values.get("include_names", "true"), "include_names")
    index_blocks = False
    if allow_index_blocks:
        index_blocks = _parse_bool(values.get("index_blocks", "false"), "index_blocks")

    if threads < 1 or threads > 128:
        raise RuntimeError(f"threads out of range: {threads}")
    if dimensions < 1 or dimensions > 4096:
        raise RuntimeError(f"dimensions out of range: {dimensions}")

    return IndexRequest(
        corpora=corpora,
        threads=threads,
        dimensions=dimensions,
        index_blocks=index_blocks,
        include_names=include_names,
    )


def _prompt_index_form(title: str, plugin_config: PluginConfig, *, allow_index_blocks: bool) -> IndexRequest | None:
    form_api = getattr(ida_kernwin, "Form", None)
    if form_api is None:
        return None
    decimal_type = getattr(form_api, "FT_DEC", None)
    numeric_kwargs = {"swidth": 10}
    if decimal_type is not None:
        numeric_kwargs["tp"] = decimal_type

    controls = {
        "corpora": form_api.StringInput(
            value=plugin_config.default_corpus,
            swidth=40,
        ),
        "threads": form_api.NumericInput(value=plugin_config.default_threads, **numeric_kwargs),
        "dimensions": form_api.NumericInput(
            value=plugin_config.default_embedding_dimensions,
            **numeric_kwargs,
        ),
        "include_names": form_api.StringInput(
            value="true" if plugin_config.include_meaningful_names else "false",
            swidth=8,
        ),
    }

    form_lines = [
        "STARTITEM 0",
        "BUTTON YES* OK",
        "BUTTON CANCEL Cancel",
        title,
        "",
        "<Corpora      :{corpora}>",
        "<Threads      :{threads}>",
        "<Dimensions   :{dimensions}>",
    ]

    if allow_index_blocks:
        controls["index_blocks"] = form_api.StringInput(
            value="true" if plugin_config.default_index_blocks_with_functions else "false",
            swidth=8,
        )
        form_lines.append("<Index blocks :{index_blocks}>")

    form_lines.append("<Include names:{include_names}>")

    form = form_api("\n".join(form_lines), controls)
    form.Compile()
    try:
        result = form.Execute()
        if result != 1:
            return None
        values = [
            f"corpora = {form.corpora.value}",
            f"threads = {form.threads.value}",
            f"dimensions = {form.dimensions.value}",
            f"include_names = {form.include_names.value}",
        ]
        if allow_index_blocks:
            values.append(f"index_blocks = {form.index_blocks.value}")
        return _parse_index_overrides("\n".join(values), allow_index_blocks=allow_index_blocks)
    finally:
        form.Free()


def prompt_config(plugin_config: PluginConfig) -> PluginConfig | None:
    default_corpora = _ask_text(plugin_config.default_corpus, "Binlex config: default corpora (comma-separated)")
    if default_corpora is None:
        return None
    default_threads = _ask_int(plugin_config.default_threads, "Binlex config: default threads", 1, 128)
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
        "Index blocks when indexing functions?",
    )
    if default_index_blocks is None:
        return None
    include_names = _ask_bool(
        plugin_config.include_meaningful_names,
        "Record meaningful function names?",
    )
    if include_names is None:
        return None

    return PluginConfig(
        index_root=plugin_config.index_root,
        default_corpus=", ".join(_parse_corpora(default_corpora)) or "default",
        default_threads=default_threads,
        default_embedding_dimensions=default_dimensions,
        default_compare_limit=default_compare_limit,
        default_index_blocks_with_functions=default_index_blocks,
        include_meaningful_names=include_names,
    )


def prompt_index(title: str, plugin_config: PluginConfig, *, allow_index_blocks: bool) -> IndexRequest | None:
    form_request = _prompt_index_form(title, plugin_config, allow_index_blocks=allow_index_blocks)
    if form_request is None:
        raise RuntimeError("IDA form API is not available for the Binlex indexing dialog")
    return form_request


def prompt_compare(title: str, plugin_config: PluginConfig, available_corpora: list[str]) -> CompareRequest | None:
    if available_corpora:
        ida_kernwin.msg(f"[*] {title} available corpora: {', '.join(sorted(available_corpora))}\n")
    corpora_text = _ask_text(plugin_config.default_corpus, f"{title}: corpus names (comma-separated)")
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
