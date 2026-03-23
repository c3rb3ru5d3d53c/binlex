from __future__ import annotations

import json

from PyQt5.QtWidgets import QApplication

import ida_kernwin

from .context import (
    minhash_for_context,
    resolve_block_context,
    resolve_function_context,
    tlsh_for_context,
    vector_for_context,
    visual_hash_for_context,
)


def _copy_text(label: str, text: str) -> None:
    QApplication.clipboard().setText(text)
    ida_kernwin.msg(f"[*] copied {label} to clipboard\n")


def copy_vector(plugin_config, function_scope: bool) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    context = resolve_function_context(config) if function_scope else resolve_block_context(config)
    vector = vector_for_context(context)
    if not vector:
        raise RuntimeError("embeddings vector is not available for this context")
    _copy_text("vector", json.dumps(vector))


def copy_minhash(plugin_config, function_scope: bool) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    context = resolve_function_context(config) if function_scope else resolve_block_context(config)
    value = minhash_for_context(context, config)
    if not value:
        raise RuntimeError("minhash is not available for this context")
    _copy_text("minhash", value)


def copy_tlsh(plugin_config, function_scope: bool) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    context = resolve_function_context(config) if function_scope else resolve_block_context(config)
    value = tlsh_for_context(context, config)
    if not value:
        raise RuntimeError("TLSH is not available for this context")
    _copy_text("tlsh", value)


def copy_visual_hash(plugin_config, function_scope: bool, kind: str) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    context = resolve_function_context(config) if function_scope else resolve_block_context(config)
    value = visual_hash_for_context(context, config, kind)
    if not value:
        raise RuntimeError(f"{kind} is not available for this context")
    _copy_text(kind, value)


def copy_hex(plugin_config, function_scope: bool) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    context = resolve_function_context(config) if function_scope else resolve_block_context(config)
    if not context.bytes_data:
        raise RuntimeError("hex bytes are not available for this context")
    _copy_text("hex", context.bytes_data.hex())


def copy_pattern(plugin_config, function_scope: bool) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    context = resolve_function_context(config) if function_scope else resolve_block_context(config)
    if not context.pattern:
        raise RuntimeError("pattern is not available for this context")
    _copy_text("pattern", context.pattern)
