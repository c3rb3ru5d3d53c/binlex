from __future__ import annotations

import json
import os
import platform
import subprocess

import ida_kernwin

from binlex.genetics import Chromosome
from binlex.hashing import MinHash32, TLSH

from .context import (
    chromosome_from_pattern,
    current_viewer_selection,
    minhash_for_context,
    resolve_block_context,
    resolve_function_context,
    resolve_selection_context,
    selection_bytes,
    selection_pattern,
    selection_vectors,
    tlsh_for_context,
    vector_for_context,
    visual_hash_for_context,
)
try:
    from qt_compat import import_qt
except ModuleNotFoundError:  # pragma: no cover - fallback for packaged package layouts
    from ..qt_compat import import_qt


def _write_windows_clipboard(text: str) -> bool:
    if _write_command_clipboard(text, ["clip"]):
        return True
    try:
        import ctypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        GMEM_MOVEABLE = 0x0002
        CF_UNICODETEXT = 13

        if not user32.OpenClipboard(None):
            return False
        try:
            user32.EmptyClipboard()
            size = (len(text) + 1) * ctypes.sizeof(ctypes.c_wchar)
            handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, size)
            if not handle:
                return False
            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                kernel32.GlobalFree(handle)
                return False
            buffer = ctypes.create_unicode_buffer(text)
            try:
                ctypes.memmove(pointer, ctypes.addressof(buffer), size)
            finally:
                kernel32.GlobalUnlock(handle)
            if not user32.SetClipboardData(CF_UNICODETEXT, handle):
                kernel32.GlobalFree(handle)
                return False
            return True
        finally:
            user32.CloseClipboard()
    except Exception:
        return False


def _write_command_clipboard(text: str, command: list[str]) -> bool:
    try:
        subprocess.run(command, input=text.encode("utf-8"), check=True)
        return True
    except Exception:
        return False


def _copy_to_clipboard(text: str) -> bool:
    try:
        _, _, QtGui, _ = import_qt()
        QtGui.QGuiApplication.clipboard().setText(text)
        return True
    except Exception:
        pass

    system = platform.system()
    if system == "Windows":
        return _write_windows_clipboard(text)
    if system == "Darwin":
        return _write_command_clipboard(text, ["pbcopy"])

    for command in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
        if shutil_which(command[0]):
            return _write_command_clipboard(text, command)
    return False


def shutil_which(command: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _copy_text(label: str, text: str) -> None:
    if not _copy_to_clipboard(text):
        raise RuntimeError("clipboard is not available in this IDA Python environment")
    ida_kernwin.msg(f"[*] copied {label} to clipboard\n")


def _resolve_copy_context(config, target: str):
    if target == "function":
        return resolve_function_context(config)
    if target == "selection":
        return resolve_selection_context(config)
    return resolve_block_context(config)


def _average_vectors(vectors: list[list[float]]) -> list[float]:
    if not vectors:
        return []
    dimensions = len(vectors[0])
    totals = [0.0] * dimensions
    count = 0
    for vector in vectors:
        if len(vector) != dimensions:
            continue
        for index, value in enumerate(vector):
            totals[index] += float(value)
        count += 1
    if count == 0:
        return []
    return [value / count for value in totals]


def copy_vector(plugin_config, target: str) -> None:
    from .config import build_binlex_config, require_embeddings

    config = build_binlex_config(plugin_config)
    if target == "selection":
        require_embeddings(config, target="instructions")
        selection = current_viewer_selection()
        if selection is None:
            raise RuntimeError("no instruction selection is active")
        vector = _average_vectors(selection_vectors(config, selection))
        if not vector:
            raise RuntimeError("embeddings vector is not available for this instruction selection")
        _copy_text("vector", json.dumps(vector))
        return
    require_embeddings(config, target=target)
    context = _resolve_copy_context(config, target)
    vector = vector_for_context(context)
    if not vector:
        raise RuntimeError("embeddings vector is not available for this context")
    _copy_text("vector", json.dumps(vector))


def copy_minhash(plugin_config, target: str) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    if target == "selection":
        selection = current_viewer_selection()
        if selection is None:
            raise RuntimeError("no instruction selection is active")
        pattern = selection_pattern(config, selection)
        if not pattern:
            raise RuntimeError("minhash is not available for this instruction selection")
        value = MinHash32(
            pattern.encode("utf-8"),
            config.chromosomes.minhash.number_of_hashes,
            config.chromosomes.minhash.shingle_size,
            config.chromosomes.minhash.seed,
        ).hexdigest()
        _copy_text("minhash", value)
        return
    context = _resolve_copy_context(config, target)
    value = minhash_for_context(context, config)
    if not value:
        raise RuntimeError("minhash is not available for this context")
    _copy_text("minhash", value)


def copy_tlsh(plugin_config, target: str) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    if target == "selection":
        selection = current_viewer_selection()
        if selection is None:
            raise RuntimeError("no instruction selection is active")
        pattern = selection_pattern(config, selection)
        if not pattern:
            raise RuntimeError("TLSH is not available for this instruction selection")
        value = TLSH(pattern.encode("utf-8")).hexdigest(config.chromosomes.tlsh.minimum_byte_size)
        if not value:
            raise RuntimeError("TLSH is not available for this instruction selection")
        _copy_text("tlsh", value)
        return
    context = _resolve_copy_context(config, target)
    value = tlsh_for_context(context, config)
    if not value:
        raise RuntimeError("TLSH is not available for this context")
    _copy_text("tlsh", value)


def copy_visual_hash(plugin_config, target: str, kind: str) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    if target == "selection":
        selection = current_viewer_selection()
        if selection is None:
            raise RuntimeError("no instruction selection is active")
        pattern = selection_pattern(config, selection)
        if not pattern:
            raise RuntimeError(f"{kind} is not available for this instruction selection")
        image = chromosome_from_pattern(pattern, config).imaging().linear().grayscale().png()
        if kind == "ahash":
            value = image.ahash()
        elif kind == "dhash":
            value = image.dhash()
        else:
            value = image.phash()
        if value is None:
            raise RuntimeError(f"{kind} is not available for this instruction selection")
        _copy_text(kind, value.hexdigest())
        return
    context = _resolve_copy_context(config, target)
    value = visual_hash_for_context(context, config, kind)
    if not value:
        raise RuntimeError(f"{kind} is not available for this context")
    _copy_text(kind, value)


def copy_hex(plugin_config, target: str) -> None:
    if target == "selection":
        selection = current_viewer_selection()
        if selection is None:
            raise RuntimeError("no instruction selection is active")
        data = selection_bytes(selection)
        if not data:
            raise RuntimeError("hex bytes are not available for this instruction selection")
        _copy_text("hex", data.hex())
        return
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    context = _resolve_copy_context(config, target)
    if not context.bytes_data:
        raise RuntimeError("hex bytes are not available for this context")
    _copy_text("hex", context.bytes_data.hex())


def copy_pattern(plugin_config, target: str) -> None:
    from .config import build_binlex_config

    config = build_binlex_config(plugin_config)
    if target == "selection":
        selection = current_viewer_selection()
        if selection is None:
            raise RuntimeError("no instruction selection is active")
        pattern = selection_pattern(config, selection)
        if not pattern:
            raise RuntimeError("pattern is not available for this instruction selection")
        _copy_text("pattern", pattern)
        return
    context = _resolve_copy_context(config, target)
    if not context.pattern:
        raise RuntimeError("pattern is not available for this context")
    _copy_text("pattern", context.pattern)
