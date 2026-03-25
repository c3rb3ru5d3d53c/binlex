from __future__ import annotations

import copy
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import ida_registry

from binlex import Config


REGISTRY_SUBKEY = "binlex"
REGISTRY_KEY = "mvp_config"
CONFIG_DIRECTORY = "binlex"
CONFIG_FILE_NAME = "ida.toml"
AUTO_NAME_PATTERNS = (
    r"^sub_[0-9A-Fa-f]+$",
    r"^loc_[0-9A-Fa-f]+$",
    r"^locret_[0-9A-Fa-f]+$",
    r"^nullsub_[0-9A-Fa-f]+$",
    r"^j_[0-9A-Fa-f]+$",
    r"^def_[0-9A-Fa-f]+$",
    r"^unk_[0-9A-Fa-f]+$",
    r"^off_[0-9A-Fa-f]+$",
)


@dataclass
class PluginConfig:
    index_root: str = str(Path.home() / ".cache" / "binlex" / "ida-local-index")
    default_corpus: str = "default"
    default_threads: int = 4
    default_embedding_dimensions: int = 64
    default_compare_limit: int = 16
    default_index_blocks_with_functions: bool = False
    include_meaningful_names: bool = True

    def clone(self) -> "PluginConfig":
        return copy.deepcopy(self)


def plugin_config_directory() -> Path:
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / CONFIG_DIRECTORY
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / CONFIG_DIRECTORY
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / CONFIG_DIRECTORY
    return Path.home() / ".config" / CONFIG_DIRECTORY


def plugin_config_path() -> Path:
    return plugin_config_directory() / CONFIG_FILE_NAME


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _serialize_plugin_config(config: PluginConfig) -> str:
    return "\n".join(
        [
            "# Binlex IDA plugin configuration",
            "",
            f'index_root = {json.dumps(config.index_root)}',
            f'default_corpus = {json.dumps(config.default_corpus)}',
            f"default_threads = {config.default_threads}",
            f"default_embedding_dimensions = {config.default_embedding_dimensions}",
            f"default_compare_limit = {config.default_compare_limit}",
            f"default_index_blocks_with_functions = {_toml_bool(config.default_index_blocks_with_functions)}",
            f"include_meaningful_names = {_toml_bool(config.include_meaningful_names)}",
            "",
        ]
    )


def _parse_plugin_config_toml(text: str) -> PluginConfig:
    data: dict[str, object] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key in {"index_root", "default_corpus"}:
            data[key] = json.loads(value)
        elif key in {
            "default_threads",
            "default_embedding_dimensions",
            "default_compare_limit",
        }:
            data[key] = int(value)
        elif key in {
            "default_index_blocks_with_functions",
            "include_meaningful_names",
        }:
            normalized = value.lower()
            if normalized not in {"true", "false"}:
                raise ValueError(f"invalid boolean value for {key}: {value}")
            data[key] = normalized == "true"
    return PluginConfig(**data)


def ensure_plugin_config_file(config: PluginConfig | None = None) -> Path:
    path = plugin_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path
    path.write_text(_serialize_plugin_config(config or PluginConfig()), encoding="utf-8")
    return path


def open_plugin_config_in_editor(config: PluginConfig | None = None) -> Path:
    return ensure_plugin_config_file(config)


def is_meaningful_name(name: str | None) -> bool:
    if not name:
        return False
    value = name.strip()
    if not value:
        return False
    for pattern in AUTO_NAME_PATTERNS:
        if re.match(pattern, value):
            return False
    return True


def load_plugin_config(*, strict: bool = False) -> PluginConfig:
    path = plugin_config_path()
    if path.is_file():
        try:
            return _parse_plugin_config_toml(path.read_text(encoding="utf-8"))
        except Exception:
            if strict:
                raise
            return PluginConfig()

    raw = ida_registry.reg_read_string(REGISTRY_KEY, subkey=REGISTRY_SUBKEY)
    if not raw:
        return PluginConfig()
    try:
        import json

        data = json.loads(raw)
        return PluginConfig(**data)
    except Exception:
        if strict:
            raise
        return PluginConfig()


def save_plugin_config(config: PluginConfig) -> None:
    path = ensure_plugin_config_file(config)
    path.write_text(_serialize_plugin_config(config), encoding="utf-8")

    ida_registry.reg_write_string(
        REGISTRY_KEY,
        json.dumps(
            {
                "index_root": config.index_root,
                "default_corpus": config.default_corpus,
                "default_threads": config.default_threads,
                "default_embedding_dimensions": config.default_embedding_dimensions,
                "default_compare_limit": config.default_compare_limit,
                "default_index_blocks_with_functions": config.default_index_blocks_with_functions,
                "include_meaningful_names": config.include_meaningful_names,
            },
            sort_keys=True,
        ),
        subkey=REGISTRY_SUBKEY,
    )


def build_binlex_config(plugin_config: PluginConfig, *, threads: int | None = None, dimensions: int | None = None) -> Config:
    config = Config()
    config.general.threads = threads or plugin_config.default_threads
    embeddings = config.processors.embeddings
    embeddings.enabled = True
    embeddings.dimensions = dimensions or plugin_config.default_embedding_dimensions
    embeddings.instructions.enabled = True
    embeddings.blocks.enabled = True
    embeddings.functions.enabled = True
    embeddings.transport.inline.enabled = True
    embeddings.transport.ipc.enabled = False
    embeddings.transport.http.enabled = False
    return config
