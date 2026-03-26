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
BINLEX_CONFIG_FILE_NAME = "binlex.toml"
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
LEGACY_IDA_INDEX_ROOT = str(Path.home() / ".cache" / "binlex" / "ida-local-index")


@dataclass
class PluginConfig:
    index_root: str | None = None
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


def binlex_config_directory() -> Path:
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


def binlex_config_path() -> Path:
    return binlex_config_directory() / BINLEX_CONFIG_FILE_NAME


def _processor_binary_names() -> tuple[str, ...]:
    if sys.platform.startswith("win"):
        return ("binlex-processor-embeddings.exe", "binlex-processor-embeddings")
    return ("binlex-processor-embeddings",)


def require_embeddings(config: Config, *, target: str) -> None:
    if not config.processors.enabled:
        raise RuntimeError(
            "Binlex processors are disabled in your Binlex config. "
            "Enable `processors.enabled = true` to use embeddings-backed IDA actions."
        )

    processor_path = config.processors.path
    if not processor_path:
        raise RuntimeError(
            "Binlex embeddings require `processors.path` to be set in your Binlex config."
        )

    processor_dir = Path(processor_path)
    if not processor_dir.is_dir():
        raise RuntimeError(
            f"Configured Binlex processors.path does not exist: {processor_dir}"
        )

    if not any((processor_dir / name).is_file() for name in _processor_binary_names()):
        raise RuntimeError(
            f"Configured Binlex processors.path does not contain `binlex-processor-embeddings`: {processor_dir}"
        )

    embeddings = config.processors.embeddings
    if not embeddings.enabled:
        raise RuntimeError(
            "Binlex embeddings are disabled in your Binlex config. "
            "Enable the `embeddings` processor to use embeddings-backed IDA actions."
        )

    enabled_for_target = {
        "instructions": embeddings.instructions.enabled,
        "block": embeddings.blocks.enabled,
        "function": embeddings.functions.enabled,
    }.get(target)
    if not enabled_for_target:
        raise RuntimeError(
            f"Binlex embeddings are disabled for `{target}` in your Binlex config."
        )


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _serialize_plugin_config(config: PluginConfig) -> str:
    lines = [
        "# Binlex IDA plugin configuration",
        "",
    ]
    if config.index_root:
        lines.append(f'index_root = {json.dumps(config.index_root)}')
    lines.extend(
        [
            f'default_corpus = {json.dumps(config.default_corpus)}',
            f"default_threads = {config.default_threads}",
            f"default_embedding_dimensions = {config.default_embedding_dimensions}",
            f"default_compare_limit = {config.default_compare_limit}",
            f"default_index_blocks_with_functions = {_toml_bool(config.default_index_blocks_with_functions)}",
            f"include_meaningful_names = {_toml_bool(config.include_meaningful_names)}",
            "",
        ]
    )
    return "\n".join(lines)


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


def ensure_binlex_config_file() -> Path:
    path = binlex_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    config = Config()
    try:
        config.from_default()
    except Exception:
        try:
            config.write_default()
        except Exception:
            pass
    if not path.exists():
        path.write_text(config.to_string(), encoding="utf-8")
    return path


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
            config = _parse_plugin_config_toml(path.read_text(encoding="utf-8"))
            if config.index_root == LEGACY_IDA_INDEX_ROOT:
                config.index_root = None
            return config
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
        config = PluginConfig(**data)
        if config.index_root == LEGACY_IDA_INDEX_ROOT:
            config.index_root = None
        return config
    except Exception:
        if strict:
            raise
        return PluginConfig()


def effective_index_root(plugin_config: PluginConfig) -> str:
    if plugin_config.index_root:
        return plugin_config.index_root
    config = Config()
    try:
        config.from_default()
    except Exception:
        pass
    return config.index.local.directory


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
    try:
        config.from_default()
    except Exception:
        pass
    config.general.threads = threads or plugin_config.default_threads
    config.processors.embeddings.enabled = True
    if dimensions is not None:
        config.processors.embeddings.dimensions = dimensions
    return config
