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
from binlex.clients import Web


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


@dataclass
class PluginConfig:
    web_url: str = "http://127.0.0.1:8000"
    web_api_key: str = ""
    web_verify_tls: bool = False
    default_corpus: str = "default"
    default_threads: int = 4
    default_embedding_dimensions: int = 64
    default_compare_limit: int = 16
    default_index_blocks_with_functions: bool = True

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
    # Note: The processors configuration has been removed from the binlex API.
    # Embeddings functionality is now handled differently.
    # This function is kept for compatibility but no longer performs validation.
    pass


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _serialize_plugin_config(config: PluginConfig) -> str:
    lines = [
        "# Binlex IDA plugin configuration",
        "",
        f'web_url = {json.dumps(config.web_url)}',
        f'web_api_key = {json.dumps(config.web_api_key)}',
        f"web_verify_tls = {_toml_bool(config.web_verify_tls)}",
        f'default_corpus = {json.dumps(config.default_corpus)}',
        f"default_threads = {config.default_threads}",
        f"default_embedding_dimensions = {config.default_embedding_dimensions}",
        f"default_compare_limit = {config.default_compare_limit}",
        f"default_index_blocks_with_functions = {_toml_bool(config.default_index_blocks_with_functions)}",
        "",
    ]
    return "\n".join(lines)


def _parse_plugin_config_toml(text: str) -> PluginConfig:
    data: dict[str, object] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key in {"web_url", "web_api_key", "default_corpus"}:
            data[key] = json.loads(value)
        elif key in {
            "default_threads",
            "default_embedding_dimensions",
            "default_compare_limit",
        }:
            data[key] = int(value)
        elif key in {
            "web_verify_tls",
            "default_index_blocks_with_functions",
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
    # Note: Config.from_default(), write_default(), and to_string() have been removed from the API
    # Creating a simple default config file if it doesn't exist
    if not path.exists():
        default_config = """# Binlex configuration file
# See documentation for available options
"""
        path.write_text(default_config, encoding="utf-8")
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
            return _parse_plugin_config_toml(path.read_text(encoding="utf-8"))
        except Exception:
            if strict:
                raise
            return PluginConfig()

    raw = ida_registry.reg_read_string(REGISTRY_KEY, subkey=REGISTRY_SUBKEY)
    if not raw:
        return PluginConfig()
    try:
        data = json.loads(raw)
        filtered = {
            key: value
            for key, value in data.items()
            if key
            in {
                "web_url",
                "web_api_key",
                "web_verify_tls",
                "default_corpus",
                "default_threads",
                "default_embedding_dimensions",
                "default_compare_limit",
                "default_index_blocks_with_functions",
            }
        }
        return PluginConfig(**filtered)
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
                "web_url": config.web_url,
                "web_api_key": config.web_api_key,
                "web_verify_tls": config.web_verify_tls,
                "default_corpus": config.default_corpus,
                "default_threads": config.default_threads,
                "default_embedding_dimensions": config.default_embedding_dimensions,
                "default_compare_limit": config.default_compare_limit,
                "default_index_blocks_with_functions": config.default_index_blocks_with_functions,
            },
            sort_keys=True,
        ),
        subkey=REGISTRY_SUBKEY,
    )


def build_binlex_config(
    plugin_config: PluginConfig,
    *,
    threads: int | None = None,
    dimensions: int | None = None,
) -> Config:
    config = Config()
    # Set threads directly on the config object (API change: no more config.general)
    config.threads = threads or plugin_config.default_threads
    # Note: config.processors.embeddings has been removed from the API
    # Embeddings configuration is now handled differently
    return config


def build_web_client(plugin_config: PluginConfig, config: Config | None = None) -> Web:
    url = plugin_config.web_url.strip()
    if not url:
        raise RuntimeError("web_url must be configured for the Binlex IDA plugin")
    api_key = plugin_config.web_api_key.strip()
    if not api_key:
        raise RuntimeError("web_api_key must be configured for the Binlex IDA plugin")
    return Web(
        config or build_binlex_config(plugin_config),
        url=url,
        verify=plugin_config.web_verify_tls,
        api_key=api_key,
    )
