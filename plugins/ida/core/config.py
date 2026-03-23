from __future__ import annotations

import copy
import re
from dataclasses import asdict, dataclass
from pathlib import Path

import ida_registry

from binlex import Config


REGISTRY_SUBKEY = "binlex"
REGISTRY_KEY = "mvp_config"
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


def load_plugin_config() -> PluginConfig:
    raw = ida_registry.reg_read_string(REGISTRY_KEY, subkey=REGISTRY_SUBKEY)
    if not raw:
        return PluginConfig()
    try:
        import json

        data = json.loads(raw)
        return PluginConfig(**data)
    except Exception:
        return PluginConfig()


def save_plugin_config(config: PluginConfig) -> None:
    import json

    ida_registry.reg_write_string(
        REGISTRY_KEY,
        json.dumps(asdict(config), sort_keys=True),
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
