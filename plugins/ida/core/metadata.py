from __future__ import annotations

import json
from pathlib import Path


class MetadataStore:
    def __init__(self, root: str) -> None:
        self.path = Path(root).expanduser() / ".binlex_ida_metadata.json"

    def _load(self) -> dict:
        if not self.path.is_file():
            return {"version": 1, "corpora": {}}
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {"version": 1, "corpora": {}}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True))

    @staticmethod
    def _address_key(address: int) -> str:
        return hex(address)

    def record_names(
        self,
        *,
        corpus: str,
        collection: str,
        sha256: str,
        address: int,
        names: list[str],
    ) -> None:
        if not names:
            return
        data = self._load()
        corpora = data.setdefault("corpora", {})
        samples = corpora.setdefault(corpus, {})
        sample = samples.setdefault(sha256, {"function": {}, "block": {}})
        collection_map = sample.setdefault(collection, {})
        collection_map[self._address_key(address)] = sorted(set(name for name in names if name))
        self._save(data)

    def record_many(
        self,
        *,
        corpus: str,
        collection: str,
        sha256: str,
        items: dict[int, list[str]],
    ) -> None:
        if not items:
            return
        data = self._load()
        corpora = data.setdefault("corpora", {})
        samples = corpora.setdefault(corpus, {})
        sample = samples.setdefault(sha256, {"function": {}, "block": {}})
        collection_map = sample.setdefault(collection, {})
        for address, names in items.items():
            filtered = sorted(set(name for name in names if name))
            if filtered:
                collection_map[self._address_key(address)] = filtered
        self._save(data)

    def names_for(self, *, corpus: str, collection: str, sha256: str, address: int) -> list[str]:
        data = self._load()
        return (
            data.get("corpora", {})
            .get(corpus, {})
            .get(sha256, {})
            .get(collection, {})
            .get(self._address_key(address), [])
        )
