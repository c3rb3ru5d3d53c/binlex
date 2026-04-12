# Binlex IDA Plugin

Minimal IDA frontend for `binlex-web`.

The plugin disassembles locally inside IDA, then uses `binlex-web` for:

- indexing functions and blocks
- vector search / comparison
- remote symbol-backed rename suggestions

## Requirements

- `binlex-web` must be running
- the plugin config must contain:
  - `web_url`
  - `web_api_key`
- your Binlex config still needs working embeddings processors locally so IDA can generate vectors before sending queries to `binlex-web`

## Exposed Actions

- launcher actions:
  - `Config`
  - `Index -> Functions`
  - `Compare -> Function`
- context actions in disassembly / pseudocode:
  - block/function indexing
  - block/function comparison
  - copy helpers for vector, hashes, hex, and pattern

## Install

```bash
cd plugins/ida
pip install .
python -m binlex_ida install
```

Use `python -m binlex_ida print-target` to inspect the detected IDA plugins directory, or pass `--target`.

`--source` is the plugin source tree that contains `main.py`, `ida-plugin.json`, `core/`, and `ui/`. It is not the IDA plugins directory.

Windows example:

```powershell
python -m binlex_ida install --target "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
```

## Plugin Config

The plugin config is stored in `ida.toml`. The important fields are:

```toml
web_url = "http://127.0.0.1:8080"
web_api_key = "replace-me"
web_verify_tls = true
default_corpus = "default"
default_threads = 4
default_embedding_dimensions = 64
default_compare_limit = 16
default_index_blocks_with_functions = true
```

## Docker Deployment

The intended MVP workflow is to run `binlex-web` locally with Docker or Docker Compose, then point the plugin at that local service.

## Uninstall

```bash
python -m binlex_ida uninstall
```

## Build Archive

```bash
python -m binlex_ida archive
```
