# Binlex IDA Plugin

Minimal IDA frontend for `LocalIndex`.

The plugin exposes:

- batch actions from the main `Binlex` menu:
  - `Index > Functions`
  - `Compare > Functions`
  - `Config`
- context actions from right click in disassembly/listing and pseudocode:
  - block/function indexing
  - block/function comparison
  - copy helpers for vector, hashes, hex, and pattern

## Install

```bash
cd plugins/ida
pip install .
python -m plugin install
```

Use `python -m plugin print-target` to inspect the detected IDA plugins directory, or pass `--target`.

`--source` is the plugin source tree that contains `main.py`, `ida-plugin.json`, `core/`, and `ui/`. It is not the IDA plugins directory.

Windows example:

```powershell
python -m plugin install --target "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
```

## Uninstall

```bash
python -m plugin uninstall
```

## Build Archive

```bash
python -m plugin archive
```
