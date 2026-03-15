# Binlex IDA Plugin

This directory is the package root for the Binlex IDA plugin.

## Install

```bash
cd plugins/ida
pip install .
python -m plugin install
```

Use `python -m plugin print-target` to see the detected IDA plugins directory, or pass `--target` to install into a specific path.

## Uninstall

```bash
python -m plugin uninstall
```

## Build Archive

```bash
python -m plugin archive
```
