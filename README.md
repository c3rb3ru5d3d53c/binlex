![build](https://github.com/c3rb3ru5d3d53c/binlex/actions/workflows/cicd.yml/badge.svg?branch=master)
![OS Linux](https://img.shields.io/badge/os-linux-brightgreen)
![OS Windows](https://img.shields.io/badge/os-windows-brightgreen)
![OS MacOS](https://img.shields.io/badge/os-macos-brightgreen)
[![GitHub stars](https://img.shields.io/github/stars/c3rb3ru5d3d53c/binlex)](https://github.com/c3rb3ru5d3d53c/binlex/stargazers)
[![GitHub license](https://img.shields.io/github/license/c3rb3ru5d3d53c/binlex)](https://github.com/c3rb3ru5d3d53c/binlex/blob/master/LICENSE)
![GitHub all releases](https://img.shields.io/github/downloads/c3rb3ru5d3d53c/binlex/total)

<table>
  <tr>
    <td style="border: none; text-align: center; vertical-align: middle;">
      <img src="./assets/binlex.png" alt="Binlex logo" width="100" style="display: inline-block;">
    </td>
    <td style="border: none; text-align: center; vertical-align: middle; padding-left: 10px;">
      <h1 style="font-weight: bold; margin: 0;">Binlex - A Binary Genetic Trait Lexer Framework</h1>
      <div style="font-size: smaller; font-weight: bold; margin-top: 5px;">
        If maldevs think their binary is FUD, they're about to have an existential crisis.
      </div>
    </td>
  </tr>
</table>

Binlex extracts instructions, basic blocks, and functions from binaries and emits searchable JSON traits for reverse engineering, hunting, and similarity workflows. It models binary structure with a genomics-inspired hierarchy: genomes (instructions, blocks, functions), chromosomes (wildcarded patterns), allele pairs (bytes), and genes (nibbles). That representation makes malware analysis and binary similarity more systematic by enabling pattern-level comparison, clustering, and signature generation across large sample sets.

## Features

- 🧬 Fast trait extraction for instructions, blocks, and functions
- 🔐 Hashing and traits: MinHash, TLSH, SHA256, entropy, and wildcard patterns
- 📈 Normalization and feature pipelines for ML-oriented similarity workflows
- 🧰 Interfaces: CLI, Rust API, Python API/bindings, and IDA plugin
- ⚙️ Processor framework in Rust with fast external execution over `ipc` and `http`
- 🧠 Built-in processors include `vex` and `embeddings`; you can also build and share your own
- 🎯 Tooling for YARA generation, symbol ingestion, and batch JSON workflows

## Supported Targets 🌐

- Platforms: Linux, macOS, Windows
- Formats: PE, ELF, MachO
- Architectures: AMD64, I386, CIL

## Built-In Processors 🧠

- `binlex-processor-vex`: lifts instructions, blocks, or functions into VEX IR
- `binlex-processor-embeddings`: generates vector embeddings for similarity and ML workflows

Processors are implemented in Rust for fast execution. Binlex ships with these processors out of the box, and you can build and share your own processor backends as separate `binlex-processor-*` binaries.

See [Custom Processors](docs/processors.md) for the processor model and registration flow.

## Included Tools 🧰

- `binlex`: main CLI for binary trait extraction
- `binlex-server`: processor transport server for `http` workflows
- `binlex-hash`: hashing utility
- `binlex-image`: image-related utility
- `binlex-symbols`: symbol ingestion and conversion helper
- `binlex-yara`: generate YARA rules from Binlex-style patterns or streams

## Quick Start 🚀

### Build 🛠️

```bash
cargo build --release --workspace
```

### Run on a Sample ▶️

```bash
binlex -i sample.dll --threads 16 | jq
```

### Explore The CLI

```bash
binlex --help
```

### Optional: Python Bindings 🐍

```bash
cd bindings/python/
virtualenv -p python3 venv/
source venv/bin/activate
pip install maturin[patchelf]
maturin develop
```

### Optional: Packaging 📦

```bash
make zst   # Arch Linux
make deb   # Debian-based
make wheel # Python Wheel
```

### Optional: Binlex Server 🖥️

```bash
cp env.example .env
docker compose up -d
```

### Optional: IDA Plugin 🧠

```bash
cd plugins/ida/
pip install .
python -m binlex_ida install
```

## Configuration Path 📁

Default config file location:
- Linux: `$XDG_CONFIG_HOME/binlex/binlex.toml` or `$HOME/.config/binlex/binlex.toml`
- macOS: `$HOME/Library/Application Support/binlex/binlex.toml`
- Windows: `%APPDATA%\binlex\binlex.toml`

## Docs 📚

- [Command-Line Guide](docs/command-line.md)
- [Custom Processors](docs/processors.md)

API reference docs can be generated from source:

```bash
cargo doc --open
```

## Examples 🧪

- [Python Examples](examples/python/)
- [Rust Examples](examples/rust/)

## Citation 📖

If you use Binlex in a journal publication or open-source AI model, cite:

```bibtex
@misc{binlex,
  author = {c3rb3ru5d3d53c},
  title = {binlex: A Binary Genetic Trait Lexer Framework},
  year = {2025},
  note = {Available at \url{https://github.com/c3rb3ru5d3d53c/binlex}}
}
```

For corporate/personal usage or generated outputs (for example YARA rules), citation is not required.
