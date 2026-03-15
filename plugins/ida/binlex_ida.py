from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
from pathlib import Path


PLUGIN_NAME = "binlex"
RUNTIME_FILES = (
    "__init__.py",
    "main.py",
    "ida-plugin.json",
    "requirements.txt",
)
RUNTIME_DIRS = (
    "actions",
    "gui",
    "lib",
)


def resolve_source_root() -> Path:
    candidates = [
        Path.cwd(),
        Path(__file__).resolve().parent,
    ]
    for candidate in candidates:
        if (candidate / "ida-plugin.json").is_file() and (candidate / "main.py").is_file():
            return candidate
    raise FileNotFoundError(
        "could not locate the plugin source root; run this from plugins/ida or pass --source"
    )


def candidate_plugin_directories() -> list[Path]:
    env_target = os.environ.get("BINLEX_IDA_PLUGIN_DIR") or os.environ.get("IDAPLUGINS")
    candidates: list[Path] = []
    if env_target:
        candidates.append(Path(env_target).expanduser())

    home = Path.home()
    system = platform.system()
    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        local_appdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins")
        if local_appdata:
            candidates.append(Path(local_appdata) / "Hex-Rays" / "IDA Pro" / "plugins")
    elif system == "Darwin":
        candidates.extend(
            [
                home / "Library" / "Application Support" / "Hex-Rays" / "IDA Pro" / "plugins",
                home / ".idapro" / "plugins",
            ]
        )
    else:
        candidates.extend(
            [
                home / ".config" / "idapro" / "plugins",
                home / ".idapro" / "plugins",
                home / ".config" / "Hex-Rays" / "IDA Pro" / "plugins",
            ]
        )

    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        candidate = candidate.expanduser()
        if candidate not in seen:
            unique.append(candidate)
            seen.add(candidate)
    return unique


def resolve_target_root(target: str | None) -> Path:
    if target:
        return Path(target).expanduser()

    candidates = candidate_plugin_directories()
    for candidate in candidates:
        if candidate.exists():
            return candidate
    if candidates:
        return candidates[0]
    raise FileNotFoundError("could not determine an IDA plugins directory")


def copy_runtime(source_root: Path, destination_root: Path) -> Path:
    plugin_root = destination_root / PLUGIN_NAME
    plugin_root.parent.mkdir(parents=True, exist_ok=True)
    if plugin_root.exists():
        shutil.rmtree(plugin_root)
    plugin_root.mkdir(parents=True, exist_ok=True)

    for filename in RUNTIME_FILES:
        shutil.copy2(source_root / filename, plugin_root / filename)
    for dirname in RUNTIME_DIRS:
        shutil.copytree(source_root / dirname, plugin_root / dirname)

    return plugin_root


def install(source: str | None, target: str | None) -> int:
    source_root = Path(source).expanduser() if source else resolve_source_root()
    target_root = resolve_target_root(target)
    plugin_root = copy_runtime(source_root, target_root)
    print(f"installed Binlex IDA plugin to {plugin_root}")
    return 0


def uninstall(target: str | None) -> int:
    target_root = resolve_target_root(target)
    plugin_root = target_root / PLUGIN_NAME
    if plugin_root.exists():
        shutil.rmtree(plugin_root)
        print(f"removed {plugin_root}")
        return 0
    print(f"nothing to remove at {plugin_root}")
    return 0


def archive(source: str | None, output: str | None) -> int:
    source_root = Path(source).expanduser() if source else resolve_source_root()
    output_path = Path(output).expanduser() if output else source_root / "dist" / "binlex-ida.zip"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    staging_root = output_path.parent / PLUGIN_NAME
    if staging_root.exists():
        shutil.rmtree(staging_root)
    copy_runtime(source_root, output_path.parent)
    shutil.make_archive(str(output_path.with_suffix("")), "zip", output_path.parent, PLUGIN_NAME)
    shutil.rmtree(staging_root)
    print(f"created {output_path}")
    return 0


def print_target(target: str | None) -> int:
    print(resolve_target_root(target))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Binlex IDA plugin installer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="install the plugin into an IDA plugins directory")
    install_parser.add_argument("--source", help="path to the plugin source root")
    install_parser.add_argument("--target", help="path to the IDA plugins directory")

    uninstall_parser = subparsers.add_parser("uninstall", help="remove the plugin from an IDA plugins directory")
    uninstall_parser.add_argument("--target", help="path to the IDA plugins directory")

    archive_parser = subparsers.add_parser("archive", help="create a zip archive of the plugin")
    archive_parser.add_argument("--source", help="path to the plugin source root")
    archive_parser.add_argument("--output", help="output zip path")

    target_parser = subparsers.add_parser("print-target", help="print the detected IDA plugins directory")
    target_parser.add_argument("--target", help="path to the IDA plugins directory")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "install":
        return install(args.source, args.target)
    if args.command == "uninstall":
        return uninstall(args.target)
    if args.command == "archive":
        return archive(args.source, args.output)
    if args.command == "print-target":
        return print_target(args.target)

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
