import argparse

from binlex_bindings.binlex import _run_processor_entry


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m binlex._processor")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--processor", required=True)
    parser.add_argument("--compression", default="false")
    args = parser.parse_args()

    return _run_processor_entry(
        args.processor,
        args.socket,
        args.compression.lower() == "true",
    )


if __name__ == "__main__":
    raise SystemExit(main())
