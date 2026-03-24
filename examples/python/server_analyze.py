#!/usr/bin/env python
# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse

from binlex import Config
from binlex.transports.http import Client


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="server_analyze",
        description="Analyze a binary through binlex-server and print the first function PNG pHash",
    )
    parser.add_argument("--input", required=True, help="Input binary path")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:5000",
        help="binlex-server base URL",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=16,
        help="Thread count for analysis configuration",
    )
    args = parser.parse_args()

    config = Config()
    config.general.threads = args.threads
    config.processors.enabled = True
    config.processors.embeddings.enabled = True
    config.processors.embeddings.transport.http.enabled = True
    config.processors.embeddings.transport.http.url = args.url

    client = Client(config)

    cfg = client.analyze_file(args.input)
    functions = cfg.functions()
    if not functions:
        print("no functions produced")
        return 0

    phash = functions[0].png().phash()
    print(phash.hexdigest() if phash else "no phash")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
