#!/usr/bin/env python

import argparse
from pathlib import Path

from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import ELF, MACHO, PE
from binlex.index import Collection, LocalIndex
from binlex.metadata import Attribute


def configure_embeddings(config: Config, dimensions: int) -> None:
    embeddings = config.processors.embeddings
    embeddings.enabled = True
    embeddings.dimensions = dimensions
    embeddings.transport.inline.enabled = True
    embeddings.transport.ipc.enabled = False
    embeddings.transport.http.enabled = False


def build_pe_graph(path: str, config: Config) -> tuple[Graph, str, Attribute]:
    pe = PE(path, config)
    image = pe.image()
    disassembler = Disassembler(
        pe.architecture(),
        image,
        pe.executable_virtual_address_ranges(),
        config,
    )
    graph = Graph(pe.architecture(), config)
    disassembler.disassemble_controlflow(pe.entrypoint_virtual_addresses(), graph)
    return graph, pe.sha256(), Attribute.from_file(pe.file())


def build_elf_graph(path: str, config: Config) -> tuple[Graph, str, Attribute]:
    elf = ELF(path, config)
    image = elf.image()
    disassembler = Disassembler(
        elf.architecture(),
        image,
        elf.executable_virtual_address_ranges(),
        config,
    )
    graph = Graph(elf.architecture(), config)
    disassembler.disassemble_controlflow(elf.entrypoint_virtual_addresses(), graph)
    return graph, elf.sha256(), Attribute.from_file(elf.file())


def build_macho_graph(path: str, config: Config, slice_index: int) -> tuple[Graph, str, Attribute]:
    macho = MACHO(path, config)
    architecture = macho.architecture(slice_index)
    if architecture is None:
        raise ValueError(f"invalid Mach-O slice index: {slice_index}")
    image = macho.image(slice_index)
    disassembler = Disassembler(
        architecture,
        image,
        macho.executable_virtual_address_ranges(slice_index),
        config,
    )
    graph = Graph(architecture, config)
    disassembler.disassemble_controlflow(
        macho.entrypoint_virtual_addresses(slice_index),
        graph,
    )
    return graph, macho.sha256(), Attribute.from_file(macho.file())


def build_graph(path: str, file_type: str, config: Config, macho_slice: int) -> tuple[Graph, str, Attribute]:
    if file_type == "pe":
        return build_pe_graph(path, config)
    if file_type == "elf":
        return build_elf_graph(path, config)
    if file_type == "macho":
        return build_macho_graph(path, config, macho_slice)
    raise ValueError(f"unsupported file type: {file_type}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Index a binary into binlex LocalIndex and search it back via the internal LanceDB index.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", required=True, help="Path to the input binary")
    parser.add_argument(
        "--type",
        required=True,
        choices=("pe", "elf", "macho"),
        help="Binary container type",
    )
    parser.add_argument(
        "--root",
        default="./local-store-db",
        help="LocalIndex root directory",
    )
    parser.add_argument(
        "--corpus",
        default="default",
        help="Corpus name used for indexing and searching",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum number of search hits to return",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of analysis threads",
    )
    parser.add_argument(
        "--dimensions",
        type=int,
        default=64,
        help="Embedding vector dimensions",
    )
    parser.add_argument(
        "--macho-slice",
        type=int,
        default=0,
        help="Mach-O slice index when --type=macho",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        raise FileNotFoundError(f"input file not found: {input_path}")

    config = Config()
    config.general.threads = args.threads
    configure_embeddings(config, args.dimensions)

    graph, analyzed_sha256, file_attribute = build_graph(
        str(input_path),
        args.type,
        config,
        args.macho_slice,
    )
    functions = graph.functions()
    if not functions:
        raise RuntimeError("no functions were discovered in the controlflow graph")

    store = LocalIndex(config, directory=args.root)
    sha256 = store.put(input_path.read_bytes())
    if analyzed_sha256 is not None and analyzed_sha256 != sha256:
        raise RuntimeError("file sha256 mismatch between format parser and LocalIndex")

    store.graph(
        corpus=args.corpus,
        sha256=sha256,
        graph=graph,
        attributes=[
            file_attribute,
            Attribute.tag(args.type),
        ],
        selector="processors.embeddings.vector",
    )
    store.commit()

    restored_graph = store.load(args.corpus, sha256)
    query_function = restored_graph.functions()[0]
    embedding = query_function.processor("embeddings")
    if "vector" not in embedding:
        raise RuntimeError("embeddings processor output missing from query function")
    query_vector = embedding["vector"]

    results = store.search(
        corpora=[args.corpus],
        vector=query_vector,
        collections=[Collection.Function],
        architectures=[query_function.architecture()],
        limit=args.limit,
    )

    print(f"indexed sha256: {sha256}")
    print(f"restored graph: {len(restored_graph.functions())} functions")
    print(
        f"query function: address={hex(query_function.address())} "
        f"vector_dimensions={len(query_vector)}"
    )
    print("function hits:")
    for index, hit in enumerate(results, start=1):
        matched_function = hit.function()
        matched_address = hex(matched_function.address()) if matched_function is not None else "n/a"
        print(
            f"{index:02d}. score={hit.score():.6f} "
            f"sha256={hit.sha256()} "
            f"address={hex(hit.address())} "
            f"matched_function={matched_address} "
            f"object_id={hit.object_id()}"
        )


if __name__ == "__main__":
    main()
