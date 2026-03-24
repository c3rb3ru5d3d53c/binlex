from __future__ import annotations

from dataclasses import dataclass

import ida_bytes
import ida_kernwin
import ida_ua
import idc

from binlex.controlflow import Block, Function
from binlex.genetics import Chromosome
from binlex.hashing import MinHash32, TLSH

from .disassembly import (
    build_disassembler,
    build_graph,
    current_block_address,
    current_function_address,
    disassemble_block_graph,
    disassemble_function_graph,
)


@dataclass
class SelectionRange:
    start: int
    end: int


@dataclass
class ResolvedContext:
    kind: str
    address: int
    function_address: int | None
    function_name: str
    selection: SelectionRange | None
    graph: object
    entity: object
    bytes_data: bytes
    pattern: str


def current_viewer_selection(widget=None) -> SelectionRange | None:
    viewer = widget or ida_kernwin.get_current_viewer()
    if viewer is None:
        return None
    status, start, end = ida_kernwin.read_range_selection(viewer)
    if not status or start == end:
        return None
    return SelectionRange(start=start, end=end)


def selected_instruction_addresses(selection: SelectionRange) -> list[int]:
    addresses: list[int] = []
    address = selection.start
    while address < selection.end:
        instruction = ida_ua.insn_t()
        size = ida_ua.decode_insn(instruction, address)
        if size <= 0:
            next_address = idc.next_head(address, selection.end)
            if next_address == idc.BADADDR or next_address <= address:
                break
            address = next_address
            continue
        if idc.is_code(idc.get_full_flags(address)):
            addresses.append(address)
        address += size
    return addresses


def selection_bytes(selection: SelectionRange) -> bytes:
    size = max(0, selection.end - selection.start)
    if size == 0:
        return b""
    return ida_bytes.get_bytes(selection.start, size) or b""


def _transient_block_for_selection(config, selection: SelectionRange):
    addresses = selected_instruction_addresses(selection)
    if not addresses:
        raise RuntimeError("no instructions are selected")
    graph = build_graph(config)
    graph.set_block(addresses[0])
    disassembler = build_disassembler(config)
    for address in addresses:
        disassembler.disassemble_instruction(address, graph)
    for current, nxt in zip(addresses, addresses[1:]):
        graph.extend_instruction_edges(current, [nxt])
    block = Block(addresses[0], graph)
    chromosome = block.chromosome()
    return graph, block, chromosome.pattern()


def _function_pattern(function) -> str:
    chromosome = function.chromosome()
    if chromosome is not None:
        return chromosome.pattern()
    patterns = []
    for block in sorted(function.blocks(), key=lambda item: item.address()):
        patterns.append(block.chromosome().pattern())
    return "".join(patterns)


def resolve_function_context(config, widget=None) -> ResolvedContext:
    del widget
    function_address = current_function_address()
    if function_address is None:
        raise RuntimeError("the cursor is not inside a function")
    graph = disassemble_function_graph(function_address, config)
    entity = Function(function_address, graph)
    function_name = idc.get_func_name(function_address) or ""
    bytes_data = entity.bytes() or b""
    pattern = _function_pattern(entity)
    return ResolvedContext(
        kind="function",
        address=entity.address(),
        function_address=function_address,
        function_name=function_name,
        selection=None,
        graph=graph,
        entity=entity,
        bytes_data=bytes_data,
        pattern=pattern,
    )


def resolve_block_context(config, widget=None) -> ResolvedContext:
    selection = current_viewer_selection(widget)
    if selection is not None:
        return resolve_selection_context(config, widget)

    address = ida_kernwin.get_screen_ea()
    block_address = current_block_address(address)
    if block_address is None:
        raise RuntimeError("the cursor is not inside a block")
    graph = disassemble_block_graph(block_address, config)
    entity = Block(block_address, graph)
    function_address = current_function_address(address)
    function_name = idc.get_func_name(function_address) if function_address is not None else ""
    return ResolvedContext(
        kind="block",
        address=entity.address(),
        function_address=function_address,
        function_name=function_name or "",
        selection=None,
        graph=graph,
        entity=entity,
        bytes_data=entity.bytes() or b"",
        pattern=entity.chromosome().pattern(),
    )


def resolve_selection_context(config, widget=None) -> ResolvedContext:
    selection = current_viewer_selection(widget)
    if selection is None:
        raise RuntimeError("no instruction selection is active")
    graph, entity, pattern = _transient_block_for_selection(config, selection)
    function_address = current_function_address(selection.start)
    function_name = idc.get_func_name(function_address) if function_address is not None else ""
    return ResolvedContext(
        kind="selection",
        address=entity.address(),
        function_address=function_address,
        function_name=function_name or "",
        selection=selection,
        graph=graph,
        entity=entity,
        bytes_data=selection_bytes(selection),
        pattern=pattern,
    )


def vector_for_context(context: ResolvedContext) -> list[float] | None:
    processor = context.entity.processor("embeddings")
    if not isinstance(processor, dict):
        return None
    vector = processor.get("vector")
    if not isinstance(vector, list):
        return None
    return vector


def minhash_for_context(context: ResolvedContext, config) -> str | None:
    if context.kind in {"block", "function"}:
        value = context.entity.minhash()
        return None if value is None else value.hexdigest()
    minhash = MinHash32(
        context.bytes_data,
        config.chromosomes.minhash.number_of_hashes,
        config.chromosomes.minhash.shingle_size,
        config.chromosomes.minhash.seed,
    )
    return minhash.hexdigest()


def tlsh_for_context(context: ResolvedContext, config) -> str | None:
    if context.kind in {"block", "function"}:
        value = context.entity.tlsh()
        if value is None:
            return None
        return value.hexdigest(config.functions.tlsh.minimum_byte_size)
    tlsh = TLSH(context.bytes_data)
    return tlsh.hexdigest(config.chromosomes.tlsh.minimum_byte_size)


def visual_hash_for_context(context: ResolvedContext, config, kind: str) -> str | None:
    image = None
    if hasattr(context.entity, "png"):
        image = context.entity.png()
    if image is None:
        image = Chromosome(context.pattern, config).png()
    if kind == "ahash":
        value = image.ahash()
    elif kind == "dhash":
        value = image.dhash()
    else:
        value = image.phash()
    return None if value is None else value.hexdigest()
