from __future__ import annotations

import os
import tempfile
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import idaapi
import idautils
import idc

from binlex.architecture import Architecture
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import Image


def architecture_for_current_ida() -> Architecture:
    processor = ida_ida.inf_get_procname()
    if processor != "metapc":
        raise RuntimeError(f"unsupported IDA processor for Binlex plugin: {processor}")
    if ida_ida.inf_is_32bit_exactly():
        return Architecture.I386
    return Architecture.AMD64


def segment_ranges() -> list[dict]:
    segments: list[dict] = []
    for segment in idautils.Segments():
        start = idc.get_segm_start(segment)
        end = idc.get_segm_end(segment)
        permissions = idc.get_segm_attr(segment, idc.SEGATTR_PERM)
        segments.append(
            {
                "start": start,
                "end": end,
                "permissions": permissions,
                "executable": bool(permissions & idaapi.SEGPERM_EXEC),
            }
        )
    return segments


def virtual_address_ranges() -> dict[int, int]:
    return {segment["start"]: segment["end"] for segment in segment_ranges()}


def executable_virtual_address_ranges() -> dict[int, int]:
    return {segment["start"]: segment["end"] for segment in segment_ranges() if segment["executable"]}


def mapped_image() -> Image:
    input_path = idc.get_input_file_path() or "ida"
    safe_name = Path(input_path).name.replace(os.sep, "_").replace(":", "_")
    image_path = Path(tempfile.gettempdir()) / "binlex-ida-plugin" / f"{safe_name}.img"
    image_path.parent.mkdir(parents=True, exist_ok=True)
    image_path.unlink(missing_ok=True)

    image = Image(str(image_path), False)
    for segment in segment_ranges():
        start = segment["start"]
        end = segment["end"]
        data = ida_bytes.get_bytes(start, end - start)
        if data is None:
            continue
        if image.size() < start:
            image.seek_to_end()
            image.write_padding(start - image.size())
        image.seek_to_end()
        image.write(data)
    return image


def build_graph(config) -> Graph:
    return Graph(architecture_for_current_ida(), config)


def build_disassembler(config) -> Disassembler:
    return Disassembler(
        architecture_for_current_ida(),
        mapped_image(),
        executable_virtual_address_ranges(),
        config,
    )


def disassemble_function_graph(function_address: int, config) -> Graph:
    graph = build_graph(config)
    build_disassembler(config).disassemble_function(function_address, graph)
    return graph


def disassemble_block_graph(block_address: int, config) -> Graph:
    graph = build_graph(config)
    build_disassembler(config).disassemble_block(block_address, graph)
    return graph


def disassemble_graph(addresses: list[int] | set[int], config) -> Graph:
    graph = build_graph(config)
    build_disassembler(config).disassemble(set(addresses), graph)
    return graph


def current_function_address(address: int | None = None) -> int | None:
    current = ida_kernwin.get_screen_ea() if address is None else address
    function = ida_funcs.get_func(current)
    if function is None:
        return None
    return function.start_ea


def current_block_address(address: int | None = None) -> int | None:
    current = ida_kernwin.get_screen_ea() if address is None else address
    function = ida_funcs.get_func(current)
    if function is None:
        return None

    flowchart = idaapi.FlowChart(function)
    for block in flowchart:
        if block.start_ea <= current < block.end_ea:
            return block.start_ea
    return None
