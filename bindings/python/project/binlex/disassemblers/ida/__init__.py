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

"""IDA Pro integration helpers for binlex disassembly workflows.

This module is import-safe outside IDA so documentation tooling can inspect the
package, but the runtime functionality requires the IDA Python environment.
"""

import os
import tempfile
from typing import Iterator, List

from binlex.controlflow import (
	Block as BinlexBlock,
	Function as BinlexFunction,
	Instruction as BinlexInstruction,
)
from binlex.core.magic import Magic

try:
	import idapro
	import idc
	import ida_ida
	import ida_nalt
	import idaapi
	import idautils
	import ida_bytes
	import ida_ua
	IDA_AVAILABLE = True
	IDA_IMPORT_ERROR = None
except ModuleNotFoundError as exc:
	idapro = None
	idc = None
	ida_ida = None
	ida_nalt = None
	idaapi = None
	idautils = None
	ida_bytes = None
	ida_ua = None
	IDA_AVAILABLE = False
	IDA_IMPORT_ERROR = exc

from binlex_bindings.binlex.controlflow import (
	Graph,
)

from binlex_bindings.binlex.disassemblers.capstone import Disassembler as CapstoneDisassembler

from binlex_bindings.binlex.formats import Image

from binlex_bindings.binlex import (
	Architecture,
	Config,
)


def _require_ida() -> None:
	if not IDA_AVAILABLE:
		raise RuntimeError(
			"The IDA disassembler integration requires the IDA Python runtime."
		) from IDA_IMPORT_ERROR


class UnsupportedInputFormatError(RuntimeError):
	"""Raised when a path is not an IDA database or supported executable."""


class UnsupportedArchitectureError(RuntimeError):
	"""Raised when IDA resolves to an architecture unsupported by this binding."""


class DatabaseLoadError(RuntimeError):
	"""Raised when IDA fails to open or load the requested input."""

class IDACommon():
	"""Shared helpers for objects backed by the active IDA database."""

	@staticmethod
	def architecture() -> Architecture:
		"""Return the current IDA processor as a binlex architecture."""
		_require_ida()
		if ida_ida.inf_get_procname() == 'metapc':
			if ida_ida.inf_is_32bit_exactly():
				return Architecture.from_str('i386')
			return Architecture.from_str('amd64')

class IDAInstruction(IDACommon):
	"""Lightweight view of an instruction decoded by IDA."""

	def __init__(self, address: int):
		"""Decode the instruction located at `address`."""
		_require_ida()
		instruction = ida_ua.insn_t()
		ida_ua.decode_insn(instruction, address)
		self.instruction = instruction
		self._cfg = None

	def address(self) -> int:
		return self.instruction.ea

	def size(self) -> int:
		return self.instruction.size

	def bind(self, cfg):
		self._cfg = cfg
		return self

	def _graph_instruction(self):
		if self._cfg is None:
			raise RuntimeError(
				"IDAInstruction is not bound to a Binlex graph; disassemble it first."
			)
		return BinlexInstruction(self.address(), self._cfg)

	def chromosome(self):
		return self._graph_instruction().chromosome()

	def blocks(self):
		return self._graph_instruction().blocks()

	def next(self):
		return self._graph_instruction().next()

	def to(self):
		return self._graph_instruction().to()

	def has_indirect_target(self):
		return self._graph_instruction().has_indirect_target()

	def functions(self):
		return self._graph_instruction().functions()

	def processors(self):
		return self._graph_instruction().processors()

	def processor(self, name):
		return self._graph_instruction().processor(name)

	def to_dict(self):
		return self._graph_instruction().to_dict()

	def json(self):
		return self._graph_instruction().json()

class IDABlock(IDACommon):
	"""Basic-block wrapper exposing IDA flow-chart information."""

	def __init__(self, block):
		"""Wrap an IDA basic block object."""
		_require_ida()
		self.block = block
		self._cfg = None

	def address(self) -> int:
		return self.block.start_ea

	def end(self) -> int:
		return self.block.end_ea

	def instructions_iter(self) -> Iterator[IDAInstruction]:
		address = self.address()
		while address < self.end():
			instruction = IDAInstruction(address).bind(self._cfg)
			if instruction.size() <= 0:
				break
			yield instruction
			address += instruction.size()

	def instructions(self) -> List[IDAInstruction]:
		return list(self.instructions_iter())

	def to(self) -> set:
		return {bb.start_ea for bb in self.block.succs()}

	def bind(self, cfg):
		self._cfg = cfg
		return self

	def _graph_block(self):
		if self._cfg is None:
			raise RuntimeError(
				"IDABlock is not bound to a Binlex graph; disassemble it first."
			)
		return BinlexBlock(self.address(), self._cfg)

	def architecture(self):
		return self._graph_block().architecture()

	def chromosome(self):
		return self._graph_block().chromosome()

	def bytes(self):
		return self._graph_block().bytes()

	def prologue(self):
		return self._graph_block().prologue()

	def edges(self):
		return self._graph_block().edges()

	def next(self):
		return self._graph_block().next()

	def entropy(self):
		return self._graph_block().entropy()

	def blocks(self):
		return self._graph_block().blocks()

	def number_of_instructions(self):
		return self._graph_block().number_of_instructions()

	def functions(self):
		return self._graph_block().functions()

	def processors(self):
		return self._graph_block().processors()

	def processor(self, name):
		return self._graph_block().processor(name)

	def tlsh(self):
		return self._graph_block().tlsh()

	def sha256(self):
		return self._graph_block().sha256()

	def minhash(self):
		return self._graph_block().minhash()

	def size(self):
		return self._graph_block().size()

	def to_dict(self):
		return self._graph_block().to_dict()

	def json(self):
		return self._graph_block().json()

class IDAFunction(IDACommon):
	"""Function wrapper backed by IDA's database model."""

	def __init__(self, address: int):
		"""Look up and wrap the function containing `address`."""
		_require_ida()
		self.function = idaapi.get_func(address)
		self._cfg = None

	def address(self):
		return self.function.start_ea

	def bind(self, cfg):
		self._cfg = cfg
		return self

	def _graph_function(self):
		if self._cfg is None:
			raise RuntimeError(
				"IDAFunction is not bound to a Binlex graph; disassemble it first."
			)
		return BinlexFunction(self.address(), self._cfg)

	def blocks(self):
		return [IDABlock(block).bind(self._cfg) for block in idaapi.FlowChart(self.function)]

	def name(self):
		return idc.get_func_name(self.address())

	def architecture(self):
		return self._graph_function().architecture()

	def chromosome(self):
		return self._graph_function().chromosome()

	def cyclomatic_complexity(self):
		return self._graph_function().cyclomatic_complexity()

	def average_instructions_per_block(self):
		return self._graph_function().average_instructions_per_block()

	def bytes(self):
		return self._graph_function().bytes()

	def entropy(self):
		return self._graph_function().entropy()

	def number_of_instructions(self):
		return self._graph_function().number_of_instructions()

	def number_of_blocks(self):
		return self._graph_function().number_of_blocks()

	def tlsh(self):
		return self._graph_function().tlsh()

	def sha256(self):
		return self._graph_function().sha256()

	def minhash(self):
		return self._graph_function().minhash()

	def size(self):
		return self._graph_function().size()

	def contiguous(self):
		return self._graph_function().contiguous()

	def end(self):
		return self._graph_function().end()

	def to_dict(self):
		return self._graph_function().to_dict()

	def json(self):
		return self._graph_function().json()

class IDA():
	"""High-level helpers for interrogating the active IDA session."""

	SUPPORTED_MAGIC = {Magic.PE, Magic.ELF, Magic.MACHO}
	DATABASE_SUFFIXES = {".i64", ".idb"}

	def __init__(self, path: str | None = None, run_auto_analysis: bool = True):
		_require_ida()
		self._database_open = False
		self._owns_database = False
		self._processor = None
		self._architecture = None
		self._sha256 = None
		self._functions = None
		self._segments = None
		self._blocks = None
		self._instructions = None
		if path is not None:
			self.open(path, run_auto_analysis=run_auto_analysis)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, traceback):
		self.close()
		return False

	def _invalidate_caches(self):
		self._processor = None
		self._architecture = None
		self._sha256 = None
		self._functions = None
		self._segments = None
		self._blocks = None
		self._instructions = None

	@classmethod
	def _is_database_path(cls, path: str) -> bool:
		return os.path.splitext(path)[1].lower() in cls.DATABASE_SUFFIXES

	def _validate_input_path(self, path: str):
		if self._is_database_path(path):
			return
		magic = Magic.from_file(path)
		if magic not in self.SUPPORTED_MAGIC:
			raise UnsupportedInputFormatError(
				f"unsupported input format for IDA disassembly: {path} ({magic.value})"
			)

	def _validate_loaded_architecture(self):
		architecture = self.architecture()
		if architecture is None:
			raise UnsupportedArchitectureError(
				f"unsupported IDA processor for binlex.disassemblers.ida: {self.processor()}"
			)
		return architecture

	def load(self, path: str, run_auto_analysis: bool = True):
		self._validate_input_path(path)
		result = idapro.open_database(path, run_auto_analysis=run_auto_analysis)
		if result not in (0, None):
			raise DatabaseLoadError(f"failed to load input into IDA: {path}")
		self._database_open = True
		self._owns_database = True
		self._invalidate_caches()
		try:
			self._validate_loaded_architecture()
		except Exception:
			self.close()
			raise
		return self

	def open(self, path: str, run_auto_analysis: bool = True):
		return self.load(path, run_auto_analysis=run_auto_analysis)

	def processor(self) -> str | None:
		if self._processor is None:
			self._processor = ida_ida.inf_get_procname()
		return self._processor

	def is_32bit(self) -> bool:
		return ida_ida.inf_is_32bit_exactly()

	def architecture(self) -> Architecture | None:
		if self._architecture is not None:
			return self._architecture
		if self.processor() == 'metapc':
			if self.is_32bit():
				self._architecture = Architecture.from_str('i386')
			else:
				self._architecture = Architecture.from_str('amd64')
		return self._architecture

	def sha256(self):
		if self._sha256 is None:
			self._sha256 = ida_nalt.retrieve_input_file_sha256().hex()
		return self._sha256

	@staticmethod
	def attribute_symbol(address: int):
		attribute = {}
		attribute['type'] = 'symbol'
		attribute['symbol_type'] = 'function'
		attribute['file_offset'] = None
		attribute['relative_virtual_address'] = None
		attribute['virtual_address'] = address
		attribute['name'] = idc.get_func_name(address)
		attribute['slice'] = None
		return attribute

	def functions(self) -> list:
		if self._functions is None:
			self._functions = [IDAFunction(address) for address in idautils.Functions()]
		return self._functions

	def function(self, address: int):
		function = idaapi.get_func(address)
		if function is None:
			return None
		return IDAFunction(function.start_ea)

	def block(self, address: int):
		function = idaapi.get_func(address)
		if function is None:
			return None
		for block in idaapi.FlowChart(function):
			if block.start_ea <= address < block.end_ea:
				return IDABlock(block)
		return None

	def blocks(self) -> list[IDABlock]:
		if self._blocks is None:
			seen = set()
			blocks = []
			for function in self.functions():
				for block in function.blocks():
					if block.address() in seen:
						continue
					seen.add(block.address())
					blocks.append(block)
			self._blocks = blocks
		return self._blocks

	def instruction(self, address: int):
		if not idc.is_code(idc.get_full_flags(address)):
			return None
		return IDAInstruction(address)

	def instructions(self) -> list[IDAInstruction]:
		if self._instructions is None:
			seen = set()
			instructions = []
			for block in self.blocks():
				for instruction in block.instructions():
					if instruction.address() in seen:
						continue
					seen.add(instruction.address())
					instructions.append(instruction)
			self._instructions = instructions
		return self._instructions

	def segment_ranges(self) -> list[dict]:
		if self._segments is not None:
			return self._segments
		segments = []
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
		self._segments = segments
		return self._segments

	def virtual_address_ranges(self) -> dict[int, int]:
		return {
			segment["start"]: segment["end"]
			for segment in self.segment_ranges()
		}

	def executable_virtual_address_ranges(self) -> dict[int, int]:
		return {
			segment["start"]: segment["end"]
			for segment in self.segment_ranges()
			if segment["executable"]
		}

	def is_function_address(self, address: int) -> bool:
		function = idaapi.get_func(address)
		if function is None: return False
		return function.start_ea == address

	def attributes(self, address: int) -> List[dict]:
		attributes = [self.attribute_file()]
		if self.is_function_address(address):
			attributes.append(self.attribute_symbol(address))
		return attributes

	def attribute_file(self):
		return {
            'type': 'file',
            'sha256': self.sha256(),
            'tlsh': None,
            'size': None,
            'entropy': None,
        }

	def close(self):
		if self._database_open and self._owns_database:
			idapro.close_database()
		self._database_open = False
		self._owns_database = False
		self._invalidate_caches()

	def image(self):
		directory = os.path.join(tempfile.gettempdir(), 'binlex')
		if not os.path.exists(directory): os.makedirs(directory)
		file_path = os.path.join(directory, self.sha256())
		mapped_file = Image(file_path, False)
		for segment in self.segment_ranges():
			start = segment["start"]
			end = segment["end"]
			data = ida_bytes.get_bytes(start, end - start)
			if data is None: continue
			if mapped_file.size() < start:
				mapped_file.seek_to_end()
				mapped_file.write_padding(start - mapped_file.size())
			mapped_file.seek_to_end()
			mapped_file.write(data)
		return mapped_file

	def graph(self, config: Config) -> Graph:
		architecture = self.architecture()
		if architecture is None:
			raise RuntimeError("unsupported IDA processor for Binlex graph creation")
		return Graph(architecture, config)

	def disassembler(self, config: Config):
		architecture = self.architecture()
		if architecture is None:
			raise RuntimeError("unsupported IDA processor for Binlex disassembly")
		return Disassembler(
			architecture,
			self.image(),
			self.executable_virtual_address_ranges(),
			config,
		)

	def disassemble(self, config: Config, cfg: Graph | None = None) -> Graph:
		if cfg is None:
			cfg = self.graph(config)
		self.disassembler(config).disassemble(cfg)
		return cfg

	def disassemble_function(self, address: int, config: Config, cfg: Graph | None = None):
		function = self.function(address)
		if function is None:
			return None
		if cfg is None:
			cfg = self.graph(config)
		self.disassembler(config).disassemble_function(function, cfg)
		return function

class Disassembler():
	"""Bridge IDA database objects into binlex control-flow structures."""

	def __init__(self, architecture: Architecture, image: Image | bytes, executable_virtual_address_ranges: dict, config: Config):
		"""Create a disassembler that uses IDA for traversal and Capstone for decode."""
		_require_ida()
		self.ida = IDA()
		self.architecture = architecture
		mapped_ranges = self.ida.virtual_address_ranges()
		self.executable_virtual_address_ranges = dict(mapped_ranges)
		self.executable_virtual_address_ranges.update(executable_virtual_address_ranges)
		self.config = config
		self.image = image.mmap() if isinstance(image, Image) else image
		self.disassembler = CapstoneDisassembler(
			self.architecture,
			self.image,
			self.executable_virtual_address_ranges,
			self.config
		)

	def disassemble_instruction(self, instruction: IDAInstruction, cfg: Graph):
		"""Disassemble a decoded IDA instruction into the graph."""
		instruction.bind(cfg)
		self.disassembler.disassemble_instruction(instruction.address(), cfg)

	def disassemble_block(self, block: IDABlock, cfg: Graph):
		"""Disassemble every instruction in an IDA basic block."""
		block.bind(cfg)
		last_instruction_address = None
		for instruction in block.instructions_iter():
			self.disassemble_instruction(instruction, cfg)
			if self.ida.is_function_address(instruction.address()):
				cfg.set_function(instruction.address())
			if block.address() == instruction.address():
				cfg.set_block(instruction.address())
			last_instruction_address = instruction.address()
		if last_instruction_address is not None:
			cfg.extend_instruction_edges(last_instruction_address, block.to())

	def disassemble_function(self, function: IDAFunction, cfg: Graph):
		"""Disassemble every block in an IDA function."""
		function.bind(cfg)
		cfg.set_function(function.address())
		for block in function.blocks():
			self.disassemble_block(block, cfg)

	def disassemble(self, cfg: Graph):
		"""Disassemble all functions discovered in the open IDA database."""
		for function in self.ida.functions():
			self.disassemble_function(function, cfg)
