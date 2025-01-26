import os
import re
import tempfile
import idapro
import idc
import ida_ida
import ida_nalt
import idaapi
import idautils
import ida_bytes
import ida_ua

from binlex_bindings.binlex.controlflow import (
	Graph,
)

from binlex_bindings.binlex.disassemblers.capstone import Disassembler as CapstoneDisassembler

from binlex_bindings.binlex.types import MemoryMappedFile

from binlex_bindings.binlex import (
	Architecture,
	Config,
)

from typing import List

class IDACommon():

	@staticmethod
	def architecture() -> Architecture:
		if ida_ida.inf_get_procname() == 'metapc':
			if ida_ida.inf_is_32bit_exactly():
				return Architecture.from_str('i386')
			return Architecture.from_str('amd64')

class IDAInstruction(IDACommon):
	def __init__(self, address: int):
		instruction = ida_ua.insn_t()
		ida_ua.decode_insn(instruction, address)
		self.instruction = instruction

	def address(self) -> int:
		return self.instruction.ea

	def size(self) -> int:
		return self.instruction.size

class IDABlock(IDACommon):
	def __init__(self, block):
		self.block = block

	def address(self) -> int:
		return self.block.start_ea

	def end(self) -> int:
		return self.block.end_ea

	def instructions(self) -> List[IDAInstruction]:
		instructions = []
		address = self.address()
		while address < self.end():
			instruction = IDAInstruction(address)
			instructions.append(instruction)
			address += instruction.size()
		return instructions

	def to(self) -> set:
		return set([self.address() for bb in self.block.succs()])

class IDAFunction(IDACommon):
	def __init__(self, address: int):
		self.function = idaapi.get_func(address)

	def address(self):
		return self.function.start_ea

	def blocks(self):
		return [IDABlock(block) for block in idaapi.FlowChart(self.function)]

	def name(self):
		return idc.get_func_name(self.address)

class IDA():
	def __init__(self):
		pass

	def processor(self) -> str | None:
		return ida_ida.inf_get_procname()

	def is_32bit(self) -> bool:
		return ida_ida.inf_is_32bit_exactly()

	def architecture(self) -> Architecture | None:
		if self.processor() == 'metapc':
			if self.is_32bit():
				return Architecture.from_str('i386')
			return Architecture.from_str('amd64')

	def sha256(self):
		return ida_nalt.retrieve_input_file_sha256().hex()

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
		return [IDAFunction(address) for address in idautils.Functions()]

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

	def open_database(self, path: str, run_auto_analysis: bool = True):
		idapro.open_database(path, run_auto_analysis=run_auto_analysis)

	def close_database(self):
		idapro.close_database()

	def image(self):
		directory = os.path.join(tempfile.gettempdir(), 'binlex')
		if not os.path.exists(directory): os.makedirs(directory)
		file_path = os.path.join(directory, IDA().sha256())
		mapped_file = MemoryMappedFile(file_path, False)
		for segment in idautils.Segments():
			start = idc.get_segm_start(segment)
			end = idc.get_segm_end(segment)
			data = ida_bytes.get_bytes(start, end - start)
			if data is None: continue
			if mapped_file.size() < start:
				mapped_file.seek_to_end()
				mapped_file.write_padding(start - mapped_file.size())
			mapped_file.seek_to_end()
			mapped_file.write(data)
		return mapped_file

class Disassembler():
	def __init__(self, architecture: Architecture, image: bytes, executable_virtual_address_ranges: dict, config: Config):
		self.architecture = architecture
		self.executable_virtual_address_ranges = executable_virtual_address_ranges
		self.config = config
		self.image = image
		self.disassembler = CapstoneDisassembler(
			self.architecture,
			self.image,
			self.executable_virtual_address_ranges,
			self.config
		)

	def disassemble_instruction(self, instruction: IDAInstruction, cfg: Graph):
		self.disassembler.disassemble_instruction(instruction.address(), cfg)

	def disassemble_block(self, block: IDABlock, cfg: Graph):
		for instruction in block.instructions():
			self.disassemble_instruction(instruction, cfg)
			if IDA().is_function_address(instruction.address()):
				cfg.set_function(instruction.address())
			if block.address() == instruction.address():
				cfg.set_block(instruction.address())
			if idc.prev_head(block.end()) == instruction.address():
				cfg.extend_instruction_edges(instruction.address(), block.to())

	def disassemble_function(self, function: IDAFunction, cfg: Graph):
		for block in function.blocks():
			self.disassemble_block(block, cfg)

	def disassemble_controlflow(self, cfg: Graph):
		for function in IDA().functions():
			self.disassemble_function(function, cfg)
