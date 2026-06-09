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

"""Control-flow graph wrappers for instructions, blocks, and functions."""

from binlex_bindings.binlex.controlflow import Block as _BlockBinding
from binlex_bindings.binlex.controlflow import EntityKind as _EntityKindBinding
from binlex_bindings.binlex.controlflow import Function as _FunctionBinding
from binlex_bindings.binlex.controlflow import Graph as _GraphBinding
from binlex_bindings.binlex.controlflow import GraphQueue as _GraphQueueBinding
from binlex_bindings.binlex.controlflow import GraphState as GraphState
from binlex_bindings.binlex.controlflow import Instruction as _InstructionBinding
from binlex_bindings.binlex.controlflow import Reference as _ReferenceBinding
from binlex_bindings.binlex.controlflow.instruction import Operand as Operand
from binlex_bindings.binlex.controlflow.instruction import OperandKind as OperandKind

from binlex.core.architecture import _coerce_architecture
from binlex.formats import Image
from binlex.hashing import MinHash32, SHA256, SSDeep, TLSH
from binlex.irs.hir import HirFunction
from binlex.irs.lir import Lir, LirBlock, LirFunction
from binlex.irs.mir import MirBlock, MirFunction

EntityKind = _EntityKindBinding

def _decompiler_symbol_map(graph):
    if graph is None:
        return {}
    return graph.symbols()


def _symbol_metadata(symbol):
    if isinstance(symbol, dict):
        name = symbol.get("name")
        virtual_address = symbol.get("virtual_address")
        file_offset = symbol.get("file_offset", 0)
        relative_virtual_address = symbol.get("relative_virtual_address")
        kind = symbol.get("kind", "unknown")
    else:
        name = symbol.name()
        virtual_address = symbol.virtual_address()
        file_offset = symbol.file_offset()
        relative_virtual_address = symbol.relative_virtual_address()
        kind = str(symbol.kind())

    if virtual_address is None or not name:
        return None

    result = {
        "name": str(name),
        "file_offset": int(file_offset or 0),
        "virtual_address": int(virtual_address),
        "kind": str(kind),
    }
    if relative_virtual_address is not None:
        result["relative_virtual_address"] = int(relative_virtual_address)
    return result


def _coerce_symbol_metadata(symbols):
    if isinstance(symbols, dict):
        result = []
        for virtual_address, value in symbols.items():
            if isinstance(value, dict):
                symbol = dict(value)
                symbol.setdefault("virtual_address", virtual_address)
            else:
                symbol = {"virtual_address": virtual_address, "name": value}
            symbol = _symbol_metadata(symbol)
            if symbol is not None:
                result.append(symbol)
        return result

    result = []
    for symbol in symbols or []:
        try:
            symbol = _symbol_metadata(symbol)
        except Exception:
            continue
        if symbol is not None:
            result.append(symbol)
    return result


def _coerce_metadata(metadata):
    if metadata is None:
        return {}
    if isinstance(metadata, dict):
        return dict(metadata)
    return {"symbols": _coerce_symbol_metadata(metadata)}


def _const_u64_value(expression):
    if not isinstance(expression, dict) or "Const" not in expression:
        return None
    value = expression["Const"].get("value")
    try:
        return int(value)
    except Exception:
        return None


def _read_register_name(expression):
    if not isinstance(expression, dict) or "Read" not in expression:
        return None
    read = expression["Read"]
    if not isinstance(read, dict) or "Register" not in read:
        return None
    return read["Register"].get("name")


def _resolve_indirect_symbol_address(instruction_dict, expression, register_map, depth=0):
    if depth > 4 or not isinstance(expression, dict):
        return None

    if "Binary" in expression:
        binary = expression["Binary"]
        if (
            isinstance(binary, dict)
            and binary.get("op") == "Add"
            and _read_register_name(binary.get("left")) in {"rip", "eip"}
        ):
            displacement = _const_u64_value(binary.get("right"))
            encoding = instruction_dict.get("encoding") or {}
            base = encoding.get("address")
            size = len(encoding.get("bytes") or [])
            if displacement is not None and base is not None:
                return int(base) + int(size) + displacement

    register_name = _read_register_name(expression)
    if register_name and register_map:
        aliased = register_map.get(register_name)
        if isinstance(aliased, dict):
            return _resolve_indirect_symbol_address(
                instruction_dict, aliased, register_map, depth + 1
            )

    return _const_u64_value(expression)


def _resolve_indirect_symbol_name(
    instruction_dict, target_dict, symbol_map, register_map=None, depth=0
):
    if depth > 4 or not symbol_map or not isinstance(target_dict, dict):
        return None

    register_name = _read_register_name(target_dict)
    if register_name and register_map:
        aliased = register_map.get(register_name)
        if isinstance(aliased, dict):
            return _resolve_indirect_symbol_name(
                instruction_dict, aliased, symbol_map, register_map, depth + 1
            )

    load = target_dict.get("Load")
    if not isinstance(load, dict):
        return None

    bits = load.get("bits", 64)
    space = load.get("space")
    addr = load.get("addr")

    address = None
    if space == "Default":
        address = _resolve_indirect_symbol_address(
            instruction_dict, addr, register_map or {}
        )

    if address is None:
        return None

    symbol_name = symbol_map.get(address)
    if not symbol_name:
        return None

    return {"Function": {"name": symbol_name, "bits": bits}}


class Instruction:
    """Single decoded instruction tracked inside a control-flow graph."""

    def __init__(self, address, cfg):
        """Look up the instruction at `address` within the provided graph."""
        self._inner = _InstructionBinding(address, cfg._inner)
        self._config = cfg._config
        self._graph = cfg

    @classmethod
    def _from_binding(cls, binding, config=None, graph=None):
        """Wrap an existing native instruction binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        result._graph = graph
        return result

    def address(self):
        """Return the instruction address."""
        return self._inner.address()

    def kind(self):
        """Return the controlflow entity kind for this instruction."""
        return self._inner.kind()

    def chromosome(self):
        """Return the chromosome derived from this instruction, if available."""
        return self._inner.chromosome()

    def successor_blocks(self):
        """Return the successor blocks reached by this instruction."""
        return [Block._from_binding(item, self._config) for item in self._inner.successor_blocks()]

    def successor_block_references(self):
        """Return the outgoing successor block references."""
        return [Reference._from_binding(item) for item in self._inner.successor_block_references()]

    def fallthrough(self):
        """Return the sequential fallthrough instruction address, if known."""
        return self._inner.fallthrough()

    def branches(self):
        """Return the explicit branch target addresses for this instruction."""
        return self._inner.branches()

    def successors(self):
        """Return all outgoing CFG successor addresses for this instruction."""
        return self._inner.successors()

    def has_indirect_target(self):
        """Return whether this instruction branches to an indirect target."""
        return self._inner.has_indirect_target()

    def is_conditional(self):
        """Return whether this instruction is conditional."""
        return self._inner.is_conditional()

    def callees(self):
        """Return the directly called functions."""
        return [Function._from_binding(item, self._config) for item in self._inner.callees()]

    def callee_references(self):
        """Return the direct outgoing call references."""
        return [Reference._from_binding(item) for item in self._inner.callee_references()]

    def size(self):
        """Return the instruction size in bytes."""
        return self._inner.size()

    def bytes(self):
        """Return the decoded raw bytes for this instruction."""
        return self._inner.bytes()

    def mnemonic(self):
        """Return the decoded mnemonic of the instruction."""
        return self._inner.mnemonic()

    def disassembly(self):
        """Return the canonical disassembly text of the instruction."""
        return self._inner.disassembly()

    def operands(self):
        """Return normalized decoded operands."""
        return self._inner.operands()

    def embedding(self, backend=None, dimensions=None):
        """Return an embedding vector for this instruction, if available."""
        from binlex.embeddings import Embedding, EmbeddingBackend

        if self._config is None:
            return None
        backend = EmbeddingBackend.DEFAULT if backend is None else backend
        dimensions = 64 if dimensions is None else dimensions
        return Embedding(
            self.architecture(),
            self._config,
            backend=backend,
            dimensions=dimensions,
        ).embed_instruction(self)

    def llvm(self):
        """Return LLVM IR for this instruction."""
        from binlex.irs.llvm import LlvmModule

        return LlvmModule._with_inner(None, None, self._config, self._inner.llvm())

    def vex(self):
        """Return VEX IR for this instruction."""
        from binlex.irs.vex import VexModule

        return VexModule._from_inner(self._inner.vex(), self._config)

    def lir(self):
        """Return canonical LIR for this instruction, if present."""
        lir = self._inner.lir()
        if lir is None:
            return None
        return Lir._from_inner(lir)

    def set_lir(self, lir):
        """Replace the canonical LIR for this instruction inside the graph."""
        inner = getattr(lir, "_inner", lir)
        self._inner.set_lir(inner)
        return self

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


class Block:
    """Basic block wrapper backed by the native control-flow engine."""

    def __init__(self, address, cfg):
        """Look up the block that starts at `address` within the provided graph."""
        self._inner = _BlockBinding(address, cfg._inner)
        self._config = cfg._config
        self._graph = cfg

    @classmethod
    def _from_binding(cls, binding, config=None, graph=None):
        """Wrap an existing native block binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        result._graph = graph
        return result

    def address(self):
        """Return the starting address of the block."""
        return self._inner.address()

    def kind(self):
        """Return the controlflow entity kind for this block."""
        return self._inner.kind()

    def architecture(self):
        """Return the architecture associated with this block."""
        return self._inner.architecture()

    def chromosome(self):
        """Return the chromosome derived from this block, if available."""
        return self._inner.chromosome()

    def instructions(self):
        """Return the instructions contained in this block."""
        return [Instruction._from_binding(item, self._config, self._graph) for item in self._inner.instructions()]

    def bytes(self):
        """Return the raw bytes for this block."""
        return self._inner.bytes()

    def prologue(self):
        """Return whether this block looks like a function prologue."""
        return self._inner.prologue()

    def edges(self):
        """Return the number of outgoing edges from this block."""
        return self._inner.edges()

    def fallthrough(self):
        """Return the sequential fallthrough address after this block, if available."""
        return self._inner.fallthrough()

    def branches(self):
        """Return the explicit branch target addresses targeted by this block."""
        return self._inner.branches()

    def entropy(self):
        """Return the entropy of this block, if available."""
        return self._inner.entropy()

    def successors(self):
        """Return the blocks directly reached from this block."""
        return [Block._from_binding(item, self._config, self._graph) for item in self._inner.successors()]

    def predecessors(self):
        """Return the blocks that directly reach this block."""
        return [Block._from_binding(item, self._config, self._graph) for item in self._inner.predecessors()]

    def successor_references(self):
        """Return direct outgoing control-flow references for this block."""
        return [Reference._from_binding(item) for item in self._inner.successor_references()]

    def predecessor_references(self):
        """Return direct incoming control-flow references for this block."""
        return [Reference._from_binding(item) for item in self._inner.predecessor_references()]

    def number_of_instructions(self):
        """Return the number of instructions contained in this block."""
        return self._inner.number_of_instructions()

    def callees(self):
        """Return the functions directly called from this block."""
        return [Function._from_binding(item, self._config, self._graph) for item in self._inner.callees()]

    def callee_references(self):
        """Return direct outgoing call references for this block."""
        return [Reference._from_binding(item) for item in self._inner.callee_references()]

    def embedding(self, backend=None, dimensions=None):
        """Return an embedding vector for this block, if available."""
        from binlex.embeddings import Embedding, EmbeddingBackend

        if self._config is None:
            return None
        backend = EmbeddingBackend.DEFAULT if backend is None else backend
        dimensions = 64 if dimensions is None else dimensions
        return Embedding(
            self.architecture(),
            self._config,
            backend=backend,
            dimensions=dimensions,
        ).embed_block(self)

    def llvm(self):
        """Return LLVM IR for this block."""
        from binlex.irs.llvm import LlvmModule

        return LlvmModule._with_inner(None, None, self._config, self._inner.llvm())

    def vex(self):
        """Return VEX IR for this block."""
        from binlex.irs.vex import VexModule

        return VexModule._from_inner(self._inner.vex(), self._config)

    def lir(self):
        """Return canonical LIR for this block."""
        return LirBlock._from_inner(self._inner.lir())

    def mir(self):
        """Return optimized MIR for this block."""
        return self._inner.mir()

    def tlsh(self):
        """Return the TLSH object for this block, if available."""
        return self._inner.tlsh()

    def sha256(self):
        """Return the SHA-256 object for this block, if available."""
        return self._inner.sha256()

    def minhash(self):
        """Return the MinHash object for this block, if available."""
        return self._inner.minhash()

    def ssdeep(self):
        """Return the ssdeep object for this block, if available."""
        return self._inner.ssdeep()

    def end(self):
        """Return the ending address of this block."""
        return self._inner.end()

    def size(self):
        """Return the size of this block in bytes."""
        return self._inner.size()

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


class FunctionCallee:
    """A direct outgoing call relationship from a function."""

    @classmethod
    def _from_binding(cls, binding, config=None, graph=None):
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        result._graph = graph
        return result

    def address(self):
        """Return the callsite address."""
        return self._inner.address()

    def function(self):
        """Return the function targeted by the callsite."""
        return Function._from_binding(self._inner.function(), self._config, self._graph)

    def __str__(self):
        return str(self._inner)


class FunctionCaller:
    """A direct incoming call relationship into a function."""

    @classmethod
    def _from_binding(cls, binding, config=None, graph=None):
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        result._graph = graph
        return result

    def address(self):
        """Return the callsite address."""
        return self._inner.address()

    def function(self):
        """Return the function containing the callsite."""
        return Function._from_binding(self._inner.function(), self._config, self._graph)

    def __str__(self):
        return str(self._inner)


class Function:
    """Function wrapper backed by the native control-flow engine."""

    def __init__(self, address, cfg):
        """Look up the function that starts at `address` within the provided graph."""
        self._inner = _FunctionBinding(address, cfg._inner)
        self._config = cfg._config
        self._graph = cfg

    @classmethod
    def _from_binding(cls, binding, config=None, graph=None):
        """Wrap an existing native function binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        result._graph = graph
        return result

    def address(self):
        """Return the starting address of the function."""
        return self._inner.address()

    def kind(self):
        """Return the controlflow entity kind for this function."""
        return self._inner.kind()

    def architecture(self):
        """Return the architecture associated with this function."""
        return self._inner.architecture()

    def chromosome(self):
        """Return the chromosome derived from this function, if available."""
        return self._inner.chromosome()

    def cyclomatic_complexity(self):
        """Return the cyclomatic complexity of the function."""
        return self._inner.cyclomatic_complexity()

    def average_instructions_per_block(self):
        """Return the average number of instructions per basic block."""
        return self._inner.average_instructions_per_block()

    def blocks(self):
        """Return the basic blocks contained in this function."""
        return [Block._from_binding(item, self._config, self._graph) for item in self._inner.blocks()]

    def bytes(self):
        """Return the raw bytes for this function, if available."""
        return self._inner.bytes()

    def prologue(self):
        """Return whether this function starts with a prologue."""
        return self._inner.prologue()

    def edges(self):
        """Return the number of edges in the function graph."""
        return self._inner.edges()

    def entropy(self):
        """Return the entropy of this function, if available."""
        return self._inner.entropy()

    def number_of_instructions(self):
        """Return the number of instructions in this function."""
        return self._inner.number_of_instructions()

    def number_of_blocks(self):
        """Return the number of basic blocks in this function."""
        return self._inner.number_of_blocks()

    def callees(self):
        """Return direct outgoing call relationships."""
        return [FunctionCallee._from_binding(item, self._config, self._graph) for item in self._inner.callees()]

    def callers(self):
        """Return direct incoming call relationships."""
        return [FunctionCaller._from_binding(item, self._config, self._graph) for item in self._inner.callers()]

    def embedding(self, backend=None, dimensions=None):
        """Return an embedding vector for this function, if available."""
        from binlex.embeddings import Embedding, EmbeddingBackend

        if self._config is None:
            return None
        backend = EmbeddingBackend.DEFAULT if backend is None else backend
        dimensions = 64 if dimensions is None else dimensions
        return Embedding(
            self.architecture(),
            self._config,
            backend=backend,
            dimensions=dimensions,
        ).embed_function(self)

    def llvm(self):
        """Return LLVM IR for this function."""
        from binlex.irs.llvm import LlvmModule

        return LlvmModule._with_inner(None, None, self._config, self._inner.llvm())

    def vex(self):
        """Return VEX IR for this function."""
        from binlex.irs.vex import VexModule

        return VexModule._from_inner(self._inner.vex(), self._config)

    def lir(self):
        """Return raw LIR for this function."""
        result = LirFunction._from_inner(self._inner.lir())
        return result

    def mir(self):
        """Return raw MIR for this function."""
        result = MirFunction._from_inner(self._inner.mir())
        return result

    def hir(self):
        """Return raw HIR for this function."""
        result = HirFunction._from_inner(self._inner.hir())
        return result

    def ast(self):
        """Return AST for this function."""
        from binlex.irs.ast import AstFunction

        result = AstFunction._from_inner(self._inner.ast())
        return result

    def tlsh(self):
        """Return the TLSH object for this function, if available."""
        return self._inner.tlsh()

    def sha256(self):
        """Return the SHA-256 object for this function, if available."""
        return self._inner.sha256()

    def minhash(self):
        """Return the MinHash object for this function, if available."""
        return self._inner.minhash()

    def ssdeep(self):
        """Return the ssdeep object for this function, if available."""
        return self._inner.ssdeep()

    def markov(self):
        """Return normalized Markov importance scores for each block."""
        return self._inner.markov()

    def size(self):
        """Return the size of this function in bytes."""
        return self._inner.size()

    def contiguous(self):
        """Return whether the function occupies a contiguous address range."""
        return self._inner.contiguous()

    def end(self):
        """Return the ending address of this function, if available."""
        return self._inner.end()

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


class _LLVM:
    """Small builder for entity-bound LLVM rendering."""

    def __init__(self, owner, mode=None):
        self._owner = owner
        self._mode = mode

    def reconstruct(self):
        return self.__class__(self._owner, mode="reconstruct")

    def intrinsic(self):
        return self.__class__(self._owner, mode="intrinsic")

    def lir(self):
        return self.__class__(self._owner, mode="lir")

    def text(self):
        module = self._lift()
        return module.text()

    def print(self):
        module = self._lift()
        return module.print()

    def bitcode(self):
        module = self._lift()
        return module.bitcode()

    def object(self):
        module = self._lift()
        return module.object()

    def optimize_mem2reg(self):
        lifter = self._lift()
        return lifter.optimize_mem2reg()

    def optimize_instcombine(self):
        lifter = self._lift()
        return lifter.optimize_instcombine()

    def optimize_cfg(self):
        lifter = self._lift()
        return lifter.optimize_cfg()

    def optimize_gvn(self):
        lifter = self._lift()
        return lifter.optimize_gvn()

    def optimize_sroa(self):
        lifter = self._lift()
        return lifter.optimize_sroa()

    def optimize_dce(self):
        lifter = self._lift()
        return lifter.optimize_dce()

    def verify(self):
        lifter = self._lift()
        return lifter.verify()

    def _lift(self):
        if self._mode is not None:
            raise RuntimeError("llvm mode-specific conversion must be configured before graph conversion")
        module = self._owner.llvm()
        if module is None:
            raise RuntimeError("llvm lift failed")
        return module


class Reference:
    """Lightweight relationship from a source location to a target address."""

    def __init__(self, location, address):
        self._inner = _ReferenceBinding(location, address)

    @classmethod
    def _from_binding(cls, binding):
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def location(self):
        return self._inner.location()

    def address(self):
        return self._inner.address()

    def __str__(self):
        return str(self._inner)


class GraphQueue:
    """Queue wrapper used to track discovery and processing state in a graph."""

    def __init__(self, inner):
        """Wrap a native graph queue returned by a `Graph` instance."""
        self._inner = inner

    def insert_invalid(self, address):
        """Mark an address as invalid for this queue."""
        return self._inner.insert_invalid(address)

    def is_invalid(self, address):
        """Return whether an address is marked invalid."""
        return self._inner.is_invalid(address)

    def valid_addresses(self):
        """Return all addresses currently marked valid."""
        return self._inner.valid_addresses()

    def invalid_addresses(self):
        """Return all addresses currently marked invalid."""
        return self._inner.invalid_addresses()

    def processed_addresses(self):
        """Return all addresses already processed by this queue."""
        return self._inner.processed_addresses()

    def is_valid(self, address):
        """Return whether an address is marked valid."""
        return self._inner.is_valid(address)

    def insert_valid(self, address):
        """Mark an address as valid for future processing."""
        return self._inner.insert_valid(address)

    def insert_processed_extend(self, addresses):
        """Mark a set of addresses as processed."""
        return self._inner.insert_processed_extend(addresses)

    def insert_processed(self, address):
        """Mark a single address as processed."""
        return self._inner.insert_processed(address)

    def is_processed(self, address):
        """Return whether an address has already been processed."""
        return self._inner.is_processed(address)

    def enqueue_extend(self, addresses):
        """Enqueue a set of addresses for later processing."""
        return self._inner.enqueue_extend(addresses)

    def enqueue(self, address):
        """Enqueue a single address for later processing."""
        return self._inner.enqueue(address)

    def dequeue(self):
        """Dequeue the next pending address, if one exists."""
        return self._inner.dequeue()

    def dequeue_all(self):
        """Dequeue and return all pending addresses."""
        return self._inner.dequeue_all()


class Graph:
    """Mutable control-flow graph wrapper backed by the Rust implementation."""

    def __init__(self, architecture, image, config, metadata=None):
        """Create a graph for the given architecture, image, and configuration."""
        if not isinstance(image, Image):
            raise TypeError("graph image must be a binlex.formats.Image")
        self._inner = _GraphBinding(
            _coerce_architecture(architecture),
            image._inner,
            config,
            _coerce_metadata(metadata),
        )
        self._config = config
        self._image = image
        self._architecture = architecture
        self._decompiler = None

    @classmethod
    def _from_binding(cls, binding, config=None):
        """Wrap an existing native graph binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        inner_image = binding.image()
        result._image = Image._from_binding(inner_image) if inner_image is not None else None
        result._architecture = binding.architecture()
        result._decompiler = None
        return result

    @classmethod
    def from_state(cls, state):
        """Restore a graph from a complete serializable graph state."""
        result = cls._from_binding(_GraphBinding.from_state(state))
        result._config = result._inner.configuration()
        return result

    def state(self):
        """Return a complete serializable graph state."""
        return self._inner.state()

    def __getstate__(self):
        return self.state()

    def __setstate__(self, state):
        restored = Graph.from_state(state)
        self.__dict__.update(restored.__dict__)

    def architecture(self):
        """Return the graph architecture."""
        return self._inner.architecture()

    def image(self):
        """Return the graph-owned image."""
        if self._image is not None:
            return self._image
        inner_image = self._inner.image()
        if inner_image is None:
            return None
        self._image = Image._from_binding(inner_image)
        return self._image

    def configuration(self):
        """Return the graph configuration."""
        return self._config

    def executable_virtual_address_ranges(self):
        """Return executable ranges derived from the graph image."""
        return dict(self._inner.executable_virtual_address_ranges())

    def instructions(self):
        """Return all instructions currently tracked by the graph."""
        return [Instruction._from_binding(item, self._config, self) for item in self._inner.instructions()]

    def blocks(self):
        """Return all blocks currently tracked by the graph."""
        return [Block._from_binding(item, self._config, self) for item in self._inner.blocks()]

    def functions(self):
        """Return all functions currently tracked by the graph."""
        return [Function._from_binding(item, self._config, self) for item in self._inner.functions()]

    def instruction(self, address):
        """Return the instruction at `address`, if it exists."""
        result = self._inner.instruction(address)
        if result is None:
            return None
        return Instruction._from_binding(result, self._config, self)

    def block(self, address):
        """Return the block at `address`, if it exists."""
        result = self._inner.block(address)
        if result is None:
            return None
        return Block._from_binding(result, self._config, self)

    def function(self, address):
        """Return the function at `address`, if it exists."""
        result = self._inner.function(address)
        if result is None:
            return None
        return Function._from_binding(result, self._config, self)

    @property
    def queue_instructions(self):
        """Return the queue used to manage instruction discovery state."""
        return GraphQueue(self._inner.queue_instructions)

    @property
    def queue_blocks(self):
        """Return the queue used to manage block discovery state."""
        return GraphQueue(self._inner.queue_blocks)

    @property
    def queue_functions(self):
        """Return the queue used to manage function discovery state."""
        return GraphQueue(self._inner.queue_functions)

    def set_block(self, address):
        """Mark the address as a discovered block entrypoint."""
        return self._inner.set_block(address)

    def set_function(self, address):
        """Mark the address as a discovered function entrypoint."""
        return self._inner.set_function(address)

    def extend_instruction_edges(self, address, addresses):
        """Attach successor edges to an instruction."""
        return self._inner.extend_instruction_edges(address, addresses)

    def symbols(self):
        """Return the symbol-name view derived from graph metadata."""
        return dict(self._inner.symbols())

    def symbol(self, address):
        """Return the graph-owned symbol name for `address`, if present."""
        return self._inner.symbol(address)

    def insert_symbol(self, address, name):
        """Insert or replace a symbol in graph metadata."""
        return self._inner.insert_symbol(address, name)

    def replace_symbols(self, symbols):
        """Replace metadata symbols."""
        metadata = self.metadata()
        metadata["symbols"] = _coerce_symbol_metadata(symbols)
        return self._inner.replace_metadata(metadata)

    def extend_symbols(self, symbols):
        """Merge symbols into graph metadata."""
        for symbol in _coerce_symbol_metadata(symbols):
            self._inner.insert_symbol(symbol["virtual_address"], symbol["name"])
        return None

    def metadata(self):
        """Return graph metadata."""
        return self._inner.metadata()

    def replace_metadata(self, metadata):
        """Replace graph metadata."""
        return self._inner.replace_metadata(_coerce_metadata(metadata))

    def extend_metadata(self, metadata):
        """Merge metadata into graph metadata."""
        return self._inner.extend_metadata(_coerce_metadata(metadata))

    def metadata_value(self, key):
        """Return one graph metadata value by key, if present."""
        return self._inner.metadata_value(key)

    def __getattr__(self, name):
        """Delegate unknown attributes to the underlying native graph object."""
        return getattr(self._inner, name)

__all__ = [
    "Block",
    "Function",
    "FunctionCallee",
    "FunctionCaller",
    "Graph",
    "GraphQueue",
    "GraphState",
    "Instruction",
]
