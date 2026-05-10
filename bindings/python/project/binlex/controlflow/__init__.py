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
from binlex_bindings.binlex.controlflow import BlockJsonDeserializer as _BlockJsonDeserializerBinding
from binlex_bindings.binlex.controlflow import EntityKind as _EntityKindBinding
from binlex_bindings.binlex.controlflow import Function as _FunctionBinding
from binlex_bindings.binlex.controlflow import FunctionJsonDeserializer as _FunctionJsonDeserializerBinding
from binlex_bindings.binlex.controlflow import Graph as _GraphBinding
from binlex_bindings.binlex.controlflow import GraphQueue as _GraphQueueBinding
from binlex_bindings.binlex.controlflow import Instruction as _InstructionBinding
from binlex_bindings.binlex.controlflow import InstructionJsonDeserializer as _InstructionJsonDeserializerBinding
from binlex_bindings.binlex.controlflow import Reference as _ReferenceBinding
from binlex_bindings.binlex.controlflow.instruction import Operand as Operand
from binlex_bindings.binlex.controlflow.instruction import OperandKind as OperandKind

from binlex.core.architecture import _coerce_architecture
from binlex.hashing import MinHash32, SHA256, SSDeep, TLSH
from binlex.semantics import SemanticCpu, _cpu_kind_from_architecture

EntityKind = _EntityKindBinding


def _cpu_for_architecture(architecture):
    return SemanticCpu.from_kind(_cpu_kind_from_architecture(architecture))


class Instruction:
    """Single decoded instruction tracked inside a control-flow graph."""

    def __init__(self, address, cfg):
        """Look up the instruction at `address` within the provided graph."""
        self._inner = _InstructionBinding(address, cfg._inner)
        self._config = cfg._config

    @classmethod
    def _from_binding(cls, binding, config=None):
        """Wrap an existing native instruction binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
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

    def processors(self):
        """Return all processor outputs attached to this instruction."""
        return self._inner.processors()

    def processor(self, name):
        """Return a single processor output attached to this instruction."""
        return self._inner.processor(name)

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

    def lift(self, backend=None, abi=None, triple=None):
        """Return a lifter artifact for this instruction, if available."""
        from binlex.lifters import Lifter, LifterBackend

        if self._config is None:
            return None
        backend = LifterBackend.DEFAULT if backend is None else backend
        return Lifter(
            _cpu_for_architecture(self.architecture()),
            self._config,
            backend=backend,
            triple=triple,
        ).lift_instruction(self)

    def semantic(self):
        """Return canonical semantics for this instruction, if present."""
        return self._inner.semantic()

    def set_semantics(self, semantics):
        """Replace the canonical semantics for this instruction inside the graph."""
        inner = getattr(semantics, "_inner", semantics)
        self._inner.set_semantics(inner)
        return self

    def to_dict(self):
        """Convert the instruction to a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Return the JSON representation of the instruction."""
        return self._inner.json()

    def print(self):
        """Print the instruction representation to stdout."""
        return self._inner.print()

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


class InstructionJsonDeserializer:
    """Deserialize a serialized instruction JSON payload into typed accessors."""

    def __init__(self, string, config):
        """Create an instruction deserializer from a serialized JSON string."""
        self._inner = _InstructionJsonDeserializerBinding(string, config)
        self._config = config

    @classmethod
    def _from_binding(cls, binding, config=None):
        """Wrap an existing native instruction JSON deserializer binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        return result

    def architecture(self):
        """Return the architecture encoded in the serialized instruction."""
        return self._inner.architecture()

    def kind(self):
        """Return the controlflow entity kind encoded in the serialized instruction."""
        return self._inner.kind()

    def address(self):
        """Return the address of the serialized instruction."""
        return self._inner.address()

    def bytes(self):
        """Return the decoded raw bytes for the serialized instruction."""
        return self._inner.bytes()

    def size(self):
        """Return the size of the serialized instruction in bytes."""
        return self._inner.size()

    def mnemonic(self):
        """Return the decoded mnemonic of the serialized instruction."""
        return self._inner.mnemonic()

    def disassembly(self):
        """Return the canonical disassembly text of the serialized instruction."""
        return self._inner.disassembly()

    def operands(self):
        """Return normalized decoded operands for the serialized instruction."""
        return self._inner.operands()

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

    def chromosome(self):
        """Return the chromosome derived from this instruction, if available."""
        return self._inner.chromosome()

    def processors(self):
        """Return all processor outputs attached to this instruction."""
        return self._inner.processors()

    def processor(self, name):
        """Return a single processor output attached to this instruction."""
        return self._inner.processor(name)

    def semantic(self):
        """Return canonical semantics for this serialized instruction, if present."""
        return self._inner.semantic()

    def to_dict(self):
        """Convert the instruction to a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Return the JSON representation of the instruction."""
        return self._inner.json()

    def print(self):
        """Print the instruction representation to stdout."""
        return self._inner.print()

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


class Block:
    """Basic block wrapper backed by the native control-flow engine."""

    def __init__(self, address, cfg):
        """Look up the block that starts at `address` within the provided graph."""
        self._inner = _BlockBinding(address, cfg._inner)
        self._config = cfg._config

    @classmethod
    def _from_binding(cls, binding, config=None):
        """Wrap an existing native block binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
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
        return [Instruction._from_binding(item, self._config) for item in self._inner.instructions()]

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
        return [Block._from_binding(item, self._config) for item in self._inner.successors()]

    def predecessors(self):
        """Return the blocks that directly reach this block."""
        return [Block._from_binding(item, self._config) for item in self._inner.predecessors()]

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
        return [Function._from_binding(item, self._config) for item in self._inner.callees()]

    def callee_references(self):
        """Return direct outgoing call references for this block."""
        return [Reference._from_binding(item) for item in self._inner.callee_references()]

    def processors(self):
        """Return all processor outputs attached to this block."""
        return self._inner.processors()

    def processor(self, name):
        """Return a single processor output attached to this block."""
        return self._inner.processor(name)

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

    def lift(self, backend=None, abi=None, triple=None):
        """Return a lifter artifact for this block, if available."""
        from binlex.lifters import Lifter, LifterBackend

        if self._config is None:
            return None
        backend = LifterBackend.DEFAULT if backend is None else backend
        return Lifter(
            _cpu_for_architecture(self.architecture()),
            self._config,
            backend=backend,
            triple=triple,
        ).lift_block(self, abi=abi)

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

    def print(self):
        """Print the block representation to stdout."""
        return self._inner.print()

    def to_dict(self):
        """Convert the block to a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Return the JSON representation of the block."""
        return self._inner.json()

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


class Function:
    """Function wrapper backed by the native control-flow engine."""

    def __init__(self, address, cfg):
        """Look up the function that starts at `address` within the provided graph."""
        self._inner = _FunctionBinding(address, cfg._inner)
        self._config = cfg._config

    @classmethod
    def _from_binding(cls, binding, config=None):
        """Wrap an existing native function binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
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
        return [Block._from_binding(item, self._config) for item in self._inner.blocks()]

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
        """Return the functions directly called by this function."""
        return [Function._from_binding(item, self._config) for item in self._inner.callees()]

    def callers(self):
        """Return the functions that directly call this function."""
        return [Function._from_binding(item, self._config) for item in self._inner.callers()]

    def callee_references(self):
        """Return a mapping of callsite addresses to callee function addresses."""
        return self._inner.callee_references()

    def caller_references(self):
        """Return a mapping of callsite addresses to caller function addresses."""
        return self._inner.caller_references()

    def processors(self):
        """Return all processor outputs attached to this function."""
        return self._inner.processors()

    def processor(self, name):
        """Return a single processor output attached to this function."""
        return self._inner.processor(name)

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

    def lift(self, backend=None, abi=None, triple=None):
        """Return a lifter artifact for this function, if available."""
        from binlex.lifters import Lifter, LifterBackend

        if self._config is None:
            return None
        backend = LifterBackend.DEFAULT if backend is None else backend
        return Lifter(
            _cpu_for_architecture(self.architecture()),
            self._config,
            backend=backend,
            triple=triple,
        ).lift_function(self, abi=abi)

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

    def print(self):
        """Print the function representation to stdout."""
        return self._inner.print()

    def to_dict(self):
        """Convert the function to a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Return the JSON representation of the function."""
        return self._inner.json()

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

    def semantic(self):
        return self.__class__(self._owner, mode="semantic")

    def ir(self):
        lifter = self._lift()
        return lifter.ir()

    def print(self):
        lifter = self._lift()
        return lifter.print()

    def bitcode(self):
        lifter = self._lift()
        return lifter.bitcode()

    def object(self):
        lifter = self._lift()
        return lifter.object()

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
        from binlex.lifters import Lifter, LifterBackend

        config = getattr(self._owner, "_config", None)
        if config is None:
            raise RuntimeError("controlflow object is missing associated Configuration")
        if self._mode is not None:
            config = config.clone()
            config.lifters.llvm.mode = self._mode
        lifter = Lifter(_cpu_for_architecture(self._owner.architecture()), config, backend=LifterBackend.LLVM)
        if isinstance(self._owner, Instruction):
            lifter = lifter.lift_instruction(self._owner)
        elif isinstance(self._owner, Block):
            lifter = lifter.lift_block(self._owner)
        elif isinstance(self._owner, Function):
            lifter = lifter.lift_function(self._owner)
        else:
            raise TypeError(f"unsupported llvm owner: {type(self._owner)!r}")
        if lifter is None:
            raise RuntimeError("llvm lift failed")
        return lifter


class BlockJsonDeserializer:
    """Deserialize a serialized block JSON payload into typed accessors."""

    def __init__(self, string, config):
        """Create a block deserializer from a serialized JSON string."""
        self._inner = _BlockJsonDeserializerBinding(string, config)

    @classmethod
    def _from_binding(cls, binding):
        """Wrap an existing native block JSON deserializer binding."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def callee_references(self):
        """Return direct outgoing call references contained in the block payload."""
        return [Reference._from_binding(item) for item in self._inner.callee_references()]

    def architecture(self):
        """Return the architecture encoded in the serialized block."""
        return self._inner.architecture()

    def kind(self):
        """Return the controlflow entity kind encoded in the serialized block."""
        return self._inner.kind()

    def bytes(self):
        """Return the decoded raw bytes for the serialized block."""
        return self._inner.bytes()

    def address(self):
        """Return the starting address of the serialized block."""
        return self._inner.address()

    def minhash(self):
        """Return the MinHash digest for the block, if available."""
        return self._inner.minhash()

    def tlsh(self):
        """Return the TLSH digest for the block, if available."""
        return self._inner.tlsh()

    def sha256(self):
        """Return the SHA-256 digest for the block, if available."""
        return self._inner.sha256()

    def ssdeep(self):
        """Return the ssdeep digest for the block, if available."""
        return self._inner.ssdeep()

    def edges(self):
        """Return the number of outgoing control-flow edges."""
        return self._inner.edges()

    def successor_references(self):
        """Return direct outgoing control-flow references in the payload."""
        return [Reference._from_binding(item) for item in self._inner.successor_references()]

    def predecessor_references(self):
        """Return direct incoming control-flow references in the payload."""
        return [Reference._from_binding(item) for item in self._inner.predecessor_references()]

    def branches(self):
        """Return the explicit branch target addresses targeted by the block."""
        return self._inner.branches()

    def is_conditional(self):
        """Return whether the block ends with a conditional transfer of control."""
        return self._inner.is_conditional()

    def entropy(self):
        """Return the block entropy, if available."""
        return self._inner.entropy()

    def fallthrough(self):
        """Return the sequential fallthrough address after the block, if available."""
        return self._inner.fallthrough()

    def size(self):
        """Return the block size in bytes."""
        return self._inner.size()

    def number_of_instructions(self):
        """Return the number of instructions contained in the block."""
        return self._inner.number_of_instructions()

    def chromosome(self):
        """Return the chromosome derived from the serialized block."""
        return self._inner.chromosome()

    def to_dict(self):
        """Convert the serialized block payload to a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Return the normalized JSON representation of the block payload."""
        return self._inner.json()

    def print(self):
        """Print the serialized block payload to stdout."""
        return self._inner.print()

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


class FunctionJsonDeserializer:
    """Deserialize a serialized function JSON payload into typed accessors."""

    def __init__(self, string, config):
        """Create a function deserializer from a serialized JSON string."""
        self._inner = _FunctionJsonDeserializerBinding(string, config)

    @classmethod
    def _from_binding(cls, binding):
        """Wrap an existing native function JSON deserializer binding."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def blocks(self):
        """Return the block addresses contained in the function payload."""
        return self._inner.blocks()

    def kind(self):
        """Return the controlflow entity kind encoded in the serialized function."""
        return self._inner.kind()

    def callee_references(self):
        """Return direct callsite-to-callee references contained in the payload."""
        return self._inner.callee_references()

    def caller_references(self):
        """Return direct callsite-to-caller references contained in the payload."""
        return self._inner.caller_references()

    def size(self):
        """Return the total size of the function in bytes."""
        return self._inner.size()

    def contiguous(self):
        """Return whether the function occupies a contiguous address range."""
        return self._inner.contiguous()

    def architecture(self):
        """Return the architecture encoded in the serialized function."""
        return self._inner.architecture()

    def bytes(self):
        """Return the decoded raw bytes for the function, if available."""
        return self._inner.bytes()

    def address(self):
        """Return the starting address of the function."""
        return self._inner.address()

    def number_of_instructions(self):
        """Return the number of instructions in the function."""
        return self._inner.number_of_instructions()

    def number_of_blocks(self):
        """Return the number of basic blocks in the function."""
        return self._inner.number_of_blocks()

    def average_instructions_per_block(self):
        """Return the average number of instructions per block."""
        return self._inner.average_instructions_per_block()

    def entropy(self):
        """Return the function entropy, if available."""
        return self._inner.entropy()

    def edges(self):
        """Return the number of control-flow edges in the function."""
        return self._inner.edges()

    def sha256(self):
        """Return the SHA-256 digest for the function, if available."""
        return self._inner.sha256()

    def minhash(self):
        """Return the MinHash digest for the function, if available."""
        return self._inner.minhash()

    def tlsh(self):
        """Return the TLSH digest for the function, if available."""
        return self._inner.tlsh()

    def ssdeep(self):
        """Return the ssdeep digest for the function, if available."""
        return self._inner.ssdeep()

    def markov(self):
        """Return the Markov importance scores for the function, if available."""
        return self._inner.markov()

    def chromosome(self):
        """Return the chromosome derived from the serialized function."""
        return self._inner.chromosome()

    def to_dict(self):
        """Convert the serialized function payload to a Python dictionary."""
        return self._inner.to_dict()

    def json(self):
        """Return the normalized JSON representation of the function payload."""
        return self._inner.json()

    def print(self):
        """Print the serialized function payload to stdout."""
        return self._inner.print()

    def __str__(self):
        """Return the JSON representation when converted to a string."""
        return str(self._inner)


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

    def to_dict(self):
        return self._inner.to_dict()

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

    def __init__(self, architecture, config):
        """Create a graph for the given architecture and configuration."""
        self._inner = _GraphBinding(_coerce_architecture(architecture), config)
        self._config = config

    @classmethod
    def _from_binding(cls, binding, config=None):
        """Wrap an existing native graph binding."""
        result = cls.__new__(cls)
        result._inner = binding
        result._config = config
        return result

    def instructions(self):
        """Return all instructions currently tracked by the graph."""
        return [Instruction._from_binding(item, self._config) for item in self._inner.instructions()]

    def blocks(self):
        """Return all blocks currently tracked by the graph."""
        return [Block._from_binding(item, self._config) for item in self._inner.blocks()]

    def functions(self):
        """Return all functions currently tracked by the graph."""
        return [Function._from_binding(item, self._config) for item in self._inner.functions()]

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

    def get_instruction(self, address):
        """Return the instruction at `address`, if it exists."""
        result = self._inner.get_instruction(address)
        if result is None:
            return None
        return Instruction._from_binding(result, self._config)

    def get_block(self, address):
        """Return the block at `address`, if it exists."""
        result = self._inner.get_block(address)
        if result is None:
            return None
        return Block._from_binding(result, self._config)

    def get_function(self, address):
        """Return the function at `address`, if it exists."""
        result = self._inner.get_function(address)
        if result is None:
            return None
        return Function._from_binding(result, self._config)

    def __getattr__(self, name):
        """Delegate unknown attributes to the underlying native graph object."""
        return getattr(self._inner, name)

__all__ = [
    "Block",
    "BlockJsonDeserializer",
    "Function",
    "FunctionJsonDeserializer",
    "Graph",
    "GraphQueue",
    "Instruction",
    "InstructionJsonDeserializer",
]
