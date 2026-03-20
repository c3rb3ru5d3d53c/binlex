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
from binlex_bindings.binlex.controlflow import Function as _FunctionBinding
from binlex_bindings.binlex.controlflow import FunctionJsonDeserializer as _FunctionJsonDeserializerBinding
from binlex_bindings.binlex.controlflow import Graph as _GraphBinding
from binlex_bindings.binlex.controlflow import GraphQueue as _GraphQueueBinding
from binlex_bindings.binlex.controlflow import Instruction as _InstructionBinding

from binlex.architecture import _coerce_architecture
from binlex.hashing import MinHash32, SHA256, TLSH
from binlex.imaging import PNG, SVG


class Instruction:
    """Single decoded instruction tracked inside a control-flow graph."""

    def __init__(self, address, cfg):
        """Look up the instruction at `address` within the provided graph."""
        self._inner = _InstructionBinding(address, cfg._inner)

    @classmethod
    def from_binding(cls, binding):
        """Wrap an existing native instruction binding."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    @property
    def address(self):
        """Return the instruction address."""
        return self._inner.address

    def chromosome(self):
        """Return the chromosome derived from this instruction, if available."""
        return self._inner.chromosome()

    def blocks(self):
        """Return the block addresses containing this instruction."""
        return self._inner.blocks()

    def next(self):
        """Return the next linear instruction address, if known."""
        return self._inner.next()

    def to(self):
        """Return the control-flow successor addresses for this instruction."""
        return self._inner.to()

    def has_indirect_target(self):
        """Return whether this instruction branches to an indirect target."""
        return self._inner.has_indirect_target()

    def functions(self):
        """Return the function addresses associated with this instruction."""
        return self._inner.functions()

    def size(self):
        """Return the instruction size in bytes."""
        return self._inner.size()

    def png(self):
        """Render the instruction as a PNG image."""
        return PNG.from_binding(self._inner.png())

    def svg(self):
        """Render the instruction as an SVG image."""
        return SVG.from_binding(self._inner.svg())

    def processors(self):
        """Return all processor outputs attached to this instruction."""
        return self._inner.processors()

    def processor(self, name):
        """Return a single processor output attached to this instruction, if present."""
        return self._inner.processor(name)

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

    @classmethod
    def from_binding(cls, binding):
        """Wrap an existing native block binding."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def address(self):
        """Return the starting address of the block."""
        return self._inner.address()

    def architecture(self):
        """Return the architecture associated with this block."""
        return self._inner.architecture()

    def chromosome(self):
        """Return the chromosome derived from this block, if available."""
        return self._inner.chromosome()

    def instructions(self):
        """Return the instructions contained in this block."""
        return [Instruction.from_binding(item) for item in self._inner.instructions()]

    def bytes(self):
        """Return the raw bytes for this block."""
        return self._inner.bytes()

    def png(self):
        """Render the block as a PNG image."""
        return PNG.from_binding(self._inner.png())

    def svg(self):
        """Render the block as an SVG image."""
        return SVG.from_binding(self._inner.svg())

    def prologue(self):
        """Return whether this block looks like a function prologue."""
        return self._inner.prologue()

    def edges(self):
        """Return the number of outgoing edges from this block."""
        return self._inner.edges()

    def next(self):
        """Return the next linear address after this block, if available."""
        return self._inner.next()

    def to(self):
        """Return the successor addresses targeted by this block."""
        return self._inner.to()

    def entropy(self):
        """Return the entropy of this block, if available."""
        return self._inner.entropy()

    def blocks(self):
        """Return the related block addresses referenced by this block."""
        return self._inner.blocks()

    def number_of_instructions(self):
        """Return the number of instructions contained in this block."""
        return self._inner.number_of_instructions()

    def functions(self):
        """Return a mapping of referenced function addresses and counts."""
        return self._inner.functions()

    def processors(self):
        """Return all processor outputs attached to this block."""
        return self._inner.processors()

    def processor(self, name):
        """Return a single processor output attached to this block, if present."""
        return self._inner.processor(name)

    def tlsh(self):
        """Return the TLSH object for this block, if available."""
        return self._inner.tlsh()

    def sha256(self):
        """Return the SHA-256 object for this block, if available."""
        return self._inner.sha256()

    def minhash(self):
        """Return the MinHash object for this block, if available."""
        return self._inner.minhash()

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

    @classmethod
    def from_binding(cls, binding):
        """Wrap an existing native function binding."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def address(self):
        """Return the starting address of the function."""
        return self._inner.address()

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
        return [Block.from_binding(item) for item in self._inner.blocks()]

    def bytes(self):
        """Return the raw bytes for this function, if available."""
        return self._inner.bytes()

    def png(self):
        """Render the function as a PNG image, if contiguous."""
        image = self._inner.png()
        return None if image is None else PNG.from_binding(image)

    def svg(self):
        """Render the function as an SVG image, if contiguous."""
        image = self._inner.svg()
        return None if image is None else SVG.from_binding(image)

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

    def functions(self):
        """Return a mapping of referenced function addresses and counts."""
        return self._inner.functions()

    def processors(self):
        """Return all processor outputs attached to this function."""
        return self._inner.processors()

    def processor(self, name):
        """Return a single processor output attached to this function, if present."""
        return self._inner.processor(name)

    def tlsh(self):
        """Return the TLSH object for this function, if available."""
        return self._inner.tlsh()

    def sha256(self):
        """Return the SHA-256 object for this function, if available."""
        return self._inner.sha256()

    def minhash(self):
        """Return the MinHash object for this function, if available."""
        return self._inner.minhash()

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


class BlockJsonDeserializer:
    """Deserialize a serialized block JSON payload into typed accessors."""

    def __init__(self, string, config):
        """Create a block deserializer from a serialized JSON string."""
        self._inner = _BlockJsonDeserializerBinding(string, config)

    def functions(self):
        """Return referenced function addresses contained in the block payload."""
        return self._inner.functions()

    def architecture(self):
        """Return the architecture encoded in the serialized block."""
        return self._inner.architecture()

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

    def edges(self):
        """Return the number of outgoing control-flow edges."""
        return self._inner.edges()

    def blocks(self):
        """Return related block addresses referenced by the payload."""
        return self._inner.blocks()

    def to(self):
        """Return the successor addresses targeted by the block."""
        return self._inner.to()

    def conditional(self):
        """Return whether the block ends with a conditional transfer of control."""
        return self._inner.conditional()

    def entropy(self):
        """Return the block entropy, if available."""
        return self._inner.entropy()

    def next(self):
        """Return the next linear address after the block, if available."""
        return self._inner.next()

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

    def blocks(self):
        """Return the block addresses contained in the function payload."""
        return self._inner.blocks()

    def functions(self):
        """Return referenced function addresses contained in the payload."""
        return self._inner.functions()

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

    @classmethod
    def from_binding(cls, binding):
        """Wrap an existing native graph binding."""
        result = cls.__new__(cls)
        result._inner = binding
        return result

    def instructions(self):
        """Return all instructions currently tracked by the graph."""
        return [Instruction.from_binding(item) for item in self._inner.instructions()]

    def blocks(self):
        """Return all blocks currently tracked by the graph."""
        return [Block.from_binding(item) for item in self._inner.blocks()]

    def functions(self):
        """Return all functions currently tracked by the graph."""
        return [Function.from_binding(item) for item in self._inner.functions()]

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
        return Instruction.from_binding(result)

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
]
