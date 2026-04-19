# Controlflow

Binlex models disassembly as a controlflow graph made of four main object types:

- `Graph`
- `Function`
- `Block`
- `Instruction`

These are the core objects you work with after disassembly.

## Overview

The relationship is:

```text
Graph
  -> Function
    -> Block
      -> Instruction
```

This structure is the foundation for:

- similarity analysis
- semantics
- lifting
- processor output attachment
- JSON export

## Graph

`Graph` is the top-level container for a disassembled input.

It owns:

- the architecture
- the active `Config`
- the discovered instructions
- the discovered blocks
- the discovered functions

A `Graph` is usually filled by a disassembler.

### Python

```python
from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE

config = Config()
pe = PE("samples/kernel32.dll", config)
image = pe.image()

disassembler = Disassembler(
    pe.architecture(),
    image,
    pe.executable_virtual_address_ranges(),
    config,
)

graph = Graph(pe.architecture(), config)
disassembler.disassemble(pe.entrypoint_virtual_addresses(), graph)

print(len(graph.functions()))
```

### Rust

```rust
use binlex::Config;
use binlex::controlflow::Graph;
use binlex::disassemblers::capstone::Disassembler;
use binlex::formats::PE;

let config = Config::default();
let pe = PE::new("samples/kernel32.dll", config.clone())?;
let mut image = pe.image()?;

let disassembler = Disassembler::from_image(
    pe.architecture(),
    &mut image,
    pe.executable_virtual_address_ranges(),
    config.clone(),
)?;

let mut graph = Graph::new(pe.architecture(), config);
disassembler.disassemble(pe.entrypoint_virtual_addresses(), &mut graph)?;

println!("functions: {}", graph.functions().len());
```

## Function

`Function` represents a discovered function inside a graph.

A function owns:

- an entry address
- a set of blocks
- function-level metadata such as size, hashes, entropy, and optional lifted output

Functions are graph-bound objects. They are not standalone detached values.

### Python

```python
for function in graph.functions():
    print(hex(function.address()))
    print(function.number_of_blocks())
    print(function.number_of_instructions())
```

### Rust

```rust
for function in graph.functions() {
    println!("0x{:x}", function.address());
    println!("blocks: {}", function.number_of_blocks());
    println!("instructions: {}", function.number_of_instructions());
}
```

## Block

`Block` represents a basic block.

A block is:

- an ordered sequence of instructions
- with one terminating instruction
- and a set of outgoing controlflow targets

Blocks are also graph-bound.

### Python

```python
for function in graph.functions():
    for block in function.blocks():
        print(hex(block.address()))
        print(block.number_of_instructions())
        print(block.to())
```

### Rust

```rust
for function in graph.functions() {
    for block in function.blocks.values() {
        println!("block 0x{:x}", block.address());
        println!("instructions: {}", block.number_of_instructions());
        println!("targets: {:?}", block.to());
    }
}
```

## Instruction

`Instruction` is the smallest controlflow unit.

It contains:

- address
- bytes
- architecture
- controlflow properties
- optional semantics
- optional processor outputs

Instructions are usually accessed through a block, but they can also be looked up directly from the graph.

### Python

```python
for function in graph.functions():
    for block in function.blocks():
        for instruction in block.instructions():
            print(hex(instruction.address()), instruction.size())
```

### Rust

```rust
for function in graph.functions() {
    for block in function.blocks.values() {
        for instruction in block.instructions() {
            println!("0x{:x} size={}", instruction.address(), instruction.size());
        }
    }
}
```

## Contiguous And Non-Contiguous Functions

Not every discovered function is one contiguous range of bytes.

Binlex supports both:

- contiguous functions
- non-contiguous functions

This matters because:

- similarity workflows may still want a function-level view
- LLVM lifting can preserve function CFG structure even when blocks are not contiguous
- VEX lifting groups block-level text under a function artifact

The important point is that Binlex function identity is based on controlflow structure, not only on one flat byte range.

## Why This Model Matters

This controlflow hierarchy is reused everywhere else in Binlex:

- semantics are attached to `Instruction`
- LLVM lifting can happen from `Instruction`, `Block`, or `Function`
- VEX lifting can happen from `Instruction`, `Block`, or `Function`
- processors attach outputs to instructions, blocks, functions, or graphs
- JSON export is built from these same objects

If you are building on top of Binlex, this is the model to start from.

## Common Patterns

### Walk every function

```python
for function in graph.functions():
    print(function.to_dict())
```

### Walk every block in every function

```python
for function in graph.functions():
    for block in function.blocks():
        print(block.to_dict())
```

### Walk every instruction with semantics

```python
for function in graph.functions():
    for block in function.blocks():
        for instruction in block.instructions():
            semantics = instruction.semantics()
            if semantics is not None:
                print(hex(instruction.address()), semantics.status())
```

### Lift one function

```python
llvm = function.lifters().llvm()
print(llvm.text())
```

## Suggested Next Docs

If you are starting from controlflow, the next useful docs are:

- [semantics.md](./semantics.md)
- [lifters.md](./lifters.md)
