# Lifters

Binlex lifters turn controlflow objects and semantics into other IR representations.

Today there are two built-in lifters:

- LLVM
- VEX

They are intentionally different in capability:

- LLVM is a richer artifact model with text, bitcode, normalization, and optimizer access
- VEX is a simpler text-oriented IR view

## What Lifters Consume

Lifters operate on Binlex controlflow objects:

- `Instruction`
- `Block`
- `Function`

The source of meaning is LIR bindings. The source of structure is the controlflow hierarchy.

That means:

- instruction lifting uses LIR bindings
- block lifting uses ordered block instructions
- function lifting uses the function’s blocks and controlflow structure

## Common Python Usage

Use the explicit lifter API:

```python
from binlex.ir.llvm import LlvmModule
from binlex.ir.vex import Lifter as VexLifter

llvm = LlvmModule(function.lir().abi().cpu(), config)
llvm.lift_function(function)
llvm.print()
print(llvm.text())

vex = VexLifter(config)
vex.lift_function(function)
vex.print()
print(vex.text())
```

You can also build the lifter explicitly:

```python
from binlex import Configuration
from binlex.ir.llvm import LlvmModule
from binlex.ir.vex import Lifter as VexLifter

config = Configuration()

llvm = LlvmModule(function.lir().abi().cpu(), config)
llvm.lift_function(function)
llvm.print()
print(llvm.text())

vex = VexLifter(config)
vex.lift_function(function)
vex.print()
print(vex.text())
```

## Common Rust Usage

```rust
use binlex::Configuration;
use binlex::ir::llvm::Lifter as LlvmLifter;
use binlex::ir::vex::Lifter as VexLifter;
use binlex::ir::lir::{LirCpu, LirCpuKind};

let config = Configuration::default();
let cpu = LirCpu::from_kind(LirCpuKind::Amd64)?;

let mut llvm = LlvmLifter::new(cpu, config.clone(), None)?;
llvm.lift_function(&function)?;
llvm.print();
println!("{}", llvm.text()?);

let mut vex = VexLifter::new(config);
vex.lift_function(&function)?;
vex.print();
println!("{}", vex.text()?);
```

## LLVM Lifter

LLVM is the richer of the two lifters.

It supports:

- `text()`
- `print()`
- `bitcode()`
- `verify()`
- explicit optimizer methods

### Python

```python
from binlex.ir.llvm import LlvmModule

llvm = LlvmModule(function.lir().abi().cpu(), config)
llvm.lift_function(function)
llvm.print()
print(llvm.text())
bitcode = llvm.bitcode()
```

### Rust

```rust
let cpu = binlex::ir::lir::LirCpu::from_kind(binlex::ir::lir::LirCpuKind::Amd64)?;
let mut llvm = binlex::ir::llvm::Lifter::new(cpu, config.clone(), None)?;
llvm.lift_function(&function)?;

llvm.print();
let text = llvm.text()?;
let bitcode = llvm.bitcode()?;
```

### LLVM Optimizers

LLVM exposes an optimizer namespace so users can choose their own pass chain.

Python:

```python
from binlex.ir.llvm import LlvmModule

llvm = LlvmModule(function.lir().abi().cpu(), config)
llvm.lift_function(function)

llvm.optimize_mem2reg()
llvm.optimize_instcombine()
llvm.optimize_cfg()
llvm.print()
text = llvm.text()
```

The result remains an LLVM artifact, so you can still call:

- `text()`
- `print()`
- `bitcode()`
## VEX Lifter

VEX is intentionally simpler.

It currently exposes:

- `text()`
- `print()`

That is the supported surface.

### Python

```python
from binlex.ir.vex import Lifter

vex = Lifter(config)
vex.lift_function(function)
vex.print()
print(vex.text())
```

### Rust

```rust
let mut vex = binlex::ir::vex::Lifter::new(config);
vex.lift_function(&function)?;
vex.print();
println!("{}", vex.text());
```

### VEX Function Output

VEX does not have the same function-level artifact model as LLVM.

In practice:

- instruction lifting produces instruction-oriented VEX text
- block lifting produces block-oriented IRSB-style text
- function lifting produces grouped IRSB-style block output for the function

So VEX function output is best understood as a function-scoped collection of block-level IR text.

## Choosing Between LLVM And VEX

Use LLVM when you want:

- a stronger ecosystem IR
- bitcode output
- normalization
- optimizers
- interop with LLVM tooling

Use VEX when you want:

- a quick VEX-style textual IR view
- a simpler IR projection
- compatibility with workflows that conceptually expect VEX-like output

## JSON Output

Lifters can also be emitted into Binlex JSON when enabled in config.

LLVM per-entity JSON toggles:

```toml
[binlex.instructions.lifters.llvm]
enabled = false

[binlex.instructions.lifters.llvm.normalized]
enabled = false

[binlex.blocks.lifters.llvm]
enabled = false

[binlex.blocks.lifters.llvm.normalized]
enabled = false

[binlex.functions.lifters.llvm]
enabled = false

[binlex.functions.lifters.llvm.normalized]
enabled = false
```

VEX per-entity JSON toggles:

```toml
[binlex.instructions.lifters.vex]
enabled = false

[binlex.blocks.lifters.vex]
enabled = false

[binlex.functions.lifters.vex]
enabled = false
```

## Configuration

LLVM has a richer top-level lifter config:

```toml
[binlex.lifters.llvm]
module_name = "binlex"
verify = true
```

VEX currently has a simple top-level switch:

```toml
[binlex.lifters.vex]
enabled = true
```

## Suggested Next Docs

If you are using lifters, the next useful docs are:

- [controlflow.md](./controlflow.md)
- [semantics.md](./semantics.md)
