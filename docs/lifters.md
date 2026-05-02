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

The source of meaning is instruction semantics. The source of structure is the controlflow hierarchy.

That means:

- instruction lifting uses instruction semantics
- block lifting uses ordered block instructions
- function lifting uses the function’s blocks and controlflow structure

## Common Python Usage

Use the explicit lifter API:

```python
from binlex.lifters import Lifter, LifterBackend

llvm = Lifter(function.architecture(), config, backend=LifterBackend.LLVM)
llvm.lift_function(function)
llvm.print()
print(llvm.text())

vex = Lifter(function.architecture(), config, backend=LifterBackend.VEX)
vex.lift_function(function)
vex.print()
print(vex.text())
```

You can also build the lifter explicitly:

```python
from binlex import Configuration
from binlex.lifters import Lifter, LifterBackend

config = Configuration()

llvm = Lifter(function.architecture(), config, backend=LifterBackend.LLVM)
llvm.lift_function(function)
llvm.print()
print(llvm.text())

vex = Lifter(function.architecture(), config, backend=LifterBackend.VEX)
vex.lift_function(function)
vex.print()
print(vex.text())
```

## Common Rust Usage

```rust
use binlex::{Architecture, Configuration};
use binlex::lifters::{Lifter, LifterBackend};

let config = Configuration::default();

let mut llvm = Lifter::new(Architecture::AMD64, config.clone(), LifterBackend::Llvm)?;
llvm.lift_function(&function)?;
llvm.print();
println!("{}", llvm.text()?);

let mut vex = Lifter::new(Architecture::AMD64, config, LifterBackend::Vex)?;
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
- `normalized()`
- `verify()`
- `optimizers()`

### Python

```python
from binlex.lifters import Lifter, LifterBackend

llvm = Lifter(function.architecture(), config, backend=LifterBackend.LLVM)
llvm.lift_function(function)
llvm.print()
print(llvm.text())
bitcode = llvm.bitcode()
normalized_text = llvm.normalized().text()
```

### Rust

```rust
let mut llvm = binlex::lifters::Lifter::new(
    Architecture::AMD64,
    config.clone(),
    binlex::lifters::LifterBackend::Llvm,
)?;
llvm.lift_function(&function)?;

llvm.print();
let text = llvm.text()?;
let bitcode = llvm.bitcode()?;
let normalized = llvm.normalized()?.text()?;
```

### LLVM Optimizers

LLVM exposes an optimizer namespace so users can choose their own pass chain.

Python:

```python
from binlex.lifters import Lifter, LifterBackend

llvm = Lifter(function.architecture(), config, backend=LifterBackend.LLVM)
llvm.lift_function(function)

optimized = (
    llvm
    .optimizers()
    .mem2reg()
    .instcombine()
    .cfg()
)
optimized.print()
text = optimized.text()
```

The result remains an LLVM artifact, so you can still call:

- `text()`
- `print()`
- `bitcode()`
- `normalized()`

### Normalized LLVM

`normalized()` is intended for similarity-oriented canonicalization, not heavy optimization.

It is useful when you want:

- stable naming
- reduced address noise
- more comparable LLVM output across inputs

Example:

```python
from binlex.lifters import Lifter, LifterBackend

llvm = Lifter(function.architecture(), config, backend=LifterBackend.LLVM)
llvm.lift_function(function)
llvm.normalized().print()
print(llvm.normalized().text())
```

## VEX Lifter

VEX is intentionally simpler.

It currently exposes:

- `text()`
- `print()`

That is the supported surface.

### Python

```python
from binlex.lifters import Lifter, LifterBackend

vex = Lifter(function.architecture(), config, backend=LifterBackend.VEX)
vex.lift_function(function)
vex.print()
print(vex.text())
```

### Rust

```rust
let mut vex = binlex::lifters::vex::Lifter::new(config);
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

When enabled, JSON includes:

- `lifters.llvm.text`
- `lifters.llvm.normalized.text` when configured
- `lifters.vex.text`

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
