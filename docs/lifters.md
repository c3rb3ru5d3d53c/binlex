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

The easiest API is the object-bound convenience form:

```python
llvm = function.lifters().llvm()
print(llvm.text())

vex = function.lifters().vex()
print(vex.text())
```

You can also build the lifter explicitly:

```python
from binlex import Config
from binlex.lifters.llvm import Lifter as LlvmLifter
from binlex.lifters.vex import Lifter as VexLifter

config = Config()

llvm = LlvmLifter(config)
llvm.lift_function(function)
print(llvm.text())

vex = VexLifter(config)
vex.lift_function(function)
print(vex.text())
```

## Common Rust Usage

```rust
use binlex::Config;
use binlex::lifters::llvm::Lifter as LlvmLifter;
use binlex::lifters::vex::Lifter as VexLifter;

let config = Config::default();

let mut llvm = LlvmLifter::new(config.clone());
llvm.lift_function(&function)?;
println!("{}", llvm.text());

let mut vex = VexLifter::new(config);
vex.lift_function(&function)?;
println!("{}", vex.text());
```

## LLVM Lifter

LLVM is the richer of the two lifters.

It supports:

- `text()`
- `bitcode()`
- `normalized()`
- `verify()`
- `optimizers()`

### Python

```python
llvm = function.lifters().llvm()

print(llvm.text())
bitcode = llvm.bitcode()
normalized_text = llvm.normalized().text()
```

### Rust

```rust
let mut llvm = binlex::lifters::llvm::Lifter::new(config.clone());
llvm.lift_function(&function)?;

let text = llvm.text();
let bitcode = llvm.bitcode();
let normalized = llvm.normalized()?.text();
```

### LLVM Optimizers

LLVM exposes an optimizer namespace so users can choose their own pass chain.

Python:

```python
llvm = function.lifters().llvm()

text = (
    llvm
    .optimizers()
    .mem2reg()
    .instcombine()
    .cfg()
    .text()
)
```

The result remains an LLVM artifact, so you can still call:

- `text()`
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
llvm = function.lifters().llvm()
print(llvm.normalized().text())
```

## VEX Lifter

VEX is intentionally simpler.

It currently exposes:

- `text()`

That is the supported surface.

### Python

```python
vex = function.lifters().vex()
print(vex.text())
```

### Rust

```rust
let mut vex = binlex::lifters::vex::Lifter::new(config);
vex.lift_function(&function)?;
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

## Config

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
