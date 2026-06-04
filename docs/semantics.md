# LirModule

Binlex semantics are the canonical instruction-meaning layer used between disassembly and lifting.

They are intended to be useful outside Binlex’s built-in disassemblers too. You can construct
semantics directly in Rust or Python and use them for your own:

- analysis pipelines
- normalization/canonicalization
- custom pattern matching
- experimental lifters
- interchange with your own tools

The important idea is:

```text
bytes / decoder / your own source
  -> Lir
  -> lifters or your own consumers
```

LirModule are not tied to one architecture backend. They describe:

- temporary values
- reads and writes
- memory effects
- intrinsics
- control-flow terminators
- partial/complete status
- diagnostics when modeling is incomplete

## Model

The top-level type is `Lir`.

It contains:

- `version`
- `status`
- `temporaries`
- `effects`
- `terminator`
- `diagnostics`

The main building blocks are:

- `LirLocation`
  - register
  - flag
  - program counter
  - temporary
  - memory

- `LirExpression`
  - constants
  - reads
  - loads
  - unary/binary ops
  - casts
  - compares
  - select/extract/concat
  - intrinsics

- `LirEffect`
  - set
  - store
  - fence
  - trap
  - intrinsic
  - nop

- `LirTerminator`
  - fallthrough
  - jump
  - branch
  - call
  - return
  - unreachable
  - trap

## Status And Diagnostics

`LirStatus` is:

- `Complete`
- `Partial`

Use `Complete` only when the modeled effects are intended to be trusted as-is. In practice that
means:

- no missing architectural side effects that you know about
- no attached diagnostics

Use `Partial` when you can describe some of the instruction but not all of it. Attach
`LirDiagnostic` values to explain what is missing. That is the preferred way to model
unsupported or architecture-specific cases without inventing false precision.

Use `Partial` for intrinsic-backed placeholders when the intrinsic is carrying architectural detail
that is not yet modeled directly in the semantics IR.

## Rust Usage

Import the semantics types from `binlex::ir::lir`:

```rust
use binlex::ir::lir::{
    Lir,
    LirEffect,
    LirExpression,
    LirLocation,
    LirOperationBinary,
    LirStatus,
    LirTerminator,
};
```

### Example: `eax = eax + 4; ret`

```rust
use binlex::ir::lir::{
    Lir,
    LirEffect,
    LirExpression,
    LirLocation,
    LirOperationBinary,
    LirStatus,
    LirTerminator,
};

let semantics = Lir {
    version: 1,
    status: LirStatus::Complete,
    temporaries: Vec::new(),
    effects: vec![
        LirEffect::Set {
            dst: LirLocation::Register {
                name: "eax".to_string(),
                bits: 32,
            },
            expression: LirExpression::Binary {
                op: LirOperationBinary::Add,
                left: Box::new(LirExpression::Read(Box::new(
                    LirLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                ))),
                right: Box::new(LirExpression::Const {
                    value: 4,
                    bits: 32,
                }),
                bits: 32,
            },
        },
    ],
    terminator: LirTerminator::Return { expression: None },
    diagnostics: Vec::new(),
};
```

### Example: explicit memory store

```rust
use binlex::ir::lir::{
    Lir,
    LirAddressSpace,
    LirEffect,
    LirExpression,
    LirLocation,
    LirStatus,
    LirTerminator,
};

let semantics = Lir {
    version: 1,
    status: LirStatus::Complete,
    temporaries: Vec::new(),
    effects: vec![
        LirEffect::Store {
            space: LirAddressSpace::Stack,
            addr: LirExpression::Read(Box::new(LirLocation::Register {
                name: "rsp".to_string(),
                bits: 64,
            })),
            expression: LirExpression::Read(Box::new(LirLocation::Register {
                name: "rax".to_string(),
                bits: 64,
            })),
            bits: 64,
        },
    ],
    terminator: LirTerminator::FallThrough,
    diagnostics: Vec::new(),
};
```

### Example: partial semantics

```rust
use binlex::ir::lir::{
    Lir,
    LirDiagnostic,
    LirDiagnosticKind,
    LirStatus,
    LirTerminator,
};

let semantics = Lir {
    version: 1,
    status: LirStatus::Partial,
    temporaries: Vec::new(),
    effects: Vec::new(),
    terminator: LirTerminator::Trap,
    diagnostics: vec![
        LirDiagnostic {
            kind: LirDiagnosticKind::UnsupportedInstruction,
            message: "instruction not modeled yet".to_string(),
        },
    ],
};
```

### Serializing semantics

LirModule serialize cleanly with Serde:

```rust
let json = serde_json::to_string_pretty(&semantics.process())?;
println!("{}", json);
```

`u128` constants are serialized safely as strings in JSON, so large constant values survive
transport and storage without loss.

## Python Usage

The Python bindings expose the same model through `binlex.irs.lir`.

```python
from binlex.irs.lir import (
    Lir,
    LirDiagnostic,
    LirDiagnosticKind,
    LirEffect,
    LirExpression,
    LirLocation,
    LirOperationBinary,
    LirStatus,
    LirTerminator,
)
```

### Example: `eax = eax + 4; ret`

```python
from binlex.irs.lir import (
    Lir,
    LirEffect,
    LirExpression,
    LirLocation,
    LirOperationBinary,
    LirStatus,
    LirTerminator,
)

eax = LirLocation.register("eax", 32)

expr = LirExpression.binary(
    LirOperationBinary.Add,
    LirExpression.read(eax),
    LirExpression.const(4, 32),
    32,
)

semantics = Lir(
    1,
    LirStatus.Complete,
    effects=[
        LirEffect.set(eax, expr),
    ],
    terminator=LirTerminator.return_(),
)
```

### Example: partial semantics with diagnostics

```python
from binlex.irs.lir import (
    Lir,
    LirDiagnostic,
    LirDiagnosticKind,
    LirStatus,
    LirTerminator,
)

semantics = Lir(
    1,
    LirStatus.Partial,
    diagnostics=[
        LirDiagnostic(
            LirDiagnosticKind.UnsupportedInstruction,
            "custom instruction not modeled yet",
        ),
    ],
    terminator=LirTerminator.trap(),
)
```

### Example: inspect

```python
print(semantics.text())
bytecode = semantics.bytecode()
round_tripped = Lir.from_bytecode(bytecode)
```

The Python bindings also expose constructors for the lower-level pieces:

- `LirTemporary(...)`
- `LirLocation.register(...)`
- `LirLocation.flag(...)`
- `LirLocation.program_counter(...)`
- `LirLocation.temporary(...)`
- `LirLocation.memory(...)`
- `LirExpression.const(...)`
- `LirExpression.read(...)`
- `LirExpression.load(...)`
- `LirExpression.unary(...)`
- `LirExpression.binary(...)`
- `LirExpression.cast(...)`
- `LirExpression.compare(...)`
- `LirExpression.select(...)`
- `LirExpression.extract(...)`
- `LirExpression.concat(...)`
- `LirExpression.undefined(...)`
- `LirExpression.poison(...)`
- `LirExpression.intrinsic(...)`
- `LirEffect.set(...)`
- `LirEffect.store(...)`
- `LirEffect.fence(...)`
- `LirEffect.trap(...)`
- `LirEffect.intrinsic(...)`
- `LirEffect.nop()`
- `LirTerminator.fallthrough()`
- `LirTerminator.jump(...)`
- `LirTerminator.branch(...)`
- `LirTerminator.call(...)`
- `LirTerminator.return_(...)`
- `LirTerminator.unreachable()`
- `LirTerminator.trap()`

## Using LirModule From Disassembly

Binlex semantics are enabled by default during disassembly.

Rust:

```rust
use binlex::controlflow::Graph;
use binlex::disassemblers::capstone::Disassembler;
use binlex::formats::PE;
use binlex::Configuration;

let config = Configuration::default();
let pe = PE::new(std::fs::read("samples/kernel32.dll")?, config.clone())?;
let mut image = pe.image()?;
let disassembler = Disassembler::from_image(
    pe.architecture(),
    &mut image,
    pe.executable_virtual_address_ranges(),
    config.clone(),
)?;

let mut graph = Graph::new(pe.architecture(), config.clone());
disassembler.disassemble(pe.entrypoint_virtual_addresses(), &mut graph)?;

for function in graph.functions() {
    for block in function.blocks.values() {
        for instruction in block.instructions() {
            if let Some(semantics) = instruction.semantics.as_ref() {
                println!(
                    "0x{:x}: status={:?} effects={} terminator={:?}",
                    instruction.address(),
                    semantics.status,
                    semantics.effects.len(),
                    semantics.terminator.kind(),
                );
            }
        }
    }
}
```

Python:

```python
from binlex import Configuration
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE

config = Configuration()
from pathlib import Path

pe = PE(Path("samples/kernel32.dll").read_bytes(), config)
image = pe.image()

disassembler = Disassembler(
    pe.architecture(),
    image,
    pe.executable_virtual_address_ranges(),
    config,
)

graph = Graph(pe.architecture(), config)
disassembler.disassemble(pe.entrypoint_virtual_addresses(), graph)

for function in graph.functions():
    for block in function.blocks():
        for instruction in block.instructions():
            semantics = instruction.semantic()
            if semantics is None:
                continue
            print(
                hex(instruction.address()),
                semantics.status(),
                len(semantics.effects()),
                semantics.terminator().kind(),
            )
```

Disassembly does not eagerly collect LIR. Semantics are built on demand from the
decoded instruction detail when an accessor, lifter, symbolic executor, or decompiler
asks for them.

## Recommended Usage

If you are building on top of Binlex semantics:

- treat `Lir` as your canonical source IR
- use `Partial` plus diagnostics when you cannot model everything
- keep architecture-specific details in intrinsics or diagnostics instead of forcing them into
  inaccurate generic forms
- serialize with JSON when you need transport or persistence
- lower from semantics into your own IR rather than re-decoding raw bytes again

That is the intended extension point.
