# Semantics

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
  -> InstructionSemantics
  -> lifters or your own consumers
```

Semantics are not tied to one architecture backend. They describe:

- temporary values
- reads and writes
- memory effects
- intrinsics
- control-flow terminators
- partial/complete status
- diagnostics when modeling is incomplete

## Model

The top-level type is `InstructionSemantics`.

It contains:

- `version`
- `status`
- `temporaries`
- `effects`
- `terminator`
- `diagnostics`

The main building blocks are:

- `SemanticLocation`
  - register
  - flag
  - program counter
  - temporary
  - memory

- `SemanticExpression`
  - constants
  - reads
  - loads
  - unary/binary ops
  - casts
  - compares
  - select/extract/concat
  - intrinsics

- `SemanticEffect`
  - set
  - store
  - fence
  - trap
  - intrinsic
  - nop

- `SemanticTerminator`
  - fallthrough
  - jump
  - branch
  - call
  - return
  - unreachable
  - trap

## Status And Diagnostics

`SemanticStatus` is:

- `Complete`
- `Partial`

Use `Complete` only when the modeled effects are intended to be trusted as-is. In practice that
means:

- no missing architectural side effects that you know about
- no attached diagnostics

Use `Partial` when you can describe some of the instruction but not all of it. Attach
`SemanticDiagnostic` values to explain what is missing. That is the preferred way to model
unsupported or architecture-specific cases without inventing false precision.

Use `Partial` for intrinsic-backed placeholders when the intrinsic is carrying architectural detail
that is not yet modeled directly in the semantics IR.

## Rust Usage

Import the semantics types from `binlex::semantics`:

```rust
use binlex::semantics::{
    InstructionSemantics,
    SemanticEffect,
    SemanticExpression,
    SemanticLocation,
    SemanticOperationBinary,
    SemanticStatus,
    SemanticTerminator,
};
```

### Example: `eax = eax + 4; ret`

```rust
use binlex::semantics::{
    InstructionSemantics,
    SemanticEffect,
    SemanticExpression,
    SemanticLocation,
    SemanticOperationBinary,
    SemanticStatus,
    SemanticTerminator,
};

let semantics = InstructionSemantics {
    version: 1,
    status: SemanticStatus::Complete,
    temporaries: Vec::new(),
    effects: vec![
        SemanticEffect::Set {
            dst: SemanticLocation::Register {
                name: "eax".to_string(),
                bits: 32,
            },
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::Add,
                left: Box::new(SemanticExpression::Read(Box::new(
                    SemanticLocation::Register {
                        name: "eax".to_string(),
                        bits: 32,
                    },
                ))),
                right: Box::new(SemanticExpression::Const {
                    value: 4,
                    bits: 32,
                }),
                bits: 32,
            },
        },
    ],
    terminator: SemanticTerminator::Return { expression: None },
    diagnostics: Vec::new(),
};
```

### Example: explicit memory store

```rust
use binlex::semantics::{
    InstructionSemantics,
    SemanticAddressSpace,
    SemanticEffect,
    SemanticExpression,
    SemanticLocation,
    SemanticStatus,
    SemanticTerminator,
};

let semantics = InstructionSemantics {
    version: 1,
    status: SemanticStatus::Complete,
    temporaries: Vec::new(),
    effects: vec![
        SemanticEffect::Store {
            space: SemanticAddressSpace::Stack,
            addr: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                name: "rsp".to_string(),
                bits: 64,
            })),
            expression: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                name: "rax".to_string(),
                bits: 64,
            })),
            bits: 64,
        },
    ],
    terminator: SemanticTerminator::FallThrough,
    diagnostics: Vec::new(),
};
```

### Example: partial semantics

```rust
use binlex::semantics::{
    InstructionSemantics,
    SemanticDiagnostic,
    SemanticDiagnosticKind,
    SemanticStatus,
    SemanticTerminator,
};

let semantics = InstructionSemantics {
    version: 1,
    status: SemanticStatus::Partial,
    temporaries: Vec::new(),
    effects: Vec::new(),
    terminator: SemanticTerminator::Trap,
    diagnostics: vec![
        SemanticDiagnostic {
            kind: SemanticDiagnosticKind::UnsupportedInstruction,
            message: "instruction not modeled yet".to_string(),
        },
    ],
};
```

### Serializing semantics

Semantics serialize cleanly with Serde:

```rust
let json = serde_json::to_string_pretty(&semantics.process())?;
println!("{}", json);
```

`u128` constants are serialized safely as strings in JSON, so large constant values survive
transport and storage without loss.

## Python Usage

The Python bindings expose the same model through `binlex.semantics`.

```python
from binlex.semantics import (
    InstructionSemantics,
    SemanticDiagnostic,
    SemanticDiagnosticKind,
    SemanticEffect,
    SemanticExpression,
    SemanticLocation,
    SemanticOperationBinary,
    SemanticStatus,
    SemanticTerminator,
)
```

### Example: `eax = eax + 4; ret`

```python
from binlex.semantics import (
    InstructionSemantics,
    SemanticEffect,
    SemanticExpression,
    SemanticLocation,
    SemanticOperationBinary,
    SemanticStatus,
    SemanticTerminator,
)

eax = SemanticLocation.register("eax", 32)

expr = SemanticExpression.binary(
    SemanticOperationBinary.Add,
    SemanticExpression.read(eax),
    SemanticExpression.const(4, 32),
    32,
)

semantics = InstructionSemantics(
    1,
    SemanticStatus.Complete,
    effects=[
        SemanticEffect.set(eax, expr),
    ],
    terminator=SemanticTerminator.return_(),
)
```

### Example: partial semantics with diagnostics

```python
from binlex.semantics import (
    InstructionSemantics,
    SemanticDiagnostic,
    SemanticDiagnosticKind,
    SemanticStatus,
    SemanticTerminator,
)

semantics = InstructionSemantics(
    1,
    SemanticStatus.Partial,
    diagnostics=[
        SemanticDiagnostic(
            SemanticDiagnosticKind.UnsupportedInstruction,
            "custom instruction not modeled yet",
        ),
    ],
    terminator=SemanticTerminator.trap(),
)
```

### Example: inspect and serialize

```python
print(semantics.json())

data = semantics.to_dict()
round_tripped = InstructionSemantics.from_dict(data)
```

The Python bindings also expose constructors for the lower-level pieces:

- `SemanticTemporary(...)`
- `SemanticLocation.register(...)`
- `SemanticLocation.flag(...)`
- `SemanticLocation.program_counter(...)`
- `SemanticLocation.temporary(...)`
- `SemanticLocation.memory(...)`
- `SemanticExpression.const(...)`
- `SemanticExpression.read(...)`
- `SemanticExpression.load(...)`
- `SemanticExpression.unary(...)`
- `SemanticExpression.binary(...)`
- `SemanticExpression.cast(...)`
- `SemanticExpression.compare(...)`
- `SemanticExpression.select(...)`
- `SemanticExpression.extract(...)`
- `SemanticExpression.concat(...)`
- `SemanticExpression.undefined(...)`
- `SemanticExpression.poison(...)`
- `SemanticExpression.intrinsic(...)`
- `SemanticEffect.set(...)`
- `SemanticEffect.store(...)`
- `SemanticEffect.fence(...)`
- `SemanticEffect.trap(...)`
- `SemanticEffect.intrinsic(...)`
- `SemanticEffect.nop()`
- `SemanticTerminator.fallthrough()`
- `SemanticTerminator.jump(...)`
- `SemanticTerminator.branch(...)`
- `SemanticTerminator.call(...)`
- `SemanticTerminator.return_(...)`
- `SemanticTerminator.unreachable()`
- `SemanticTerminator.trap()`

## Using Semantics From Disassembly

Binlex semantics are enabled by default during disassembly.

Rust:

```rust
use binlex::controlflow::Graph;
use binlex::disassemblers::capstone::Disassembler;
use binlex::formats::PE;
use binlex::Config;

let config = Config::default();
let pe = PE::new("samples/kernel32.dll", config.clone())?;
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

for function in graph.functions():
    for block in function.blocks():
        for instruction in block.instructions():
            semantics = instruction.semantics()
            if semantics is None:
                continue
            print(
                hex(instruction.address()),
                semantics.status(),
                len(semantics.effects()),
                semantics.terminator().kind(),
            )
```

If you want a faster CLI-only or graph-only run, semantics can be disabled:

```toml
[binlex.semantics]
enabled = false
```

or by using `--minimal` in the CLI.

If you want semantics to remain available through `instruction.semantics()` but omit them from
serialized instruction JSON:

```toml
[binlex.instructions.semantics]
enabled = false
```

## Recommended Usage

If you are building on top of Binlex semantics:

- treat `InstructionSemantics` as your canonical source IR
- use `Partial` plus diagnostics when you cannot model everything
- keep architecture-specific details in intrinsics or diagnostics instead of forcing them into
  inaccurate generic forms
- serialize with JSON when you need transport or persistence
- lower from semantics into your own IR rather than re-decoding raw bytes again

That is the intended extension point.
