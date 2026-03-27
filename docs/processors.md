# Custom Processors

This page shows the simplest way to build a processor for Binlex.

## What A Processor Does

A processor takes Binlex data, runs some analysis, and returns JSON that gets attached back to the graph.

This means, you can build your own processor for your own analysis workflow and share your processor binary with others.

You can run a processor at five levels:

- `instruction`
- `block`
- `function`
- `graph`
- `complete`

Most processors follow this shape:

1. Define a request type.
2. Define a response type.
3. Implement `Processor::execute(...)`.
4. Implement `GraphProcessor` hooks for the levels you care about.
5. Export a `registration()` that declares supported platforms and default config.

## The Easiest Mental Model

Think of the processor API as two layers:

- `Processor` is the worker. It accepts a typed request and returns a typed response.
- `GraphProcessor` is the adapter. It tells Binlex how to build requests from graph entities and where to attach the results.

If your request and response already match the JSON sent by Binlex, you usually only need:

- `impl Processor`
- `impl GraphProcessor`
- `registration()`

## Minimal Example

This example attaches the size of each function in bytes.

```rust
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use binlex::config::{
    ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
};
use binlex::controlflow::{Function, Graph};
use binlex::core::{Architecture, OperatingSystem, Transport};
use binlex::processor::{
    GraphProcessor, GraphProcessorFanout, OnGraphOptions, external_processor_registration,
};
use binlex::runtime::{Processor, ProcessorError};

#[derive(Serialize, Deserialize, Clone)]
pub struct ExampleRequest {
    pub bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExampleResponse {
    pub size: usize,
}

#[derive(Default)]
pub struct ExampleProcessor;

impl Processor for ExampleProcessor {
    const NAME: &'static str = "example";
    type Request = ExampleRequest;
    type Response = ExampleResponse;

    fn execute(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        Ok(ExampleResponse {
            size: request.bytes.len(),
        })
    }
}

impl GraphProcessor for ExampleProcessor {
    fn function_message(function: &Function<'_>) -> Option<Value> {
        let bytes = function.bytes()?;
        Some(json!({ "bytes": bytes }))
    }

    fn on_function(function: &Function<'_>) -> Option<Value> {
        let bytes = function.bytes()?;
        let response = Self::execute_owned(ExampleRequest { bytes }).ok()?;
        Some(json!({ "size": response.size, "address": function.address() }))
    }

    fn on_graph_options() -> OnGraphOptions {
        OnGraphOptions {
            instructions: false,
            blocks: false,
            functions: false,
        }
    }

    fn on_graph(_: &Graph) -> Option<GraphProcessorFanout> {
        None
    }
}

pub fn registration() -> binlex::processor::ProcessorRegistration {
    external_processor_registration(
        ExampleProcessor::NAME,
        ">=2.0.0 <2.1.0",
        &[OperatingSystem::LINUX, OperatingSystem::MACOS],
        &[Architecture::AMD64, Architecture::I386],
        &[Transport::IPC, Transport::HTTP],
        ExampleProcessor::on_graph_options(),
        ConfigProcessor {
            enabled: false,
            instructions: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            blocks: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            functions: ConfigProcessorTarget {
                enabled: true,
                options: BTreeMap::new(),
            },
            graph: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            complete: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            options: BTreeMap::new(),
            transport: ConfigProcessorTransports {
                ipc: ConfigProcessorTransport {
                    enabled: true,
                    options: BTreeMap::new(),
                },
                http: ConfigProcessorTransport {
                    enabled: false,
                    options: BTreeMap::from([
                        ("url".to_string(), "http://127.0.0.1:5000".into()),
                        ("verify".to_string(), false.into()),
                    ]),
                },
            },
        },
    )
}
```

## Which Methods Matter

### `Processor::execute(...)`

This is the only required analysis method.

- Input: `Self::Request`
- Output: `Self::Response`

It should not know anything about Binlex graph internals. It should only process the request it receives.

### `instruction_message`, `block_message`, `function_message`, `graph_message`

These methods build the JSON payload sent to your processor.

Defaults:

- instruction, block, and function messages serialize the entity's base JSON
- graph messages default to `None`

Override these when your processor needs a different request shape.

### `request_message(...)`

This converts incoming JSON into `Self::Request`.

The default implementation is:

```rust
serde_json::from_value(data)
```

If your request type matches the JSON payload, you do not need to override it.

### `response_message(...)`

This converts `Self::Response` back into JSON.

The default implementation is:

```rust
serde_json::to_value(response)
```

If your response type is already serializable into the JSON you want, leave it alone.

## Lifecycle

Binlex can call these hooks during processing:

- `on_instruction(...)` for each instruction
- `on_block(...)` for each block
- `on_function(...)` for each function
- `on_graph(...)` after the graph is complete
- `on_complete(...)` after all processor stages have completed

The `on_*` hooks are optional. Return `None` to skip output.

## When To Use `on_graph`

Use `on_graph(...)` when the analysis needs the whole graph at once.

Typical examples:

- embeddings
- whole-function CFG features
- ranking or scoring that compares many entities together

`on_graph(...)` returns a `GraphProcessorFanout`, which lets you attach results back to individual entities by address:

```rust
GraphProcessorFanout {
    instructions: BTreeMap::new(),
    blocks: BTreeMap::new(),
    functions: BTreeMap::new(),
}
```

## `OnGraphOptions`

Graph-stage processors can ask Binlex to include full entity collections in the graph payload:

```rust
fn on_graph_options() -> OnGraphOptions {
    OnGraphOptions {
        instructions: false,
        blocks: false,
        functions: true,
    }
}
```

This matters only for graph-level transport payloads.

Use it to keep requests small:

- enable only the collections your processor actually needs
- leave unused collections as `false`

## Choosing A Pattern

Use per-entity hooks when:

- each instruction, block, or function can be processed independently
- you want simple behavior
- you do not need whole-graph context

Use `on_graph(...)` when:

- the analysis needs relationships across the graph
- you want one pass that fans results back to many entities
- you want to perform multi-threading

## When To Use `on_complete`

Use `on_complete(...)` when the processor needs the fully processed graph and wants to persist,
export, or publish the results.

Typical examples:

- storing finalized processor outputs
- indexing enriched functions or blocks
- writing graph artifacts to external systems

`on_complete(...)` is a terminal stage. It should consume the finalized graph state and perform
side effects rather than attaching new outputs back onto entities.

## Registration

`registration()` tells Binlex how to discover and configure the processor.

It should declare:

- processor name
- compatible Binlex version range
- supported operating systems
- supported architectures
- supported transports
- graph payload options
- default processor config

The backend executable name is derived from the processor name:

```text
binlex-processor-<name>
```

So a processor named `example` is expected to ship as:

```text
binlex-processor-example
```
