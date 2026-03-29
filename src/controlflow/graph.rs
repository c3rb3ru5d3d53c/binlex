// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::Architecture;
use crate::Config;
use crate::controlflow::Block;
use crate::controlflow::Function;
use crate::controlflow::Instruction;
use crate::processor::{ProcessorOutputs, ProcessorTarget};
use crossbeam::queue::SegQueue;
use crossbeam_skiplist::SkipMap;
use crossbeam_skiplist::SkipSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::io::Error;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct GraphQueueSnapshot {
    pub valid: BTreeSet<u64>,
    pub invalid: BTreeSet<u64>,
    pub processed: BTreeSet<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub architecture: String,
    pub instructions: Vec<crate::controlflow::InstructionJson>,
    pub instruction_queue: GraphQueueSnapshot,
    pub block_queue: GraphQueueSnapshot,
    pub function_queue: GraphQueueSnapshot,
    #[serde(default)]
    pub processor_outputs: GraphProcessorOutputsSnapshot,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct GraphProcessorOutputsSnapshot {
    #[serde(default)]
    pub instructions: HashMap<u64, ProcessorOutputs>,
    #[serde(default)]
    pub blocks: HashMap<u64, ProcessorOutputs>,
    #[serde(default)]
    pub functions: HashMap<u64, ProcessorOutputs>,
}

/// Queue structure used within `Graph` for managing addresses in processing stages.
pub struct GraphQueue {
    /// Queue of addresses to be processed.
    pub queue: SegQueue<u64>,
    /// Set of addresses that have been processed.
    pub processed: SkipSet<u64>,
    /// Set of valid addresses in the graph.
    pub valid: SkipSet<u64>,
    /// Set of invalid addresses in the graph.
    pub invalid: SkipSet<u64>,
    /// Pending addresses in the graph.
    pub pending: SkipSet<u64>,
}

impl Clone for GraphQueue {
    /// Creates a clone of the `GraphQueue`, including all processed, valid, and invalid addresses.
    fn clone(&self) -> Self {
        let cloned_queue = SegQueue::new();
        let mut temp_queue = Vec::new();
        while let Some(item) = self.queue.pop() {
            cloned_queue.push(item);
            temp_queue.push(item);
        }
        for item in temp_queue {
            self.queue.push(item);
        }
        let cloned_processed = SkipSet::new();
        for item in self.processed.iter() {
            cloned_processed.insert(*item);
        }
        let cloned_valid = SkipSet::new();
        for item in self.valid.iter() {
            cloned_valid.insert(*item);
        }
        let cloned_invalid = SkipSet::new();
        for item in self.invalid.iter() {
            cloned_invalid.insert(*item);
        }
        let cloned_pending = SkipSet::new();
        for item in self.pending.iter() {
            cloned_pending.insert(*item);
        }
        GraphQueue {
            queue: cloned_queue,
            processed: cloned_processed,
            valid: cloned_valid,
            invalid: cloned_invalid,
            pending: cloned_pending,
        }
    }
}

impl GraphQueue {
    /// Creates a new, empty `GraphQueue` instance.
    ///
    /// # Returns
    ///
    /// Returns a new `GraphQueue` instance with empty sets and queues.
    pub fn new() -> Self {
        Self {
            queue: SegQueue::<u64>::new(),
            processed: SkipSet::<u64>::new(),
            valid: SkipSet::<u64>::new(),
            invalid: SkipSet::<u64>::new(),
            pending: SkipSet::<u64>::new(),
        }
    }

    /// Marks an address as invalid if it has not been marked as valid.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to mark as invalid.
    pub fn insert_invalid(&mut self, address: u64) {
        if !self.is_invalid(address) && !self.is_valid(address) {
            self.invalid.insert(address);
        }
    }

    /// Checks if an address is marked as invalid.
    ///
    /// # Returns
    ///
    /// Returns `true` if the address is invalid, otherwise `false`.
    pub fn is_invalid(&self, address: u64) -> bool {
        self.invalid.contains(&address)
    }

    /// Retrieves a reference to the invalid address set.
    ///
    /// # Returns
    ///
    /// Returns a reference to the `SkipSet` containing invalid addresses.
    #[allow(dead_code)]
    pub fn invalid(&self) -> &SkipSet<u64> {
        &self.invalid
    }

    /// Retrieves a reference to the valid address set.
    ///
    /// # Returns
    ///
    /// Returns a reference to the `SkipSet` containing valid addresses.
    pub fn valid(&self) -> &SkipSet<u64> {
        &self.valid
    }

    /// Collects valid addresses in a set
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet` containing valid addresses.
    pub fn valid_addresses(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        for entry in self.valid() {
            result.insert(*entry.value());
        }
        result
    }

    /// Collects invalid addresses in a set
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet` containing valid addresses.
    pub fn invalid_addresses(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        for entry in self.invalid() {
            result.insert(*entry.value());
        }
        result
    }

    /// Collects processed addresses in a set
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet` containing processed addresses.
    pub fn processed_addresses(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        for entry in self.processed() {
            result.insert(*entry.value());
        }
        result
    }

    /// Retrieves a reference to the processed address set.
    ///
    /// # Returns
    ///
    /// Returns a reference to the `SkipSet` containing processed addresses.
    pub fn processed(&self) -> &SkipSet<u64> {
        &self.processed
    }

    /// Checks if an address is marked as valid.
    ///
    /// # Returns
    ///
    /// Returns `true` if the address is valid, otherwise `false`.
    pub fn is_valid(&self, address: u64) -> bool {
        self.valid.contains(&address)
    }

    /// Marks an address as valid if it has been processed.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to mark as valid.
    pub fn insert_valid(&mut self, address: u64) {
        if self.is_processed(address) {
            self.valid.insert(address);
        }
    }

    /// Marks multiple addresses as processed.
    ///
    /// # Arguments
    ///
    /// * `addresses` - A set of addresses to mark as processed.
    pub fn insert_processed_extend(&mut self, addresses: BTreeSet<u64>) {
        for address in addresses {
            self.insert_processed(address);
        }
    }

    /// Marks a single address as processed.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to mark as processed.
    pub fn insert_processed(&mut self, address: u64) {
        self.processed.insert(address);
    }

    /// Checks if an address has been processed.
    ///
    /// # Returns
    ///
    /// Returns `true` if the address is processed, otherwise `false`.
    pub fn is_processed(&self, address: u64) -> bool {
        self.processed.contains(&address)
    }

    /// Adds multiple addresses to the processing queue.
    ///
    /// # Arguments
    ///
    /// * `addresses` - A set of addresses to enqueue.
    pub fn enqueue_extend(&mut self, addresses: BTreeSet<u64>) {
        for address in addresses {
            self.enqueue(address);
        }
    }

    /// Adds an address to the processing queue if it hasn't been processed.
    ///
    /// # Returns
    ///
    /// Returns `true` if the address was enqueued, otherwise `false`.
    pub fn enqueue(&mut self, address: u64) -> bool {
        if self.is_processed(address) {
            return false;
        }
        if self.pending.contains(&address) {
            return false;
        }
        self.pending.insert(address);
        self.queue.push(address);
        true
    }

    /// Checks if an address is currently pending in the queue.
    ///
    /// # Returns
    ///
    /// Returns `true` if the address is pending processing, otherwise `false`.
    pub fn is_pending(&self, address: u64) -> bool {
        self.pending.contains(&address)
    }

    /// Removes an address from the processing queue.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the dequeued address if available, otherwise `None`.
    pub fn dequeue(&mut self) -> Option<u64> {
        if let Some(x) = self.queue.pop() {
            self.pending.remove(&x);
            return Some(x);
        }
        None
    }

    /// Removes all addresses from the processing queue.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing all dequeued addresses.
    pub fn dequeue_all(&mut self) -> BTreeSet<u64> {
        let mut set = BTreeSet::new();
        while let Some(address) = self.queue.pop() {
            self.pending.remove(&address);
            set.insert(address);
        }
        set
    }
}

impl Default for GraphQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a control flow graph with instructions, blocks, and functions.
#[derive(Default)]
struct GraphProcessorState {
    revisions: HashMap<ProcessorTarget, u64>,
    outputs: HashMap<ProcessorTarget, HashMap<u64, ProcessorOutputs>>,
}

pub struct Graph {
    /// The Instruction Architecture
    pub architecture: Architecture,
    /// A map of instruction addresses to `Instruction` instances.
    pub listing: SkipMap<u64, Instruction>,
    /// Queue for managing basic blocks within the graph.
    pub blocks: GraphQueue,
    /// Queue for managing functions within the graph.
    pub functions: GraphQueue,
    /// Queue for managing instructions within the graph.
    pub instructions: GraphQueue,
    /// Configuration
    pub config: Config,
    revision: AtomicU64,
    processor_state: Mutex<GraphProcessorState>,
}

impl Graph {
    /// Creates a new, empty `Graph` instance with default options.
    ///
    /// # Returns
    ///
    /// Returns a `Graph` instance with empty instructions, blocks, and functions.
    #[allow(dead_code)]
    pub fn new(architecture: Architecture, config: Config) -> Self {
        Self {
            architecture,
            listing: SkipMap::<u64, Instruction>::new(),
            blocks: GraphQueue::new(),
            functions: GraphQueue::new(),
            instructions: GraphQueue::new(),
            config,
            revision: AtomicU64::new(0),
            processor_state: Mutex::new(GraphProcessorState::default()),
        }
    }

    pub fn snapshot(&self) -> GraphSnapshot {
        let instructions = self
            .listing
            .iter()
            .map(|entry| {
                let instruction = entry.value();
                let mut json = instruction.process();
                json.chromosome.mask = crate::hex::encode(&instruction.chromosome_mask);
                json
            })
            .collect();
        let processor_outputs = {
            let processor_state = self.processor_state.lock().unwrap();
            GraphProcessorOutputsSnapshot {
                instructions: processor_state
                    .outputs
                    .get(&ProcessorTarget::Instruction)
                    .cloned()
                    .unwrap_or_default(),
                blocks: processor_state
                    .outputs
                    .get(&ProcessorTarget::Block)
                    .cloned()
                    .unwrap_or_default(),
                functions: processor_state
                    .outputs
                    .get(&ProcessorTarget::Function)
                    .cloned()
                    .unwrap_or_default(),
            }
        };

        GraphSnapshot {
            architecture: self.architecture.to_string(),
            instructions,
            instruction_queue: Self::snapshot_queue(&self.instructions),
            block_queue: Self::snapshot_queue(&self.blocks),
            function_queue: Self::snapshot_queue(&self.functions),
            processor_outputs,
        }
    }

    pub fn from_snapshot(snapshot: GraphSnapshot, config: Config) -> Result<Self, Error> {
        let architecture = Architecture::from_string(&snapshot.architecture)?;
        let mut graph = Self::new(architecture, config.clone());

        for json in snapshot.instructions {
            let instruction_architecture = Architecture::from_string(&json.architecture)?;
            if instruction_architecture != architecture {
                return Err(Error::other(format!(
                    "snapshot instruction architecture mismatch: expected {}, got {}",
                    architecture, instruction_architecture
                )));
            }

            let mut instruction = Instruction::create(json.address, architecture, config.clone());
            instruction.is_prologue = json.is_prologue;
            instruction.is_block_start = json.is_block_start;
            instruction.is_function_start = json.is_function_start;
            instruction.is_return = json.is_return;
            instruction.is_call = json.is_call;
            instruction.is_jump = json.is_jump;
            instruction.is_conditional = json.is_conditional;
            instruction.is_trap = json.is_trap;
            instruction.has_indirect_target = json.has_indirect_target;
            instruction.edges = json.edges;
            instruction.bytes =
                crate::hex::decode(&json.bytes).map_err(|error| Error::other(error.to_string()))?;
            instruction.chromosome_mask = if json.chromosome.mask.is_empty() {
                vec![0; instruction.bytes.len()]
            } else {
                crate::hex::decode(&json.chromosome.mask)
                    .map_err(|error| Error::other(error.to_string()))?
            };
            instruction.pattern = json.chromosome.pattern;
            instruction.functions = json.functions;
            instruction.to = json.to;
            graph.listing.insert(instruction.address, instruction);
        }

        Self::restore_queue(&mut graph.instructions, snapshot.instruction_queue);
        Self::restore_queue(&mut graph.blocks, snapshot.block_queue);
        Self::restore_queue(&mut graph.functions, snapshot.function_queue);
        {
            let mut processor_state = graph.processor_state.lock().unwrap();
            if !snapshot.processor_outputs.instructions.is_empty() {
                processor_state.outputs.insert(
                    ProcessorTarget::Instruction,
                    snapshot.processor_outputs.instructions,
                );
                processor_state
                    .revisions
                    .insert(ProcessorTarget::Instruction, 0);
            }
            if !snapshot.processor_outputs.blocks.is_empty() {
                processor_state
                    .outputs
                    .insert(ProcessorTarget::Block, snapshot.processor_outputs.blocks);
                processor_state.revisions.insert(ProcessorTarget::Block, 0);
            }
            if !snapshot.processor_outputs.functions.is_empty() {
                processor_state.outputs.insert(
                    ProcessorTarget::Function,
                    snapshot.processor_outputs.functions,
                );
                processor_state
                    .revisions
                    .insert(ProcessorTarget::Function, 0);
                processor_state.revisions.insert(ProcessorTarget::Graph, 0);
            }
        }

        Ok(graph)
    }

    pub fn instructions(&self) -> Vec<Instruction> {
        let mut result = Vec::<Instruction>::new();
        for address in self.instructions.valid_addresses() {
            let instruction = Instruction::new(address, self).ok();
            if instruction.is_none() {
                continue;
            }
            result.push(instruction.unwrap());
        }
        result
    }

    pub fn blocks(&self) -> Vec<Block<'_>> {
        let _ = self.process_blocks();
        let mut result = Vec::<Block>::new();
        for address in self.blocks.valid_addresses() {
            let block = Block::new(address, self).ok();
            if block.is_none() {
                continue;
            }
            result.push(block.unwrap());
        }
        result
    }

    pub fn functions(&self) -> Vec<Function<'_>> {
        let _ = self.process_functions();
        let mut result = Vec::<Function>::new();
        for address in self.functions.valid_addresses() {
            let function = Function::new(address, self).ok();
            if function.is_none() {
                continue;
            }
            result.push(function.unwrap());
        }
        result
    }

    pub fn instruction_addresses(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        for entry in &self.listing {
            result.insert(*entry.key());
        }
        result
    }

    pub fn listing(&self) -> &SkipMap<u64, Instruction> {
        &self.listing
    }

    pub fn mutations(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    pub fn set_function(&mut self, address: u64) -> bool {
        let mut instruction = match self.get_instruction(address) {
            Some(instruction) => instruction,
            None => {
                return false;
            }
        };
        self.functions.insert_processed(address);
        self.functions.insert_valid(address);
        instruction.is_function_start = true;
        instruction.is_block_start = true;
        self.update_instruction(instruction);
        self.invalidate_processor_state();
        true
    }

    pub fn set_block(&mut self, address: u64) -> bool {
        let mut instruction = match self.get_instruction(address) {
            Some(instruction) => instruction,
            None => {
                return false;
            }
        };
        self.blocks.insert_processed(address);
        self.blocks.insert_valid(address);
        instruction.is_block_start = true;
        self.update_instruction(instruction);
        self.invalidate_processor_state();
        true
    }

    pub fn extend_instruction_edges(&mut self, address: u64, addresses: BTreeSet<u64>) -> bool {
        let mut instruction = match self.get_instruction(address) {
            Some(instruction) => instruction,
            None => {
                return false;
            }
        };
        instruction.to.extend(addresses);
        instruction.edges = instruction.blocks().len();
        self.update_instruction(instruction);
        self.invalidate_processor_state();
        true
    }

    pub fn insert_instruction(&mut self, instruction: Instruction) {
        self.invalidate_processor_state();
        if let Some(existing) = self.get_instruction(instruction.address) {
            self.listing.insert(
                instruction.address,
                Graph::merge_instruction(existing, instruction),
            );
            return;
        }
        self.listing.insert(instruction.address, instruction);
    }

    pub fn update_instruction(&mut self, instruction: Instruction) {
        self.invalidate_processor_state();
        if !self.is_instruction_address(instruction.address) {
            return;
        }
        self.listing.insert(instruction.address, instruction);
    }

    pub fn is_instruction_address(&self, address: u64) -> bool {
        self.listing.contains_key(&address)
    }

    pub fn get_instruction(&self, address: u64) -> Option<Instruction> {
        self.listing
            .get(&address)
            .map(|entry| entry.value().clone())
    }

    fn merge_instruction(mut existing: Instruction, incoming: Instruction) -> Instruction {
        existing.is_prologue |= incoming.is_prologue;
        existing.is_block_start |= incoming.is_block_start;
        existing.is_function_start |= incoming.is_function_start;
        existing.is_return |= incoming.is_return;
        existing.is_call |= incoming.is_call;
        existing.is_jump |= incoming.is_jump;
        existing.is_conditional |= incoming.is_conditional;
        existing.is_trap |= incoming.is_trap;
        existing.has_indirect_target |= incoming.has_indirect_target;
        existing.edges = existing.edges.max(incoming.edges);
        existing.to.extend(incoming.to);
        existing.functions.extend(incoming.functions);
        if existing.bytes.is_empty() {
            existing.bytes = incoming.bytes;
        }
        if existing.chromosome_mask.is_empty() {
            existing.chromosome_mask = incoming.chromosome_mask;
        }
        if existing.pattern.is_empty() {
            existing.pattern = incoming.pattern;
        }
        existing
    }

    pub fn merge(&mut self, graph: &mut Graph) {
        self.invalidate_processor_state();
        for entry in graph.listing() {
            self.insert_instruction(entry.value().clone());
        }

        for entry in graph.instructions.processed() {
            self.instructions.insert_processed(*entry.value());
        }

        self.instructions
            .enqueue_extend(graph.instructions.dequeue_all());

        for entry in graph.blocks.processed() {
            self.blocks.insert_processed(*entry.value());
        }

        self.blocks.enqueue_extend(graph.blocks.dequeue_all());

        for entry in graph.functions.processed() {
            self.functions.insert_processed(*entry.value());
        }

        self.functions.enqueue_extend(graph.functions.dequeue_all());

        for entry in graph.instructions.valid() {
            self.instructions.insert_valid(*entry.value());
        }

        for entry in graph.instructions.invalid() {
            self.instructions.insert_invalid(*entry.value());
        }

        for entry in graph.blocks.valid() {
            self.blocks.insert_valid(*entry.value());
        }

        for entry in graph.blocks.invalid() {
            self.blocks.insert_invalid(*entry.value());
        }

        for entry in graph.functions.valid() {
            self.functions.insert_valid(*entry.value());
        }

        for entry in graph.functions.invalid() {
            self.functions.insert_invalid(*entry.value());
        }
    }

    pub fn process(&self) -> Result<(), Error> {
        self.process_instructions()?;
        self.process_blocks()?;
        self.process_functions()?;
        self.process_graph()?;
        self.process_complete()?;
        Ok(())
    }

    pub fn process_instructions(&self) -> Result<(), Error> {
        self.process_target(ProcessorTarget::Instruction)
    }

    pub fn process_blocks(&self) -> Result<(), Error> {
        self.process_target(ProcessorTarget::Block)
    }

    pub fn process_functions(&self) -> Result<(), Error> {
        self.process_target(ProcessorTarget::Function)
    }

    pub fn process_graph(&self) -> Result<(), Error> {
        self.process_target(ProcessorTarget::Graph)
    }

    pub fn process_complete(&self) -> Result<(), Error> {
        self.process_instructions()?;
        self.process_blocks()?;
        self.process_functions()?;
        self.process_graph()?;
        self.process_target(ProcessorTarget::Complete)
    }

    pub fn processor_outputs(
        &self,
        target: ProcessorTarget,
        address: u64,
    ) -> Option<ProcessorOutputs> {
        self.processor_state
            .lock()
            .unwrap()
            .outputs
            .get(&target)?
            .get(&address)
            .cloned()
    }

    pub fn processor_output(
        &self,
        target: ProcessorTarget,
        address: u64,
        processor_name: &str,
    ) -> Option<Value> {
        let processor_state = self.processor_state.lock().unwrap();
        let outputs = processor_state.outputs.get(&target)?.get(&address)?;
        outputs
            .iter()
            .find(|(name, _)| *name == processor_name)
            .map(|(_, output)| output.clone())
    }

    fn process_target(&self, target: ProcessorTarget) -> Result<(), Error> {
        let enabled = crate::processor::enabled_processors_for_target(&self.config, target);
        let revision = self.revision.load(Ordering::SeqCst);
        {
            let processor_state = self.processor_state.lock().unwrap();
            if processor_state.revisions.get(&target) == Some(&revision) {
                return Ok(());
            }
        }

        if enabled.is_empty() {
            let mut processor_state = self.processor_state.lock().unwrap();
            if self.revision.load(Ordering::SeqCst) == revision {
                if !matches!(target, ProcessorTarget::Graph | ProcessorTarget::Complete) {
                    processor_state.outputs.entry(target).or_default();
                }
                processor_state.revisions.insert(target, revision);
            }
            return Ok(());
        }

        let mut outputs = HashMap::new();
        let remote_processors = enabled;
        match target {
            ProcessorTarget::Instruction => {
                for address in self.instructions.valid_addresses() {
                    let instruction = match self.get_instruction(address) {
                        Some(instruction) => instruction,
                        None => continue,
                    };
                    let mut entity_outputs = Vec::new();
                    for processor in &remote_processors {
                        if let Some(output) = processor.process_instruction(&instruction) {
                            entity_outputs.push((processor.name().to_string(), output));
                        }
                    }
                    if !entity_outputs.is_empty() {
                        outputs.insert(address, entity_outputs);
                    }
                }
            }
            ProcessorTarget::Block => {
                for address in self.blocks.valid_addresses() {
                    let block = match Block::new(address, self) {
                        Ok(block) => block,
                        Err(_) => continue,
                    };
                    let mut entity_outputs = Vec::new();
                    for processor in &remote_processors {
                        if let Some(output) = processor.process_block(&block) {
                            entity_outputs.push((processor.name().to_string(), output));
                        }
                    }
                    if !entity_outputs.is_empty() {
                        outputs.insert(address, entity_outputs);
                    }
                }
            }
            ProcessorTarget::Function => {
                for address in self.functions.valid_addresses() {
                    let function = match Function::new(address, self) {
                        Ok(function) => function,
                        Err(_) => continue,
                    };
                    let mut entity_outputs = Vec::new();
                    for processor in &remote_processors {
                        if let Some(output) = processor.process_function(&function) {
                            entity_outputs.push((processor.name().to_string(), output));
                        }
                    }
                    if !entity_outputs.is_empty() {
                        outputs.insert(address, entity_outputs);
                    }
                }
            }
            ProcessorTarget::Graph => {
                let mut instruction_outputs = HashMap::new();
                let mut block_outputs = HashMap::new();
                let mut function_outputs = HashMap::new();
                for processor in &remote_processors {
                    let Some(fanout) = processor.process_graph(self) else {
                        continue;
                    };

                    for (address, output) in fanout.instructions {
                        instruction_outputs
                            .entry(address)
                            .or_insert_with(Vec::new)
                            .push((processor.name().to_string(), output));
                    }

                    for (address, output) in fanout.blocks {
                        block_outputs
                            .entry(address)
                            .or_insert_with(Vec::new)
                            .push((processor.name().to_string(), output));
                    }

                    for (address, output) in fanout.functions {
                        function_outputs
                            .entry(address)
                            .or_insert_with(Vec::new)
                            .push((processor.name().to_string(), output));
                    }
                }

                let mut processor_state = self.processor_state.lock().unwrap();
                if self.revision.load(Ordering::SeqCst) == revision {
                    Self::merge_target_outputs(
                        &mut processor_state.outputs,
                        ProcessorTarget::Instruction,
                        instruction_outputs,
                    );
                    Self::merge_target_outputs(
                        &mut processor_state.outputs,
                        ProcessorTarget::Block,
                        block_outputs,
                    );
                    Self::merge_target_outputs(
                        &mut processor_state.outputs,
                        ProcessorTarget::Function,
                        function_outputs,
                    );
                    processor_state.revisions.insert(target, revision);
                }
                return Ok(());
            }
            ProcessorTarget::Complete => {
                for processor in &remote_processors {
                    processor
                        .process_complete(self)
                        .map_err(|error| Error::other(error.to_string()))?;
                }

                let mut processor_state = self.processor_state.lock().unwrap();
                if self.revision.load(Ordering::SeqCst) == revision {
                    processor_state.revisions.insert(target, revision);
                }
                return Ok(());
            }
        }

        let mut processor_state = self.processor_state.lock().unwrap();
        if self.revision.load(Ordering::SeqCst) == revision {
            processor_state.outputs.insert(target, outputs);
            processor_state.revisions.insert(target, revision);
        }
        Ok(())
    }

    fn invalidate_processor_state(&self) {
        self.revision.fetch_add(1, Ordering::SeqCst);
        let mut processor_state = self.processor_state.lock().unwrap();
        processor_state.revisions.clear();
        processor_state.outputs.clear();
    }

    fn snapshot_queue(queue: &GraphQueue) -> GraphQueueSnapshot {
        GraphQueueSnapshot {
            valid: queue.valid_addresses(),
            invalid: queue.invalid_addresses(),
            processed: queue.processed_addresses(),
        }
    }

    fn restore_queue(queue: &mut GraphQueue, snapshot: GraphQueueSnapshot) {
        for address in snapshot.processed {
            queue.insert_processed(address);
        }
        for address in snapshot.valid {
            queue.insert_valid(address);
        }
        for address in snapshot.invalid {
            queue.insert_invalid(address);
        }
    }

    fn merge_target_outputs(
        state_outputs: &mut HashMap<ProcessorTarget, HashMap<u64, ProcessorOutputs>>,
        target: ProcessorTarget,
        new_outputs: HashMap<u64, ProcessorOutputs>,
    ) {
        let existing = state_outputs.entry(target).or_default();
        for (address, outputs) in new_outputs {
            let entity_outputs = existing.entry(address).or_default();
            for (processor_name, output) in outputs {
                if let Some(existing_output) = entity_outputs
                    .iter_mut()
                    .find(|(name, _)| *name == processor_name)
                {
                    existing_output.1 = output;
                } else {
                    entity_outputs.push((processor_name, output));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Graph, GraphProcessorOutputsSnapshot, GraphQueueSnapshot, GraphSnapshot};
    use crate::controlflow::{Block, Function};
    use crate::controlflow::Instruction;
    use crate::processor::ProcessorTarget;
    use crate::{Architecture, Config};
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::collections::HashMap;

    #[test]
    fn snapshot_roundtrip_preserves_processor_outputs() {
        let config = Config::default();
        let graph = Graph::new(Architecture::AMD64, config.clone());
        let mut instruction = Instruction::create(0x1000, Architecture::AMD64, config);
        instruction.bytes = vec![0xC3];
        instruction.pattern = "c3".to_string();
        graph.listing.insert(instruction.address, instruction);

        let snapshot = GraphSnapshot {
            architecture: "amd64".to_string(),
            instructions: graph.snapshot().instructions,
            instruction_queue: GraphQueueSnapshot {
                valid: BTreeSet::from([0x1000]),
                invalid: BTreeSet::new(),
                processed: BTreeSet::from([0x1000]),
            },
            block_queue: GraphQueueSnapshot::default(),
            function_queue: GraphQueueSnapshot::default(),
            processor_outputs: GraphProcessorOutputsSnapshot {
                instructions: HashMap::from([(
                    0x1000,
                    vec![("demo".to_string(), json!({"vector": [1.0, 2.0]}))],
                )]),
                blocks: HashMap::new(),
                functions: HashMap::new(),
            },
        };

        let restored =
            Graph::from_snapshot(snapshot, Config::default()).expect("snapshot should restore");

        let output = restored
            .processor_output(ProcessorTarget::Instruction, 0x1000, "demo")
            .expect("processor output should survive snapshot roundtrip");
        assert_eq!(output, json!({"vector": [1.0, 2.0]}));
    }

    #[test]
    fn snapshot_roundtrip_preserves_wildcard_patterns_when_mask_output_disabled() {
        let config = Config::default();
        assert!(!config.chromosomes.mask.enabled);
        let mut graph = Graph::new(Architecture::AMD64, config.clone());

        let mut first = Instruction::create(0x1000, Architecture::AMD64, config.clone());
        first.bytes = vec![0x48, 0x8b, 0x05];
        first.chromosome_mask = vec![0x00, 0x00, 0xFF];
        first.pattern = "488b??".to_string();
        graph.listing.insert(first.address, first);
        graph.instructions.insert_processed(0x1000);
        graph.instructions.insert_valid(0x1000);

        let mut second = Instruction::create(0x1003, Architecture::AMD64, config.clone());
        second.bytes = vec![0xc3];
        second.chromosome_mask = vec![0x00];
        second.pattern = "c3".to_string();
        second.is_return = true;
        graph.listing.insert(second.address, second);
        graph.instructions.insert_processed(0x1003);
        graph.instructions.insert_valid(0x1003);

        graph.blocks.insert_processed(0x1000);
        graph.blocks.insert_valid(0x1000);
        graph.functions.insert_processed(0x1000);
        graph.functions.insert_valid(0x1000);

        let restored = Graph::from_snapshot(graph.snapshot(), config)
            .expect("snapshot should restore wildcard masks");

        let instruction = restored
            .get_instruction(0x1000)
            .expect("instruction should exist after restore");
        assert_eq!(instruction.chromosome().process().pattern, "488b??");

        let block = Block::new(0x1000, &restored).expect("block should restore");
        assert_eq!(block.chromosome_json().pattern, "488b??c3");

        let function = Function::new(0x1000, &restored).expect("function should restore");
        assert_eq!(
            function
                .chromosome_json()
                .expect("function chromosome should exist")
                .pattern,
            "488b??c3"
        );
    }
}
