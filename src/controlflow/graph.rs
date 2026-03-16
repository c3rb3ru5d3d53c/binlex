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
use crate::processors::{ProcessorOutputs, ProcessorTarget};
use crossbeam::queue::SegQueue;
use crossbeam_skiplist::SkipMap;
use crossbeam_skiplist::SkipSet;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::Error;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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

    fn process_target(&self, target: ProcessorTarget) -> Result<(), Error> {
        let enabled = crate::processors::enabled_processors_for_target(&self.config, target);
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
                processor_state.outputs.insert(target, HashMap::new());
                processor_state.revisions.insert(target, revision);
            }
            return Ok(());
        }

        let mut outputs = HashMap::new();
        match target {
            ProcessorTarget::Instruction => {
                for address in self.instructions.valid_addresses() {
                    let instruction = match self.get_instruction(address) {
                        Some(instruction) => instruction,
                        None => continue,
                    };
                    let mut entity_outputs = Vec::new();
                    for processor in &enabled {
                        if let Some(output) = processor.process_instruction(&instruction) {
                            entity_outputs.push((processor.name(), output));
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
                    for processor in &enabled {
                        if let Some(output) = processor.process_block(&block) {
                            entity_outputs.push((processor.name(), output));
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
                    for processor in &enabled {
                        if let Some(output) = processor.process_function(&function) {
                            entity_outputs.push((processor.name(), output));
                        }
                    }
                    if !entity_outputs.is_empty() {
                        outputs.insert(address, entity_outputs);
                    }
                }
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
}
