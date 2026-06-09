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
use crate::Configuration;
use crate::controlflow::Block;
use crate::controlflow::Function;
use crate::controlflow::Instruction;
use crate::controlflow::InstructionRecord;
use crate::controlflow::Reference;
use crate::formats::{Image, Symbol, SymbolKind};
use crate::irs::lir::Lir;
use crossbeam::queue::SegQueue;
use crossbeam_skiplist::SkipMap;
use crossbeam_skiplist::SkipSet;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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

    pub(crate) fn merge_processed_from(&mut self, other: &GraphQueue) {
        for entry in other.processed() {
            self.processed.insert(*entry.value());
        }
    }

    pub(crate) fn merge_valid_from(&mut self, other: &GraphQueue) {
        for entry in other.valid() {
            self.insert_valid(*entry.value());
        }
    }

    pub(crate) fn merge_invalid_from(&mut self, other: &GraphQueue) {
        for entry in other.invalid() {
            self.insert_invalid(*entry.value());
        }
    }

    pub(crate) fn merge_pending_from(&mut self, other: &mut GraphQueue) {
        while let Some(address) = other.dequeue() {
            let _ = self.enqueue(address);
        }
    }

    pub(crate) fn merge_from(&mut self, other: &mut GraphQueue) {
        self.merge_processed_from(other);
        self.merge_pending_from(other);
        self.merge_valid_from(other);
        self.merge_invalid_from(other);
    }
}

impl Default for GraphQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct GraphCallgraphState {
    revision: Option<u64>,
    callee_references: BTreeMap<u64, BTreeMap<u64, u64>>,
    caller_references: BTreeMap<u64, BTreeMap<u64, u64>>,
}

#[derive(Default)]
struct GraphBlockLayoutState {
    revision: Option<u64>,
    terminators: BTreeMap<u64, u64>,
    successors: BTreeMap<u64, BTreeSet<u64>>,
    predecessors: BTreeMap<u64, BTreeSet<u64>>,
}

#[derive(Default)]
struct GraphFunctionLayoutState {
    revision: Option<u64>,
    blocks: BTreeMap<u64, Vec<u64>>,
}

fn parse_metadata_address(value: &str) -> Option<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse::<u64>().ok()
}

fn symbol_kind_from_str(value: &str) -> SymbolKind {
    match value {
        "function" | "Function" => SymbolKind::Function,
        "import" | "Import" => SymbolKind::Import,
        "export" | "Export" => SymbolKind::Export,
        _ => SymbolKind::Unknown,
    }
}

fn parse_symbol_value(value: &Value) -> Option<Symbol> {
    let object = value.as_object()?;
    let name = object.get("name")?.as_str()?.to_string();
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .map(symbol_kind_from_str)
        .unwrap_or(SymbolKind::Unknown);
    Some(Symbol {
        name,
        file_offset: object
            .get("file_offset")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        virtual_address: object.get("virtual_address").and_then(Value::as_u64),
        relative_virtual_address: object
            .get("relative_virtual_address")
            .and_then(Value::as_u64),
        kind,
    })
}

pub struct Graph {
    /// The Instruction Architecture
    pub architecture: Architecture,
    /// A map of instruction addresses to `Instruction` instances.
    pub listing: SkipMap<u64, InstructionRecord>,
    /// Queue for managing basic blocks within the graph.
    pub blocks: GraphQueue,
    /// Queue for managing functions within the graph.
    pub functions: GraphQueue,
    /// Queue for managing instructions within the graph.
    pub instructions: GraphQueue,
    /// Configuration
    pub config: Configuration,
    /// Virtual image used as decode context.
    pub image: Image,
    metadata: Mutex<BTreeMap<String, Value>>,
    revision: AtomicU64,
    callgraph_state: Mutex<GraphCallgraphState>,
    block_layout_state: Mutex<GraphBlockLayoutState>,
    function_layout_state: Mutex<GraphFunctionLayoutState>,
}

impl Graph {
    /// Creates a new, empty `Graph` instance with default options.
    ///
    /// # Returns
    ///
    /// Returns a `Graph` instance with empty instructions, blocks, and functions.
    #[allow(dead_code)]
    pub fn new(architecture: Architecture, config: Configuration) -> Self {
        Self::new_with_image_metadata(architecture, Image::new(), config, BTreeMap::new())
    }

    pub fn new_with_metadata(
        architecture: Architecture,
        config: Configuration,
        metadata: BTreeMap<String, Value>,
    ) -> Self {
        Self::new_with_image_metadata(architecture, Image::new(), config, metadata)
    }

    pub fn new_with_image(architecture: Architecture, image: Image, config: Configuration) -> Self {
        Self::new_with_image_metadata(architecture, image, config, BTreeMap::new())
    }

    pub fn new_with_image_metadata(
        architecture: Architecture,
        image: Image,
        config: Configuration,
        metadata: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            architecture,
            listing: SkipMap::<u64, InstructionRecord>::new(),
            blocks: GraphQueue::new(),
            functions: GraphQueue::new(),
            instructions: GraphQueue::new(),
            config,
            image,
            metadata: Mutex::new(metadata),
            revision: AtomicU64::new(0),
            callgraph_state: Mutex::new(GraphCallgraphState::default()),
            block_layout_state: Mutex::new(GraphBlockLayoutState::default()),
            function_layout_state: Mutex::new(GraphFunctionLayoutState::default()),
        }
    }

    pub fn instructions(&self) -> Vec<Instruction<'_>> {
        let mut result = Vec::<Instruction<'_>>::new();
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

    pub fn instruction_map(&self) -> &SkipMap<u64, InstructionRecord> {
        &self.listing
    }

    pub fn metadata(&self) -> BTreeMap<String, Value> {
        self.metadata.lock().unwrap().clone()
    }

    pub fn image(&self) -> &Image {
        &self.image
    }

    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        self.image.executable_virtual_address_ranges()
    }

    pub fn replace_metadata(&mut self, metadata: BTreeMap<String, Value>) {
        *self.metadata.lock().unwrap() = metadata;
    }

    pub fn extend_metadata(&mut self, metadata: BTreeMap<String, Value>) {
        self.metadata.lock().unwrap().extend(metadata);
    }

    pub fn metadata_value(&self, key: &str) -> Option<Value> {
        self.metadata.lock().unwrap().get(key).cloned()
    }

    pub fn symbols(&self) -> BTreeMap<u64, String> {
        self.symbol_records()
            .into_iter()
            .filter_map(|symbol| symbol.virtual_address.map(|address| (address, symbol.name)))
            .collect()
    }

    pub fn symbol_records(&self) -> Vec<Symbol> {
        let metadata = self.metadata.lock().unwrap();
        let Some(value) = metadata.get("symbols") else {
            return Vec::new();
        };
        Self::metadata_symbols(value)
    }

    pub fn symbol(&self, address: u64) -> Option<String> {
        self.symbols().get(&address).cloned()
    }

    pub fn insert_symbol(&mut self, address: u64, name: String) -> Option<String> {
        let mut symbols = self.symbol_records();
        let previous = symbols
            .iter()
            .find(|symbol| symbol.virtual_address == Some(address))
            .map(|symbol| symbol.name.clone());
        symbols.retain(|symbol| symbol.virtual_address != Some(address));
        symbols.push(Symbol {
            name,
            file_offset: 0,
            virtual_address: Some(address),
            relative_virtual_address: None,
            kind: SymbolKind::Function,
        });
        self.set_symbol_records(symbols);
        previous
    }

    pub fn replace_symbols(&mut self, symbols: BTreeMap<u64, String>) {
        self.set_symbol_records(Self::symbols_from_map(symbols));
    }

    pub fn extend_symbols(&mut self, symbols: BTreeMap<u64, String>) {
        for (address, name) in symbols {
            self.insert_symbol(address, name);
        }
    }

    fn set_symbol_records(&mut self, symbols: Vec<Symbol>) {
        let value = serde_json::to_value(symbols).unwrap_or_else(|_| Value::Array(Vec::new()));
        self.metadata
            .lock()
            .unwrap()
            .insert("symbols".to_string(), value);
    }

    fn symbols_from_map(symbols: BTreeMap<u64, String>) -> Vec<Symbol> {
        symbols
            .into_iter()
            .map(|(address, name)| Symbol {
                name,
                file_offset: 0,
                virtual_address: Some(address),
                relative_virtual_address: None,
                kind: SymbolKind::Function,
            })
            .collect()
    }

    fn metadata_symbols(value: &Value) -> Vec<Symbol> {
        if let Ok(symbols) = serde_json::from_value::<Vec<Symbol>>(value.clone()) {
            return symbols;
        }

        if let Some(array) = value.as_array() {
            return array.iter().filter_map(parse_symbol_value).collect();
        }

        let Some(object) = value.as_object() else {
            return Vec::new();
        };

        object
            .iter()
            .filter_map(|(address, value)| {
                let address = parse_metadata_address(address)?;
                if let Some(name) = value.as_str() {
                    return Some(Symbol {
                        name: name.to_string(),
                        file_offset: 0,
                        virtual_address: Some(address),
                        relative_virtual_address: None,
                        kind: SymbolKind::Function,
                    });
                }

                let object = value.as_object()?;
                let name = object.get("name")?.as_str()?.to_string();
                let kind = object
                    .get("kind")
                    .and_then(Value::as_str)
                    .map(symbol_kind_from_str)
                    .unwrap_or(SymbolKind::Unknown);
                Some(Symbol {
                    name,
                    file_offset: object
                        .get("file_offset")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    virtual_address: object
                        .get("virtual_address")
                        .and_then(Value::as_u64)
                        .or(Some(address)),
                    relative_virtual_address: object
                        .get("relative_virtual_address")
                        .and_then(Value::as_u64),
                    kind,
                })
            })
            .collect()
    }

    pub fn mutations(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    pub fn set_function(&mut self, address: u64) -> bool {
        let mut instruction = match self.get_instruction_record(address) {
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
        let mut instruction = match self.get_instruction_record(address) {
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
        let mut instruction = match self.get_instruction_record(address) {
            Some(instruction) => instruction,
            None => {
                return false;
            }
        };
        instruction.to.extend(addresses);
        instruction.edges = instruction.successors().len();
        self.update_instruction(instruction);
        self.invalidate_processor_state();
        true
    }

    pub fn insert_instruction<T: Into<InstructionRecord>>(&mut self, instruction: T) {
        let instruction = instruction.into();
        self.invalidate_processor_state();
        self.insert_instruction_merged(instruction);
    }

    pub fn update_instruction<T: Into<InstructionRecord>>(&mut self, instruction: T) {
        let instruction = instruction.into();
        self.invalidate_processor_state();
        if !self.is_instruction_address(instruction.address) {
            return;
        }
        self.listing.insert(instruction.address, instruction);
    }

    pub fn is_instruction_address(&self, address: u64) -> bool {
        self.listing.contains_key(&address)
    }

    pub(crate) fn get_instruction_record(&self, address: u64) -> Option<InstructionRecord> {
        self.listing
            .get(&address)
            .map(|entry| entry.value().clone())
    }

    pub(crate) fn with_instruction_record<T, F>(&self, address: u64, f: F) -> Option<T>
    where
        F: FnOnce(&InstructionRecord) -> T,
    {
        self.listing.get(&address).map(|entry| f(entry.value()))
    }

    pub fn instruction(&self, address: u64) -> Option<Instruction<'_>> {
        Instruction::new(address, self).ok()
    }

    pub fn block(&self, address: u64) -> Option<Block<'_>> {
        let _ = self.process_blocks();
        Block::new(address, self).ok()
    }

    pub fn function(&self, address: u64) -> Option<Function<'_>> {
        let _ = self.process_functions();
        Function::new(address, self).ok()
    }

    pub(crate) fn merge_instruction(
        mut existing: InstructionRecord,
        incoming: InstructionRecord,
    ) -> InstructionRecord {
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
        if existing.mnemonic.is_empty() {
            existing.mnemonic = incoming.mnemonic;
        }
        if existing.disassembly.is_empty() {
            existing.disassembly = incoming.disassembly;
        }
        if existing.operands.is_empty() {
            existing.operands = incoming.operands;
        }
        if existing.instruction_detail.is_none() {
            existing.instruction_detail = incoming.instruction_detail;
        }
        existing.lir = Graph::merge_instruction_lir(existing.lir, incoming.lir);
        existing.reset_prepared_lir_cache();
        existing
    }

    fn insert_instruction_merged(&mut self, instruction: InstructionRecord) {
        if let Some(existing) = self.get_instruction_record(instruction.address) {
            self.listing.insert(
                instruction.address,
                Graph::merge_instruction(existing, instruction),
            );
        } else {
            self.listing.insert(instruction.address, instruction);
        }
    }

    fn merge_instruction_lir(existing: Option<Lir>, incoming: Option<Lir>) -> Option<Lir> {
        match (existing, incoming) {
            (None, None) => None,
            (Some(lir), None) => Some(lir),
            (None, Some(lir)) => Some(lir),
            (Some(existing), Some(incoming)) => {
                if existing.status >= incoming.status {
                    Some(existing)
                } else {
                    Some(incoming)
                }
            }
        }
    }

    pub fn merge(&mut self, graph: &mut Graph) {
        self.invalidate_processor_state();
        if self.listing.iter().next().is_none() {
            self.listing = std::mem::take(&mut graph.listing);
        } else {
            for entry in graph.instruction_map() {
                self.insert_instruction_merged(entry.value().clone());
            }
        }
        self.instructions.merge_from(&mut graph.instructions);
        self.blocks.merge_from(&mut graph.blocks);
        self.functions.merge_from(&mut graph.functions);
        let metadata = std::mem::take(&mut *graph.metadata.lock().unwrap());
        self.extend_metadata(metadata);
    }

    pub fn process(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn process_instructions(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn process_blocks(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn process_functions(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn process_graph(&self) -> Result<(), Error> {
        Ok(())
    }

    pub fn process_complete(&self) -> Result<(), Error> {
        Ok(())
    }

    fn ensure_callgraph(&self) {
        let revision = self.revision.load(Ordering::SeqCst);
        {
            let callgraph_state = self.callgraph_state.lock().unwrap();
            if callgraph_state.revision == Some(revision) {
                return;
            }
        }

        self.ensure_function_layouts();

        let callee_entries = self
            .functions
            .valid_addresses()
            .into_iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .filter_map(|function_address| {
                let function = Function::new(function_address, self).ok()?;
                Some((function_address, function.compute_callee_references()))
            })
            .collect::<Vec<_>>();

        let mut callee_references = BTreeMap::<u64, BTreeMap<u64, u64>>::new();
        let mut caller_references = BTreeMap::<u64, BTreeMap<u64, u64>>::new();

        for (function_address, function_callees) in callee_entries {
            for (callsite, callee) in &function_callees {
                caller_references
                    .entry(*callee)
                    .or_default()
                    .insert(*callsite, function_address);
            }
            callee_references.insert(function_address, function_callees);
        }

        let mut callgraph_state = self.callgraph_state.lock().unwrap();
        if self.revision.load(Ordering::SeqCst) == revision {
            callgraph_state.callee_references = callee_references;
            callgraph_state.caller_references = caller_references;
            callgraph_state.revision = Some(revision);
        }
    }

    pub(crate) fn function_callee_references(&self, address: u64) -> BTreeMap<u64, u64> {
        self.ensure_callgraph();
        self.callgraph_state
            .lock()
            .unwrap()
            .callee_references
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn function_caller_references(&self, address: u64) -> BTreeMap<u64, u64> {
        self.ensure_callgraph();
        self.callgraph_state
            .lock()
            .unwrap()
            .caller_references
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }

    pub fn function_reference_maps(
        &self,
    ) -> (
        BTreeMap<u64, BTreeMap<u64, u64>>,
        BTreeMap<u64, BTreeMap<u64, u64>>,
    ) {
        self.ensure_callgraph();
        let state = self.callgraph_state.lock().unwrap();
        (
            state.callee_references.clone(),
            state.caller_references.clone(),
        )
    }

    fn compute_block_terminator_address(&self, address: u64) -> Option<u64> {
        if !self.blocks.is_valid(address) {
            return None;
        }

        let mut previous_instruction: Option<u64> = None;
        let mut pc = address;

        loop {
            let instruction = self.instruction(pc);
            let Some(instruction) = instruction else {
                return previous_instruction;
            };
            if address != instruction.address && instruction.is_block_start {
                return previous_instruction;
            }
            if instruction.is_jump || instruction.is_trap || instruction.is_return {
                return Some(instruction.address);
            }
            let size = instruction.size() as u64;
            if size == 0 {
                return previous_instruction;
            }
            previous_instruction = Some(instruction.address);
            pc = instruction.address.checked_add(size)?;
        }
    }

    fn ensure_block_layouts(&self) {
        let revision = self.revision.load(Ordering::SeqCst);
        {
            let state = self.block_layout_state.lock().unwrap();
            if state.revision == Some(revision) {
                return;
            }
        }

        let addresses = self
            .blocks
            .valid_addresses()
            .into_iter()
            .collect::<Vec<_>>();
        let terminator_entries = addresses
            .into_par_iter()
            .filter_map(|address| {
                self.compute_block_terminator_address(address)
                    .map(|terminator| (address, terminator))
            })
            .collect::<Vec<_>>();

        let mut terminators = BTreeMap::new();
        let mut successors = BTreeMap::<u64, BTreeSet<u64>>::new();
        let mut predecessors = BTreeMap::<u64, BTreeSet<u64>>::new();

        for (address, terminator_address) in terminator_entries {
            terminators.insert(address, terminator_address);
            let Some(terminator) = self.instruction(terminator_address) else {
                continue;
            };
            let mut targets = terminator.branches();
            if !terminator.is_return
                && !terminator.is_trap
                && (!terminator.is_jump || terminator.is_conditional)
            {
                let fallthrough = if terminator.is_block_start && address != terminator.address {
                    Some(terminator.address)
                } else {
                    terminator.fallthrough()
                };
                if let Some(target) = fallthrough {
                    targets.insert(target);
                }
            }
            for target in &targets {
                predecessors.entry(*target).or_default().insert(address);
            }
            successors.insert(address, targets);
        }

        let mut state = self.block_layout_state.lock().unwrap();
        if self.revision.load(Ordering::SeqCst) == revision {
            state.terminators = terminators;
            state.successors = successors;
            state.predecessors = predecessors;
            state.revision = Some(revision);
        }
    }

    pub(crate) fn block_terminator_address(&self, address: u64) -> Option<u64> {
        self.ensure_block_layouts();
        self.block_layout_state
            .lock()
            .unwrap()
            .terminators
            .get(&address)
            .copied()
    }

    pub(crate) fn block_successor_addresses(&self, address: u64) -> BTreeSet<u64> {
        self.ensure_block_layouts();
        self.block_layout_state
            .lock()
            .unwrap()
            .successors
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn block_predecessor_addresses(&self, address: u64) -> BTreeSet<u64> {
        self.ensure_block_layouts();
        self.block_layout_state
            .lock()
            .unwrap()
            .predecessors
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }

    pub fn block_reference_maps(
        &self,
    ) -> (BTreeMap<u64, Vec<Reference>>, BTreeMap<u64, Vec<Reference>>) {
        self.ensure_block_layouts();
        let state = self.block_layout_state.lock().unwrap();
        let successor_references = state
            .successors
            .iter()
            .map(|(source, targets)| {
                (
                    *source,
                    targets
                        .iter()
                        .map(|target| Reference::new(*source, *target))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let predecessor_references = state
            .predecessors
            .iter()
            .map(|(target, sources)| {
                (
                    *target,
                    sources
                        .iter()
                        .map(|source| Reference::new(*source, *target))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        (successor_references, predecessor_references)
    }

    fn compute_function_block_addresses(&self, address: u64) -> Option<Vec<u64>> {
        if !self.functions.is_valid(address) {
            return None;
        }

        let mut blocks = BTreeSet::<u64>::new();
        let mut queue = GraphQueue::new();
        queue.enqueue(address);

        while let Some(block_address) = queue.dequeue() {
            queue.insert_processed(block_address);
            if self.blocks.is_invalid(block_address) {
                return None;
            }
            let block = Block::new(block_address, self).ok()?;
            queue.enqueue_extend(
                block
                    .successor_addresses()
                    .into_iter()
                    .filter(|address| self.blocks.is_valid(*address))
                    .collect(),
            );
            blocks.insert(block_address);
        }

        if blocks.is_empty() {
            return None;
        }

        Some(blocks.into_iter().collect())
    }

    fn ensure_function_layouts(&self) {
        let revision = self.revision.load(Ordering::SeqCst);
        {
            let state = self.function_layout_state.lock().unwrap();
            if state.revision == Some(revision) {
                return;
            }
        }

        self.ensure_block_layouts();

        let addresses = self
            .functions
            .valid_addresses()
            .into_iter()
            .collect::<Vec<_>>();
        let blocks = addresses
            .into_par_iter()
            .filter_map(|address| {
                self.compute_function_block_addresses(address)
                    .map(|blocks| (address, blocks))
            })
            .collect::<BTreeMap<_, _>>();

        let mut state = self.function_layout_state.lock().unwrap();
        if self.revision.load(Ordering::SeqCst) == revision {
            state.blocks = blocks;
            state.revision = Some(revision);
        }
    }

    pub(crate) fn function_block_addresses(&self, address: u64) -> Option<Vec<u64>> {
        self.ensure_function_layouts();
        self.function_layout_state
            .lock()
            .unwrap()
            .blocks
            .get(&address)
            .cloned()
    }

    fn invalidate_processor_state(&self) {
        self.revision.fetch_add(1, Ordering::SeqCst);
        let mut callgraph_state = self.callgraph_state.lock().unwrap();
        callgraph_state.revision = None;
        callgraph_state.callee_references.clear();
        callgraph_state.caller_references.clear();
        let mut block_layout_state = self.block_layout_state.lock().unwrap();
        block_layout_state.revision = None;
        block_layout_state.terminators.clear();
        block_layout_state.successors.clear();
        block_layout_state.predecessors.clear();
        let mut function_layout_state = self.function_layout_state.lock().unwrap();
        function_layout_state.revision = None;
        function_layout_state.blocks.clear();
    }
}
