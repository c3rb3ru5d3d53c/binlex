use crate::controlflow::{
    Graph, GraphQueue, Instruction, InstructionIr, InstructionRecord, Operand,
};
use crate::formats::Image;
use crate::{Architecture, Configuration};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;

#[derive(Clone, Serialize, Deserialize)]
pub struct GraphState {
    pub architecture: Architecture,
    pub image: Image,
    pub configuration: Configuration,
    pub metadata: BTreeMap<String, Value>,
    pub instructions: Vec<GraphInstructionState>,
    pub instruction_queue: GraphQueueState,
    pub block_queue: GraphQueueState,
    pub function_queue: GraphQueueState,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GraphQueueState {
    pub valid: BTreeSet<u64>,
    pub invalid: BTreeSet<u64>,
    pub processed: BTreeSet<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphInstructionState {
    pub architecture: Architecture,
    pub address: u64,
    pub is_prologue: bool,
    pub is_block_start: bool,
    pub is_function_start: bool,
    pub bytes: Vec<u8>,
    pub chromosome_mask: Vec<u8>,
    pub pattern: String,
    pub is_return: bool,
    pub is_call: bool,
    pub functions: BTreeSet<u64>,
    pub is_jump: bool,
    pub is_conditional: bool,
    pub is_trap: bool,
    pub has_indirect_target: bool,
    pub to: BTreeSet<u64>,
    pub edges: usize,
    pub mnemonic: String,
    pub disassembly: String,
    pub operands: Vec<Operand>,
    pub ir: InstructionIr,
}

impl GraphState {
    pub fn from_graph(graph: &Graph) -> Self {
        let instructions = graph
            .listing
            .iter()
            .map(|entry| GraphInstructionState::from_record(entry.value()))
            .collect();
        Self {
            architecture: graph.architecture,
            image: graph.image.clone(),
            configuration: graph.config.clone(),
            metadata: graph.metadata(),
            instructions,
            instruction_queue: GraphQueueState::from_queue(&graph.instructions),
            block_queue: GraphQueueState::from_queue(&graph.blocks),
            function_queue: GraphQueueState::from_queue(&graph.functions),
        }
    }

    pub fn into_graph(self) -> Result<Graph, Error> {
        let mut graph = Graph::new_with_image_metadata(
            self.architecture,
            self.image,
            self.configuration.clone(),
            self.metadata,
        );

        for instruction in self.instructions {
            if instruction.architecture != self.architecture {
                return Err(Error::other(format!(
                    "graph instruction architecture mismatch: expected {}, got {}",
                    self.architecture, instruction.architecture
                )));
            }
            let record = instruction.into_record(self.configuration.clone());
            graph.listing.insert(record.address, record);
        }

        self.instruction_queue.restore_into(&mut graph.instructions);
        self.block_queue.restore_into(&mut graph.blocks);
        self.function_queue.restore_into(&mut graph.functions);
        Ok(graph)
    }
}

impl GraphQueueState {
    pub fn from_queue(queue: &GraphQueue) -> Self {
        Self {
            valid: queue.valid_addresses(),
            invalid: queue.invalid_addresses(),
            processed: queue.processed_addresses(),
        }
    }

    pub fn restore_into(self, queue: &mut GraphQueue) {
        for address in self.processed {
            queue.insert_processed(address);
        }
        for address in self.valid {
            queue.insert_valid(address);
        }
        for address in self.invalid {
            queue.insert_invalid(address);
        }
    }
}

impl GraphInstructionState {
    pub fn from_record(instruction: &InstructionRecord) -> Self {
        Self {
            architecture: instruction.architecture,
            address: instruction.address,
            is_prologue: instruction.is_prologue,
            is_block_start: instruction.is_block_start,
            is_function_start: instruction.is_function_start,
            bytes: instruction.bytes.clone(),
            chromosome_mask: instruction.chromosome_mask.clone(),
            pattern: instruction.pattern.clone(),
            is_return: instruction.is_return,
            is_call: instruction.is_call,
            functions: instruction.functions.clone(),
            is_jump: instruction.is_jump,
            is_conditional: instruction.is_conditional,
            is_trap: instruction.is_trap,
            has_indirect_target: instruction.has_indirect_target,
            to: instruction.to.clone(),
            edges: instruction.edges,
            mnemonic: instruction.mnemonic.clone(),
            disassembly: instruction.disassembly.clone(),
            operands: instruction.operands.clone(),
            ir: instruction.ir.clone(),
        }
    }

    pub fn into_record(self, config: Configuration) -> InstructionRecord {
        let mut instruction = Instruction::create(self.address, self.architecture, config);
        instruction.is_prologue = self.is_prologue;
        instruction.is_block_start = self.is_block_start;
        instruction.is_function_start = self.is_function_start;
        instruction.bytes = self.bytes;
        instruction.chromosome_mask = self.chromosome_mask;
        instruction.pattern = self.pattern;
        instruction.is_return = self.is_return;
        instruction.is_call = self.is_call;
        instruction.functions = self.functions;
        instruction.is_jump = self.is_jump;
        instruction.is_conditional = self.is_conditional;
        instruction.is_trap = self.is_trap;
        instruction.has_indirect_target = self.has_indirect_target;
        instruction.to = self.to;
        instruction.edges = self.edges;
        instruction.mnemonic = self.mnemonic;
        instruction.disassembly = self.disassembly;
        instruction.operands = self.operands;
        instruction.ir = self.ir;
        instruction
    }
}
