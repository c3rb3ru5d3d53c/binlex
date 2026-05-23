use std::collections::BTreeMap;

use crossbeam_skiplist::SkipMap;

use crate::controlflow::{Graph, GraphQueue, InstructionRecord};
use crate::{Architecture, Configuration};

pub(crate) struct DisassemblyShard {
    architecture: Architecture,
    config: Configuration,
    listing: BTreeMap<u64, InstructionRecord>,
    pub(crate) blocks: GraphQueue,
    pub(crate) functions: GraphQueue,
    pub(crate) instructions: GraphQueue,
}

impl DisassemblyShard {
    pub(crate) fn new(architecture: Architecture, config: Configuration) -> Self {
        Self {
            architecture,
            config,
            listing: BTreeMap::new(),
            blocks: GraphQueue::new(),
            functions: GraphQueue::new(),
            instructions: GraphQueue::new(),
        }
    }

    pub(crate) fn get_instruction_record(&self, address: u64) -> Option<InstructionRecord> {
        self.listing.get(&address).cloned()
    }

    pub(crate) fn config(&self) -> &Configuration {
        &self.config
    }

    pub(crate) fn insert_instruction(&mut self, instruction: InstructionRecord) {
        if let Some(existing) = self.listing.remove(&instruction.address) {
            self.listing.insert(
                instruction.address,
                Graph::merge_instruction(existing, instruction),
            );
        } else {
            self.listing.insert(instruction.address, instruction);
        }
    }

    pub(crate) fn update_instruction(&mut self, instruction: InstructionRecord) {
        if self.listing.contains_key(&instruction.address) {
            self.listing.insert(instruction.address, instruction);
        }
    }

    pub(crate) fn merge(&mut self, other: &mut Self) {
        for (_, instruction) in std::mem::take(&mut other.listing) {
            self.insert_instruction(instruction);
        }
        self.instructions.merge_from(&mut other.instructions);
        self.blocks.merge_from(&mut other.blocks);
        self.functions.merge_from(&mut other.functions);
    }

    pub(crate) fn into_graph(self) -> Graph {
        let mut graph = Graph::new(self.architecture, self.config);
        let listing = SkipMap::new();
        for (address, instruction) in self.listing {
            listing.insert(address, instruction);
        }
        graph.listing = listing;
        graph.blocks = self.blocks;
        graph.functions = self.functions;
        graph.instructions = self.instructions;
        graph
    }
}
