use std::collections::{BTreeSet, HashMap, VecDeque};

use crate::irs::lir::{
    LirBlock, LirEffect, LirExpression, LirFunction, LirInstruction, LirLocation, LirModule,
    LirPhiSource, LirStatus, LirTerminator,
};

#[derive(Clone, Default)]
struct SsaContext {
    versions: HashMap<SsaKey, u64>,
    allocated_versions: HashMap<SsaKey, u64>,
    temp_versions: HashMap<u32, u32>,
    temp_ids: HashMap<(u32, u32), u32>,
    next_temp_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SsaKey {
    Register(String),
    Flag(String),
}

pub fn ssa_instruction_lir(lir: &LirInstruction) -> LirInstruction {
    let mut context = SsaContext::from_instruction(lir);
    context.rewrite_instruction(lir)
}

pub fn ssa_block_lir(block: &LirBlock) -> LirBlock {
    let mut context = SsaContext::from_instructions(block.instructions.iter());
    LirBlock {
        name: block.name.clone(),
        instructions: block
            .instructions
            .iter()
            .map(|instruction| context.rewrite_instruction(instruction))
            .collect(),
    }
}

pub fn ssa_function_lir(function: &LirFunction) -> LirFunction {
    if can_infer_cfg(function) {
        return ssa_function_lir_with_phi(function);
    }

    let mut context = SsaContext::from_instructions(
        function
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter()),
    );
    LirFunction {
        name: function.name.clone(),
        blocks: function
            .blocks
            .iter()
            .map(|block| LirBlock {
                name: block.name.clone(),
                instructions: block
                    .instructions
                    .iter()
                    .map(|instruction| context.rewrite_instruction(instruction))
                    .collect(),
            })
            .collect(),
    }
}

fn ssa_function_lir_with_phi(function: &LirFunction) -> LirFunction {
    let context = SsaContext::from_instructions(
        function
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter()),
    );
    let cfg = FunctionCfg::new(function);
    let key_bits = collect_key_bits(function);
    let order = cfg.forward_order();
    let mut output_contexts: Vec<Option<SsaContext>> = vec![None; function.blocks.len()];
    let mut rewritten_blocks: Vec<Option<LirBlock>> = vec![None; function.blocks.len()];
    let mut allocation_context = SsaContext {
        versions: HashMap::new(),
        allocated_versions: HashMap::new(),
        temp_versions: HashMap::new(),
        temp_ids: context.temp_ids.clone(),
        next_temp_id: context.next_temp_id,
    };

    for block_index in order {
        let mut block_context = merged_block_context(
            &cfg,
            block_index,
            &output_contexts,
            &key_bits,
            &allocation_context,
        );
        let phi_effects = build_block_phi_effects(
            &cfg,
            block_index,
            &output_contexts,
            &key_bits,
            &mut block_context,
        );

        let block = &function.blocks[block_index];
        let mut instructions = Vec::new();
        if !phi_effects.is_empty() {
            instructions.push(LirInstruction {
                address: block.address(),
                status: LirStatus::Complete,
                effects: phi_effects,
                terminator: LirTerminator::FallThrough,
            });
        }
        instructions.extend(
            block
                .instructions
                .iter()
                .map(|instruction| block_context.rewrite_instruction(instruction)),
        );
        output_contexts[block_index] = Some(block_context);
        if let Some(context) = &output_contexts[block_index] {
            allocation_context.merge_allocations_from(context);
        }
        rewritten_blocks[block_index] = Some(LirBlock {
            name: block.name.clone(),
            instructions,
        });
    }

    LirFunction {
        name: function.name.clone(),
        blocks: rewritten_blocks
            .into_iter()
            .enumerate()
            .map(|(index, block)| {
                block.unwrap_or_else(|| {
                    let mut fallback =
                        SsaContext::from_instructions(function.blocks[index].instructions.iter());
                    LirBlock {
                        name: function.blocks[index].name.clone(),
                        instructions: function.blocks[index]
                            .instructions
                            .iter()
                            .map(|instruction| fallback.rewrite_instruction(instruction))
                            .collect(),
                    }
                })
            })
            .collect(),
    }
}

pub fn ssa_module_lir(module: &LirModule) -> LirModule {
    LirModule {
        name: module.name.clone(),
        functions: module.functions.iter().map(ssa_function_lir).collect(),
        data: module.data.clone(),
    }
}

struct FunctionCfg {
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
    block_addresses: Vec<Option<u64>>,
}

impl FunctionCfg {
    fn new(function: &LirFunction) -> Self {
        let block_addresses = function
            .blocks
            .iter()
            .map(LirBlock::address)
            .collect::<Vec<_>>();
        let address_to_index = block_addresses
            .iter()
            .enumerate()
            .filter_map(|(index, address)| address.map(|address| (address, index)))
            .collect::<HashMap<_, _>>();
        let mut successors = vec![Vec::new(); function.blocks.len()];

        for (index, block) in function.blocks.iter().enumerate() {
            let mut block_successors = block
                .instructions
                .last()
                .map(|instruction| terminator_successors(&instruction.terminator))
                .unwrap_or_default()
                .into_iter()
                .filter_map(|address| address_to_index.get(&address).copied())
                .collect::<Vec<_>>();
            if matches!(
                block
                    .instructions
                    .last()
                    .map(|instruction| &instruction.terminator),
                Some(LirTerminator::FallThrough)
            ) {
                if index + 1 < function.blocks.len() {
                    block_successors.push(index + 1);
                }
            }
            block_successors.sort_unstable();
            block_successors.dedup();
            successors[index] = block_successors;
        }

        let mut predecessors = vec![Vec::new(); function.blocks.len()];
        for (predecessor, block_successors) in successors.iter().enumerate() {
            for successor in block_successors {
                predecessors[*successor].push(predecessor);
            }
        }

        Self {
            successors,
            predecessors,
            block_addresses,
        }
    }

    fn forward_order(&self) -> Vec<usize> {
        let mut visited = vec![false; self.successors.len()];
        let mut order = Vec::new();
        let mut queue = VecDeque::from([0usize]);
        while let Some(index) = queue.pop_front() {
            if index >= self.successors.len() || visited[index] {
                continue;
            }
            visited[index] = true;
            order.push(index);
            for successor in &self.successors[index] {
                queue.push_back(*successor);
            }
        }
        for index in 0..self.successors.len() {
            if !visited[index] {
                order.push(index);
            }
        }
        order
    }
}

fn can_infer_cfg(function: &LirFunction) -> bool {
    function.blocks.len() > 1
        && function
            .blocks
            .iter()
            .filter(|block| block.address().is_some())
            .count()
            == function.blocks.len()
}

fn terminator_successors(terminator: &LirTerminator) -> Vec<u64> {
    match terminator {
        LirTerminator::Jump { target } => const_target(target).into_iter().collect(),
        LirTerminator::Branch {
            true_target,
            false_target,
            ..
        } => [const_target(true_target), const_target(false_target)]
            .into_iter()
            .flatten()
            .collect(),
        LirTerminator::Call { return_target, .. } => return_target
            .as_ref()
            .and_then(const_target)
            .into_iter()
            .collect(),
        LirTerminator::FallThrough
        | LirTerminator::Return { .. }
        | LirTerminator::Unreachable
        | LirTerminator::Trap => Vec::new(),
    }
}

fn const_target(expression: &LirExpression) -> Option<u64> {
    match expression {
        LirExpression::Const { value, .. } => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn collect_key_bits(function: &LirFunction) -> HashMap<SsaKey, u16> {
    let mut bits = HashMap::new();
    for instruction in function
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
    {
        for effect in &instruction.effects {
            collect_effect_key_bits(effect, &mut bits);
        }
    }
    bits
}

fn collect_effect_key_bits(effect: &LirEffect, bits: &mut HashMap<SsaKey, u16>) {
    match effect {
        LirEffect::Phi { dst, .. } | LirEffect::Set { dst, .. } | LirEffect::Pop { dst, .. } => {
            collect_location_key_bits(dst, bits)
        }
        LirEffect::AtomicCmpXchg { observed, .. } => collect_location_key_bits(observed, bits),
        LirEffect::Intrinsic { outputs, .. } => {
            for output in outputs {
                collect_location_key_bits(output, bits);
            }
        }
        LirEffect::Store { .. }
        | LirEffect::MemorySet { .. }
        | LirEffect::MemoryCopy { .. }
        | LirEffect::WriteProperty { .. }
        | LirEffect::WriteElement { .. }
        | LirEffect::Push { .. }
        | LirEffect::Fence { .. }
        | LirEffect::Trap { .. }
        | LirEffect::Nop => {}
    }
}

fn collect_location_key_bits(location: &LirLocation, bits: &mut HashMap<SsaKey, u16>) {
    match location {
        LirLocation::Register { name, bits: width } => {
            bits.entry(SsaKey::Register(name.clone())).or_insert(*width);
        }
        LirLocation::Flag { name, bits: width } => {
            bits.entry(SsaKey::Flag(name.clone())).or_insert(*width);
        }
        _ => {}
    }
}

fn merged_block_context(
    cfg: &FunctionCfg,
    block_index: usize,
    output_contexts: &[Option<SsaContext>],
    key_bits: &HashMap<SsaKey, u16>,
    fallback_context: &SsaContext,
) -> SsaContext {
    let available_predecessors = cfg.predecessors[block_index]
        .iter()
        .filter_map(|predecessor| output_contexts[*predecessor].as_ref())
        .collect::<Vec<_>>();
    if available_predecessors.is_empty() {
        return SsaContext {
            versions: HashMap::new(),
            allocated_versions: fallback_context.allocated_versions.clone(),
            temp_versions: HashMap::new(),
            temp_ids: fallback_context.temp_ids.clone(),
            next_temp_id: fallback_context.next_temp_id,
        };
    }

    let mut versions = HashMap::new();
    for key in key_bits.keys() {
        let version = available_predecessors
            .iter()
            .map(|context| context.version(key))
            .max()
            .unwrap_or(0);
        versions.insert(key.clone(), version);
    }

    SsaContext {
        versions,
        allocated_versions: fallback_context.allocated_versions.clone(),
        temp_versions: HashMap::new(),
        temp_ids: fallback_context.temp_ids.clone(),
        next_temp_id: fallback_context.next_temp_id,
    }
}

fn build_block_phi_effects(
    cfg: &FunctionCfg,
    block_index: usize,
    output_contexts: &[Option<SsaContext>],
    key_bits: &HashMap<SsaKey, u16>,
    block_context: &mut SsaContext,
) -> Vec<LirEffect> {
    let predecessors = cfg.predecessors[block_index]
        .iter()
        .filter_map(|predecessor| {
            output_contexts[*predecessor]
                .as_ref()
                .map(|context| (*predecessor, context))
        })
        .collect::<Vec<_>>();
    if predecessors.len() < 2 {
        return Vec::new();
    }

    let mut phi_effects = Vec::new();
    for (key, bits) in key_bits {
        let incoming_versions = predecessors
            .iter()
            .map(|(_, context)| context.version(key))
            .collect::<BTreeSet<_>>();
        if incoming_versions.len() < 2 {
            continue;
        }

        let max_version = incoming_versions.iter().copied().max().unwrap_or(0);
        block_context.versions.insert(key.clone(), max_version);
        let dst = block_context.write_key_location(key, *bits);
        let sources = predecessors
            .iter()
            .map(|(predecessor, context)| LirPhiSource {
                predecessor: cfg.block_addresses[*predecessor],
                value: LirExpression::Read(Box::new(context.read_key_location(key, *bits))),
            })
            .collect();
        phi_effects.push(LirEffect::Phi { dst, sources });
    }
    phi_effects
}

impl SsaContext {
    fn from_instruction(lir: &LirInstruction) -> Self {
        Self::from_instructions(std::iter::once(lir))
    }

    fn from_instructions<'a>(instructions: impl Iterator<Item = &'a LirInstruction>) -> Self {
        let mut context = Self::default();
        for instruction in instructions {
            context.track_instruction_temporaries(instruction);
        }
        context
    }

    fn track_instruction_temporaries(&mut self, instruction: &LirInstruction) {
        for effect in &instruction.effects {
            self.track_effect_temporaries(effect);
        }
        self.track_terminator_temporaries(&instruction.terminator);
    }

    fn track_effect_temporaries(&mut self, effect: &LirEffect) {
        match effect {
            LirEffect::Phi { dst, sources } => {
                self.track_location_temporaries(dst);
                for source in sources {
                    self.track_expression_temporaries(&source.value);
                }
            }
            LirEffect::Set { dst, expression } => {
                self.track_location_temporaries(dst);
                self.track_expression_temporaries(expression);
            }
            LirEffect::Store {
                addr, expression, ..
            } => {
                self.track_expression_temporaries(addr);
                self.track_expression_temporaries(expression);
            }
            LirEffect::MemorySet {
                addr,
                value,
                count,
                decrement,
                ..
            } => {
                self.track_expression_temporaries(addr);
                self.track_expression_temporaries(value);
                self.track_expression_temporaries(count);
                self.track_expression_temporaries(decrement);
            }
            LirEffect::MemoryCopy {
                src_addr,
                dst_addr,
                count,
                decrement,
                ..
            } => {
                self.track_expression_temporaries(src_addr);
                self.track_expression_temporaries(dst_addr);
                self.track_expression_temporaries(count);
                self.track_expression_temporaries(decrement);
            }
            LirEffect::AtomicCmpXchg {
                addr,
                expected,
                desired,
                observed,
                ..
            } => {
                self.track_expression_temporaries(addr);
                self.track_expression_temporaries(expected);
                self.track_expression_temporaries(desired);
                self.track_location_temporaries(observed);
            }
            LirEffect::WriteProperty {
                reference,
                expression,
                ..
            } => {
                self.track_expression_temporaries(reference);
                self.track_expression_temporaries(expression);
            }
            LirEffect::WriteElement {
                reference,
                index,
                expression,
                ..
            } => {
                self.track_expression_temporaries(reference);
                self.track_expression_temporaries(index);
                self.track_expression_temporaries(expression);
            }
            LirEffect::Push { expression, .. } => self.track_expression_temporaries(expression),
            LirEffect::Pop { dst, .. } => self.track_location_temporaries(dst),
            LirEffect::Intrinsic { args, outputs, .. } => {
                for arg in args {
                    self.track_expression_temporaries(arg);
                }
                for output in outputs {
                    self.track_location_temporaries(output);
                }
            }
            LirEffect::Fence { .. } | LirEffect::Trap { .. } | LirEffect::Nop => {}
        }
    }

    fn track_terminator_temporaries(&mut self, terminator: &LirTerminator) {
        match terminator {
            LirTerminator::FallThrough | LirTerminator::Unreachable | LirTerminator::Trap => {}
            LirTerminator::Jump { target } => self.track_expression_temporaries(target),
            LirTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                self.track_expression_temporaries(condition);
                self.track_expression_temporaries(true_target);
                self.track_expression_temporaries(false_target);
            }
            LirTerminator::Call {
                target,
                return_target,
                ..
            } => {
                self.track_expression_temporaries(target);
                if let Some(return_target) = return_target {
                    self.track_expression_temporaries(return_target);
                }
            }
            LirTerminator::Return { expression } => {
                if let Some(expression) = expression {
                    self.track_expression_temporaries(expression);
                }
            }
        }
    }

    fn track_expression_temporaries(&mut self, expression: &LirExpression) {
        match expression {
            LirExpression::Read(location) => self.track_location_temporaries(location),
            LirExpression::AddressOf { location, .. } => self.track_location_temporaries(location),
            LirExpression::Load { addr, .. } => self.track_expression_temporaries(addr),
            LirExpression::Unary { arg, .. } => self.track_expression_temporaries(arg),
            LirExpression::Binary { left, right, .. }
            | LirExpression::Compare { left, right, .. } => {
                self.track_expression_temporaries(left);
                self.track_expression_temporaries(right);
            }
            LirExpression::Cast { arg, .. } => self.track_expression_temporaries(arg),
            LirExpression::Concat { parts, .. } => {
                for part in parts {
                    self.track_expression_temporaries(part);
                }
            }
            LirExpression::Extract { arg, .. } => self.track_expression_temporaries(arg),
            LirExpression::Select {
                condition,
                when_true,
                when_false,
                ..
            } => {
                self.track_expression_temporaries(condition);
                self.track_expression_temporaries(when_true);
                self.track_expression_temporaries(when_false);
            }
            LirExpression::Intrinsic { args, .. } => {
                for arg in args {
                    self.track_expression_temporaries(arg);
                }
            }
            LirExpression::ReadProperty { reference, .. } => {
                self.track_expression_temporaries(reference)
            }
            LirExpression::ReadElement {
                reference, index, ..
            } => {
                self.track_expression_temporaries(reference);
                self.track_expression_temporaries(index);
            }
            LirExpression::Const { .. }
            | LirExpression::Function { .. }
            | LirExpression::DataAddress { .. }
            | LirExpression::Undefined { .. }
            | LirExpression::Poison { .. }
            | LirExpression::Null { .. }
            | LirExpression::Allocate { .. } => {}
        }
    }

    fn track_location_temporaries(&mut self, location: &LirLocation) {
        match location {
            LirLocation::Temporary { id, .. } => {
                self.next_temp_id = self.next_temp_id.max(id.saturating_add(1));
            }
            LirLocation::Memory { addr, .. } => self.track_expression_temporaries(addr),
            LirLocation::IndexedMemory { index, .. } => self.track_expression_temporaries(index),
            LirLocation::Register { .. }
            | LirLocation::Flag { .. }
            | LirLocation::ProgramCounter { .. }
            | LirLocation::StackMemory { .. } => {}
        }
    }

    fn rewrite_instruction(&mut self, lir: &LirInstruction) -> LirInstruction {
        let read_context = self.clone();
        let mut replacements = Vec::new();
        LirInstruction {
            address: lir.address,
            status: lir.status,
            effects: lir
                .effects
                .iter()
                .map(|effect| self.rewrite_effect(effect, &read_context, &mut replacements))
                .collect(),
            terminator: self.rewrite_terminator(&lir.terminator, &read_context, &replacements),
        }
    }

    fn rewrite_effect(
        &mut self,
        effect: &LirEffect,
        read_context: &SsaContext,
        replacements: &mut Vec<(LirExpression, LirExpression)>,
    ) -> LirEffect {
        match effect {
            LirEffect::Phi { dst, sources } => LirEffect::Phi {
                dst: self.write_location(dst),
                sources: sources
                    .iter()
                    .map(|source| LirPhiSource {
                        predecessor: source.predecessor,
                        value: Self::replace_expression(
                            &read_context.rewrite_expression_from_snapshot(&source.value),
                            replacements,
                        ),
                    })
                    .collect(),
            },
            LirEffect::Set { dst, expression } => {
                let rewritten_expression =
                    read_context.rewrite_expression_from_snapshot(expression);
                let expression = Self::replace_expression(&rewritten_expression, replacements);
                let dst = self.write_location(dst);
                replacements.push((
                    rewritten_expression,
                    LirExpression::Read(Box::new(dst.clone())),
                ));
                LirEffect::Set { dst, expression }
            }
            LirEffect::Store {
                space,
                addr,
                expression,
                bits,
            } => LirEffect::Store {
                space: space.clone(),
                addr: Self::replace_expression(&self.rewrite_expression(addr), replacements),
                expression: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(expression),
                    replacements,
                ),
                bits: *bits,
            },
            LirEffect::MemorySet {
                space,
                addr,
                value,
                count,
                element_bits,
                decrement,
            } => LirEffect::MemorySet {
                space: space.clone(),
                addr: Self::replace_expression(&self.rewrite_expression(addr), replacements),
                value: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(value),
                    replacements,
                ),
                count: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(count),
                    replacements,
                ),
                element_bits: *element_bits,
                decrement: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(decrement),
                    replacements,
                ),
            },
            LirEffect::MemoryCopy {
                src_space,
                src_addr,
                dst_space,
                dst_addr,
                count,
                element_bits,
                decrement,
            } => LirEffect::MemoryCopy {
                src_space: src_space.clone(),
                src_addr: Self::replace_expression(
                    &self.rewrite_expression(src_addr),
                    replacements,
                ),
                dst_space: dst_space.clone(),
                dst_addr: Self::replace_expression(
                    &self.rewrite_expression(dst_addr),
                    replacements,
                ),
                count: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(count),
                    replacements,
                ),
                element_bits: *element_bits,
                decrement: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(decrement),
                    replacements,
                ),
            },
            LirEffect::AtomicCmpXchg {
                space,
                addr,
                expected,
                desired,
                bits,
                observed,
            } => LirEffect::AtomicCmpXchg {
                space: space.clone(),
                addr: Self::replace_expression(&self.rewrite_expression(addr), replacements),
                expected: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(expected),
                    replacements,
                ),
                desired: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(desired),
                    replacements,
                ),
                bits: *bits,
                observed: self.write_location(observed),
            },
            LirEffect::WriteProperty {
                reference,
                name,
                expression,
                bits,
            } => LirEffect::WriteProperty {
                reference: Self::replace_expression(
                    &self.rewrite_expression(reference),
                    replacements,
                ),
                name: name.clone(),
                expression: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(expression),
                    replacements,
                ),
                bits: *bits,
            },
            LirEffect::WriteElement {
                reference,
                index,
                expression,
                bits,
            } => LirEffect::WriteElement {
                reference: Self::replace_expression(
                    &self.rewrite_expression(reference),
                    replacements,
                ),
                index: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(index),
                    replacements,
                ),
                expression: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(expression),
                    replacements,
                ),
                bits: *bits,
            },
            LirEffect::Push { stack, expression } => LirEffect::Push {
                stack: stack.clone(),
                expression: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(expression),
                    replacements,
                ),
            },
            LirEffect::Pop { stack, dst } => LirEffect::Pop {
                stack: stack.clone(),
                dst: self.write_location(dst),
            },
            LirEffect::Fence { kind } => LirEffect::Fence { kind: kind.clone() },
            LirEffect::Trap { kind } => LirEffect::Trap { kind: kind.clone() },
            LirEffect::Intrinsic {
                name,
                args,
                outputs,
            } => LirEffect::Intrinsic {
                name: name.clone(),
                args: args
                    .iter()
                    .map(|arg| {
                        Self::replace_expression(
                            &read_context.rewrite_expression_from_snapshot(arg),
                            replacements,
                        )
                    })
                    .collect(),
                outputs: outputs
                    .iter()
                    .map(|output| self.write_location(output))
                    .collect(),
            },
            LirEffect::Nop => LirEffect::Nop,
        }
    }

    fn rewrite_terminator(
        &mut self,
        terminator: &LirTerminator,
        read_context: &SsaContext,
        replacements: &[(LirExpression, LirExpression)],
    ) -> LirTerminator {
        match terminator {
            LirTerminator::FallThrough => LirTerminator::FallThrough,
            LirTerminator::Jump { target } => LirTerminator::Jump {
                target: Self::replace_expression(&self.rewrite_expression(target), replacements),
            },
            LirTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => LirTerminator::Branch {
                condition: Self::replace_expression(
                    &self.rewrite_expression(condition),
                    replacements,
                ),
                true_target: Self::replace_expression(
                    &self.rewrite_expression(true_target),
                    replacements,
                ),
                false_target: Self::replace_expression(
                    &self.rewrite_expression(false_target),
                    replacements,
                ),
            },
            LirTerminator::Call {
                target,
                return_target,
                does_return,
            } => LirTerminator::Call {
                target: Self::replace_expression(
                    &read_context.rewrite_expression_from_snapshot(target),
                    replacements,
                ),
                return_target: return_target.as_ref().map(|target| {
                    Self::replace_expression(
                        &read_context.rewrite_expression_from_snapshot(target),
                        replacements,
                    )
                }),
                does_return: *does_return,
            },
            LirTerminator::Return { expression } => LirTerminator::Return {
                expression: expression.as_ref().map(|expression| {
                    Self::replace_expression(&self.rewrite_expression(expression), replacements)
                }),
            },
            LirTerminator::Unreachable => LirTerminator::Unreachable,
            LirTerminator::Trap => LirTerminator::Trap,
        }
    }

    fn rewrite_expression_from_snapshot(&self, expression: &LirExpression) -> LirExpression {
        let mut context = self.clone();
        context.rewrite_expression(expression)
    }

    fn replace_expression(
        expression: &LirExpression,
        replacements: &[(LirExpression, LirExpression)],
    ) -> LirExpression {
        for (from, to) in replacements.iter().rev() {
            if expression == from {
                return to.clone();
            }
        }
        match expression {
            LirExpression::Read(location) => {
                LirExpression::Read(Box::new(Self::replace_location(location, replacements)))
            }
            LirExpression::AddressOf { location, bits } => LirExpression::AddressOf {
                location: Box::new(Self::replace_location(location, replacements)),
                bits: *bits,
            },
            LirExpression::Load { space, addr, bits } => LirExpression::Load {
                space: space.clone(),
                addr: Box::new(Self::replace_expression(addr, replacements)),
                bits: *bits,
            },
            LirExpression::Unary { op, arg, bits } => LirExpression::Unary {
                op: op.clone(),
                arg: Box::new(Self::replace_expression(arg, replacements)),
                bits: *bits,
            },
            LirExpression::Binary {
                op,
                left,
                right,
                bits,
            } => LirExpression::Binary {
                op: op.clone(),
                left: Box::new(Self::replace_expression(left, replacements)),
                right: Box::new(Self::replace_expression(right, replacements)),
                bits: *bits,
            },
            LirExpression::Cast { op, arg, bits } => LirExpression::Cast {
                op: op.clone(),
                arg: Box::new(Self::replace_expression(arg, replacements)),
                bits: *bits,
            },
            LirExpression::Compare {
                op,
                left,
                right,
                bits,
            } => LirExpression::Compare {
                op: op.clone(),
                left: Box::new(Self::replace_expression(left, replacements)),
                right: Box::new(Self::replace_expression(right, replacements)),
                bits: *bits,
            },
            LirExpression::Concat { parts, bits } => LirExpression::Concat {
                parts: parts
                    .iter()
                    .map(|part| Self::replace_expression(part, replacements))
                    .collect(),
                bits: *bits,
            },
            LirExpression::Extract { arg, lsb, bits } => LirExpression::Extract {
                arg: Box::new(Self::replace_expression(arg, replacements)),
                lsb: *lsb,
                bits: *bits,
            },
            LirExpression::Select {
                condition,
                when_true,
                when_false,
                bits,
            } => LirExpression::Select {
                condition: Box::new(Self::replace_expression(condition, replacements)),
                when_true: Box::new(Self::replace_expression(when_true, replacements)),
                when_false: Box::new(Self::replace_expression(when_false, replacements)),
                bits: *bits,
            },
            LirExpression::Intrinsic { name, args, bits } => LirExpression::Intrinsic {
                name: name.clone(),
                args: args
                    .iter()
                    .map(|arg| Self::replace_expression(arg, replacements))
                    .collect(),
                bits: *bits,
            },
            LirExpression::ReadProperty {
                reference,
                name,
                bits,
            } => LirExpression::ReadProperty {
                reference: Box::new(Self::replace_expression(reference, replacements)),
                name: name.clone(),
                bits: *bits,
            },
            LirExpression::ReadElement {
                reference,
                index,
                bits,
            } => LirExpression::ReadElement {
                reference: Box::new(Self::replace_expression(reference, replacements)),
                index: Box::new(Self::replace_expression(index, replacements)),
                bits: *bits,
            },
            LirExpression::Const { value, bits } => LirExpression::Const {
                value: *value,
                bits: *bits,
            },
            LirExpression::Function { name, bits } => LirExpression::Function {
                name: name.clone(),
                bits: *bits,
            },
            LirExpression::DataAddress { name, bits } => LirExpression::DataAddress {
                name: name.clone(),
                bits: *bits,
            },
            LirExpression::Undefined { bits } => LirExpression::Undefined { bits: *bits },
            LirExpression::Poison { bits } => LirExpression::Poison { bits: *bits },
            LirExpression::Null { bits } => LirExpression::Null { bits: *bits },
            LirExpression::Allocate { kind, bits } => LirExpression::Allocate {
                kind: kind.clone(),
                bits: *bits,
            },
        }
    }

    fn replace_location(
        location: &LirLocation,
        replacements: &[(LirExpression, LirExpression)],
    ) -> LirLocation {
        match location {
            LirLocation::Memory { space, addr, bits } => LirLocation::Memory {
                space: space.clone(),
                addr: Box::new(Self::replace_expression(addr, replacements)),
                bits: *bits,
            },
            LirLocation::IndexedMemory { name, index, bits } => LirLocation::IndexedMemory {
                name: name.clone(),
                index: Box::new(Self::replace_expression(index, replacements)),
                bits: *bits,
            },
            LirLocation::Register { name, bits } => LirLocation::Register {
                name: name.clone(),
                bits: *bits,
            },
            LirLocation::Flag { name, bits } => LirLocation::Flag {
                name: name.clone(),
                bits: *bits,
            },
            LirLocation::ProgramCounter { bits } => LirLocation::ProgramCounter { bits: *bits },
            LirLocation::Temporary { id, bits } => LirLocation::Temporary {
                id: *id,
                bits: *bits,
            },
            LirLocation::StackMemory { name, offset, bits } => LirLocation::StackMemory {
                name: name.clone(),
                offset: *offset,
                bits: *bits,
            },
        }
    }

    fn rewrite_expression(&mut self, expression: &LirExpression) -> LirExpression {
        match expression {
            LirExpression::Read(location) => {
                LirExpression::Read(Box::new(self.read_location(location)))
            }
            LirExpression::AddressOf { location, bits } => LirExpression::AddressOf {
                location: Box::new(self.read_location(location)),
                bits: *bits,
            },
            LirExpression::Load { space, addr, bits } => LirExpression::Load {
                space: space.clone(),
                addr: Box::new(self.rewrite_expression(addr)),
                bits: *bits,
            },
            LirExpression::Unary { op, arg, bits } => LirExpression::Unary {
                op: op.clone(),
                arg: Box::new(self.rewrite_expression(arg)),
                bits: *bits,
            },
            LirExpression::Binary {
                op,
                left,
                right,
                bits,
            } => LirExpression::Binary {
                op: op.clone(),
                left: Box::new(self.rewrite_expression(left)),
                right: Box::new(self.rewrite_expression(right)),
                bits: *bits,
            },
            LirExpression::Cast { op, arg, bits } => LirExpression::Cast {
                op: op.clone(),
                arg: Box::new(self.rewrite_expression(arg)),
                bits: *bits,
            },
            LirExpression::Compare {
                op,
                left,
                right,
                bits,
            } => LirExpression::Compare {
                op: op.clone(),
                left: Box::new(self.rewrite_expression(left)),
                right: Box::new(self.rewrite_expression(right)),
                bits: *bits,
            },
            LirExpression::Concat { parts, bits } => LirExpression::Concat {
                parts: parts
                    .iter()
                    .map(|part| self.rewrite_expression(part))
                    .collect(),
                bits: *bits,
            },
            LirExpression::Extract { arg, lsb, bits } => LirExpression::Extract {
                arg: Box::new(self.rewrite_expression(arg)),
                lsb: *lsb,
                bits: *bits,
            },
            LirExpression::Select {
                condition,
                when_true,
                when_false,
                bits,
            } => LirExpression::Select {
                condition: Box::new(self.rewrite_expression(condition)),
                when_true: Box::new(self.rewrite_expression(when_true)),
                when_false: Box::new(self.rewrite_expression(when_false)),
                bits: *bits,
            },
            LirExpression::Intrinsic { name, args, bits } => LirExpression::Intrinsic {
                name: name.clone(),
                args: args
                    .iter()
                    .map(|arg| self.rewrite_expression(arg))
                    .collect(),
                bits: *bits,
            },
            LirExpression::ReadProperty {
                reference,
                name,
                bits,
            } => LirExpression::ReadProperty {
                reference: Box::new(self.rewrite_expression(reference)),
                name: name.clone(),
                bits: *bits,
            },
            LirExpression::ReadElement {
                reference,
                index,
                bits,
            } => LirExpression::ReadElement {
                reference: Box::new(self.rewrite_expression(reference)),
                index: Box::new(self.rewrite_expression(index)),
                bits: *bits,
            },
            LirExpression::Const { value, bits } => LirExpression::Const {
                value: *value,
                bits: *bits,
            },
            LirExpression::Function { name, bits } => LirExpression::Function {
                name: name.clone(),
                bits: *bits,
            },
            LirExpression::DataAddress { name, bits } => LirExpression::DataAddress {
                name: name.clone(),
                bits: *bits,
            },
            LirExpression::Undefined { bits } => LirExpression::Undefined { bits: *bits },
            LirExpression::Poison { bits } => LirExpression::Poison { bits: *bits },
            LirExpression::Null { bits } => LirExpression::Null { bits: *bits },
            LirExpression::Allocate { kind, bits } => LirExpression::Allocate {
                kind: kind.clone(),
                bits: *bits,
            },
        }
    }

    fn read_location(&mut self, location: &LirLocation) -> LirLocation {
        match location {
            LirLocation::Register { name, bits } => LirLocation::Register {
                name: self.read_name(SsaKey::Register(name.clone()), name),
                bits: *bits,
            },
            LirLocation::Flag { name, bits } => LirLocation::Flag {
                name: self.read_name(SsaKey::Flag(name.clone()), name),
                bits: *bits,
            },
            LirLocation::ProgramCounter { bits } => LirLocation::ProgramCounter { bits: *bits },
            LirLocation::Temporary { id, bits } => LirLocation::Temporary {
                id: self.read_temp_id(*id),
                bits: *bits,
            },
            LirLocation::Memory { space, addr, bits } => LirLocation::Memory {
                space: space.clone(),
                addr: Box::new(self.rewrite_expression(addr)),
                bits: *bits,
            },
            LirLocation::IndexedMemory { name, index, bits } => LirLocation::IndexedMemory {
                name: name.clone(),
                index: Box::new(self.rewrite_expression(index)),
                bits: *bits,
            },
            LirLocation::StackMemory { name, offset, bits } => LirLocation::StackMemory {
                name: name.clone(),
                offset: *offset,
                bits: *bits,
            },
        }
    }

    fn write_location(&mut self, location: &LirLocation) -> LirLocation {
        match location {
            LirLocation::Register { name, bits } => LirLocation::Register {
                name: self.write_name(SsaKey::Register(name.clone()), name),
                bits: *bits,
            },
            LirLocation::Flag { name, bits } => LirLocation::Flag {
                name: self.write_name(SsaKey::Flag(name.clone()), name),
                bits: *bits,
            },
            LirLocation::ProgramCounter { bits } => LirLocation::ProgramCounter { bits: *bits },
            LirLocation::Temporary { id, bits } => LirLocation::Temporary {
                id: self.write_temp_id(*id),
                bits: *bits,
            },
            LirLocation::Memory { space, addr, bits } => LirLocation::Memory {
                space: space.clone(),
                addr: Box::new(self.rewrite_expression(addr)),
                bits: *bits,
            },
            LirLocation::IndexedMemory { name, index, bits } => LirLocation::IndexedMemory {
                name: name.clone(),
                index: Box::new(self.rewrite_expression(index)),
                bits: *bits,
            },
            LirLocation::StackMemory { name, offset, bits } => LirLocation::StackMemory {
                name: name.clone(),
                offset: *offset,
                bits: *bits,
            },
        }
    }

    fn read_name(&self, key: SsaKey, base: &str) -> String {
        let version = self.versions.get(&key).copied().unwrap_or(0);
        format!("{base}.{version}")
    }

    fn version(&self, key: &SsaKey) -> u64 {
        self.versions.get(key).copied().unwrap_or(0)
    }

    fn read_key_location(&self, key: &SsaKey, bits: u16) -> LirLocation {
        match key {
            SsaKey::Register(name) => LirLocation::Register {
                name: self.read_name(key.clone(), name),
                bits,
            },
            SsaKey::Flag(name) => LirLocation::Flag {
                name: self.read_name(key.clone(), name),
                bits,
            },
        }
    }

    fn write_key_location(&mut self, key: &SsaKey, bits: u16) -> LirLocation {
        match key {
            SsaKey::Register(name) => LirLocation::Register {
                name: self.write_name(key.clone(), name),
                bits,
            },
            SsaKey::Flag(name) => LirLocation::Flag {
                name: self.write_name(key.clone(), name),
                bits,
            },
        }
    }

    fn write_name(&mut self, key: SsaKey, base: &str) -> String {
        let next = self
            .allocated_versions
            .entry(key.clone())
            .or_insert_with(|| self.versions.get(&key).copied().unwrap_or(0));
        *next = next.saturating_add(1);
        self.versions.insert(key, *next);
        format!("{base}.{next}")
    }

    fn merge_allocations_from(&mut self, other: &SsaContext) {
        for (key, version) in &other.allocated_versions {
            let current = self.allocated_versions.entry(key.clone()).or_insert(0);
            *current = (*current).max(*version);
        }
    }

    fn read_temp_id(&self, original: u32) -> u32 {
        let version = self.temp_versions.get(&original).copied().unwrap_or(0);
        self.temp_ids
            .get(&(original, version))
            .copied()
            .unwrap_or(original)
    }

    fn write_temp_id(&mut self, original: u32) -> u32 {
        let version = self.temp_versions.entry(original).or_insert(0);
        *version = version.saturating_add(1);
        let key = (original, *version);
        if let Some(id) = self.temp_ids.get(&key) {
            return *id;
        }
        let id = self.next_temp_id;
        self.next_temp_id = self.next_temp_id.saturating_add(1);
        self.temp_ids.insert(key, id);
        id
    }
}

#[cfg(test)]
mod tests {
    use crate::irs::lir::{
        LirBlock, LirEffect, LirExpression, LirFunction, LirInstruction, LirLocation,
        LirOperationBinary, LirOperationCompare, LirStatus, LirTerminator, ssa_block_lir,
        ssa_function_lir, ssa_instruction_lir,
    };

    #[test]
    fn ssa_instruction_reads_effect_inputs_from_instruction_entry_versions() {
        let rax = LirLocation::Register {
            name: "rax".to_string(),
            bits: 64,
        };
        let rbx = LirLocation::Register {
            name: "rbx".to_string(),
            bits: 64,
        };
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: rax.clone(),
                    expression: LirExpression::Binary {
                        op: LirOperationBinary::Add,
                        left: Box::new(LirExpression::Read(Box::new(rbx.clone()))),
                        right: Box::new(LirExpression::Const { value: 8, bits: 64 }),
                        bits: 64,
                    },
                },
                LirEffect::Set {
                    dst: rbx,
                    expression: LirExpression::Binary {
                        op: LirOperationBinary::Add,
                        left: Box::new(LirExpression::Read(Box::new(rax))),
                        right: Box::new(LirExpression::Const { value: 1, bits: 64 }),
                        bits: 64,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        assert_eq!(
            ssa_instruction_lir(&lir).text(),
            "rax.1 = rbx.0 + 0x8\nrbx.1 = rax.0 + 0x1"
        );
    }

    #[test]
    fn ssa_instruction_keeps_store_addresses_sequenced_after_stack_pointer_writes() {
        let rsp = LirLocation::Register {
            name: "rsp".to_string(),
            bits: 64,
        };
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: rsp.clone(),
                    expression: LirExpression::Binary {
                        op: LirOperationBinary::Sub,
                        left: Box::new(LirExpression::Read(Box::new(rsp.clone()))),
                        right: Box::new(LirExpression::Const { value: 8, bits: 64 }),
                        bits: 64,
                    },
                },
                LirEffect::Store {
                    space: crate::irs::lir::LirAddressSpace::Default,
                    addr: LirExpression::Read(Box::new(rsp)),
                    expression: LirExpression::Const {
                        value: 0x401005,
                        bits: 64,
                    },
                    bits: 64,
                },
            ],
            terminator: LirTerminator::Call {
                target: LirExpression::Read(Box::new(LirLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                })),
                return_target: None,
                does_return: Some(true),
            },
        };

        assert_eq!(
            ssa_instruction_lir(&lir).text(),
            "rsp.1 = rsp.0 - 0x8\n@64[rsp.1] = 0x401005\ncall rax.0"
        );
    }

    #[test]
    fn ssa_instruction_reuses_defined_result_inside_later_effect_expressions() {
        let rsp = LirLocation::Register {
            name: "rsp".to_string(),
            bits: 64,
        };
        let zf = LirLocation::Flag {
            name: "zf".to_string(),
            bits: 1,
        };
        let result = LirExpression::Binary {
            op: LirOperationBinary::Sub,
            left: Box::new(LirExpression::Read(Box::new(rsp.clone()))),
            right: Box::new(LirExpression::Const {
                value: 0x48,
                bits: 64,
            }),
            bits: 64,
        };
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![
                LirEffect::Set {
                    dst: rsp,
                    expression: result.clone(),
                },
                LirEffect::Set {
                    dst: zf,
                    expression: LirExpression::Compare {
                        op: LirOperationCompare::Eq,
                        left: Box::new(result),
                        right: Box::new(LirExpression::Const { value: 0, bits: 64 }),
                        bits: 1,
                    },
                },
            ],
            terminator: LirTerminator::FallThrough,
        };

        assert_eq!(
            ssa_instruction_lir(&lir).text(),
            "rsp.1 = rsp.0 - 0x48\nzf.1 = rsp.1 == 0x0"
        );
    }

    #[test]
    fn ssa_block_carries_versions_into_terminators() {
        let rax = LirLocation::Register {
            name: "rax".to_string(),
            bits: 64,
        };
        let zf = LirLocation::Flag {
            name: "zf".to_string(),
            bits: 1,
        };
        let block = LirBlock {
            name: None,
            instructions: vec![LirInstruction {
                address: None,
                status: LirStatus::Complete,
                effects: vec![LirEffect::Set {
                    dst: zf.clone(),
                    expression: LirExpression::Compare {
                        op: LirOperationCompare::Eq,
                        left: Box::new(LirExpression::Read(Box::new(rax))),
                        right: Box::new(LirExpression::Const { value: 0, bits: 64 }),
                        bits: 1,
                    },
                }],
                terminator: LirTerminator::Branch {
                    condition: LirExpression::Read(Box::new(zf)),
                    true_target: LirExpression::Const {
                        value: 0x401040,
                        bits: 64,
                    },
                    false_target: LirExpression::Const {
                        value: 0x401020,
                        bits: 64,
                    },
                },
            }],
        };

        assert_eq!(
            ssa_block_lir(&block).text(),
            "zf.1 = rax.0 == 0x0\nif zf.1 then 0x401040 else 0x401020"
        );
    }

    #[test]
    fn ssa_function_inserts_phi_at_cfg_join() {
        let rax = LirLocation::Register {
            name: "rax".to_string(),
            bits: 64,
        };
        let rbx = LirLocation::Register {
            name: "rbx".to_string(),
            bits: 64,
        };
        let block = |address, effects, terminator| LirBlock {
            name: None,
            instructions: vec![LirInstruction {
                address: Some(address),
                status: LirStatus::Complete,
                effects,
                terminator,
            }],
        };
        let function = LirFunction {
            name: None,
            blocks: vec![
                block(
                    0x1000,
                    Vec::new(),
                    LirTerminator::Branch {
                        condition: LirExpression::Const { value: 1, bits: 1 },
                        true_target: LirExpression::Const {
                            value: 0x2000,
                            bits: 64,
                        },
                        false_target: LirExpression::Const {
                            value: 0x3000,
                            bits: 64,
                        },
                    },
                ),
                block(
                    0x2000,
                    vec![LirEffect::Set {
                        dst: rax.clone(),
                        expression: LirExpression::Const { value: 1, bits: 64 },
                    }],
                    LirTerminator::Jump {
                        target: LirExpression::Const {
                            value: 0x4000,
                            bits: 64,
                        },
                    },
                ),
                block(
                    0x3000,
                    vec![LirEffect::Set {
                        dst: rax.clone(),
                        expression: LirExpression::Const { value: 2, bits: 64 },
                    }],
                    LirTerminator::Jump {
                        target: LirExpression::Const {
                            value: 0x4000,
                            bits: 64,
                        },
                    },
                ),
                block(
                    0x4000,
                    vec![LirEffect::Set {
                        dst: rbx,
                        expression: LirExpression::Read(Box::new(rax)),
                    }],
                    LirTerminator::Return { expression: None },
                ),
            ],
        };

        assert_eq!(
            ssa_function_lir(&function).text(),
            "if 0x1 then 0x2000 else 0x3000\nrax.1 = 0x1\ngoto 0x4000\nrax.2 = 0x2\ngoto 0x4000\nrax.3 = phi(rax.1, rax.2)\nrbx.1 = rax.3\nreturn"
        );
    }
}
