use std::collections::HashMap;

use crate::irs::lir::{
    LirBlock, LirEffect, LirExpression, LirFunction, LirInstruction, LirLocation, LirModule,
    LirTerminator,
};

#[derive(Clone, Default)]
struct SsaContext {
    versions: HashMap<SsaKey, u64>,
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

pub fn ssa_module_lir(module: &LirModule) -> LirModule {
    LirModule {
        name: module.name.clone(),
        functions: module.functions.iter().map(ssa_function_lir).collect(),
        data: module.data.clone(),
    }
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
        format!("{base}_{version}")
    }

    fn write_name(&mut self, key: SsaKey, base: &str) -> String {
        let version = self.versions.entry(key).or_insert(0);
        *version = version.saturating_add(1);
        format!("{base}_{version}")
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
        LirBlock, LirEffect, LirExpression, LirInstruction, LirLocation, LirOperationBinary,
        LirOperationCompare, LirStatus, LirTerminator, ssa_block_lir, ssa_instruction_lir,
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
            "rax_1 = rbx_0 + 0x8\nrbx_1 = rax_0 + 0x1"
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
            "rsp_1 = rsp_0 - 0x8\n@64[rsp_1] = 0x401005\ncall rax_0"
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
            "rsp_1 = rsp_0 - 0x48\nzf_1 = rsp_1 == 0x0"
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
            "zf_1 = rax_0 == 0x0\nif zf_1 then 0x401040 else 0x401020"
        );
    }
}
