use crate::controlflow::{Block, Function, Instruction};
use crate::lifters::llvm::optimizers::Optimizers;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticFenceKind, SemanticLocation, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator, SemanticTrapKind,
};
use crate::Config;
use inkwell::basic_block::BasicBlock;
use inkwell::IntPredicate;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::memory_buffer::MemoryBuffer;
use inkwell::module::Module;
use inkwell::passes::PassBuilderOptions;
use inkwell::targets::{CodeModel, InitializationConfig, RelocMode, Target, TargetMachine};
use inkwell::types::{BasicMetadataTypeEnum, IntType};
use inkwell::values::{BasicMetadataValueEnum, FunctionValue, IntValue, PointerValue};
use inkwell::OptimizationLevel;
use std::collections::{BTreeSet, HashMap};
use std::io::Error;
use std::num::NonZeroU32;

pub struct Lifter {
    config: Config,
    context: &'static Context,
    module: Module<'static>,
    emitted: BTreeSet<String>,
}

struct LoweringContext<'ctx, 'm> {
    context: &'ctx Context,
    module: &'m Module<'ctx>,
    builder: Builder<'ctx>,
    function: FunctionValue<'ctx>,
    slots: HashMap<String, PointerValue<'ctx>>,
}

impl Lifter {
    pub fn new(config: Config) -> Self {
        let context: &'static Context = Box::leak(Box::new(Context::create()));
        let module = context.create_module(&config.lifters.llvm.module_name);
        Self {
            config,
            context,
            module,
            emitted: BTreeSet::new(),
        }
    }

    pub fn lift_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        let name = format!("instruction_{:x}", instruction.address);
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let function = self.add_void_function(&name);
        let mut lowering = self.lowering_context(function);
        lowering.lower_instruction(instruction)?;
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_block(&mut self, block: &Block<'_>) -> Result<(), Error> {
        let name = format!("block_{:x}", block.address());
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let function = self.add_void_function(&name);
        let mut lowering = self.lowering_context(function);
        for instruction in block.instructions() {
            lowering.lower_instruction(&instruction)?;
        }
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_function(&mut self, function: &Function<'_>) -> Result<(), Error> {
        let name = format!("function_{:x}", function.address());
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let llvm_function = self.add_void_function(&name);
        let mut lowering = self.lowering_context(llvm_function);
        lowering.lower_function(function)?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn text(&self) -> String {
        self.module.print_to_string().to_string()
    }

    pub fn bitcode(&self) -> Vec<u8> {
        let buffer = self.module.write_bitcode_to_memory();
        buffer.as_slice().to_vec()
    }

    pub fn normalized(&self) -> Result<Self, Error> {
        let context: &'static Context = Box::leak(Box::new(Context::create()));
        let normalized = normalize_ir_text(&self.text());
        let mut bytes = normalized.into_bytes();
        bytes.push(0);
        let buffer = MemoryBuffer::create_from_memory_range_copy(&bytes, "binlex-normalized.ll");
        let module = context
            .create_module_from_ir(buffer)
            .map_err(|err| Error::other(err.to_string()))?;
        let normalized = Self {
            config: self.config.clone(),
            context,
            module,
            emitted: self.emitted.clone(),
        };
        normalized.verify_if_enabled()?;
        Ok(normalized)
    }

    pub fn optimizers(&self) -> Result<Optimizers, Error> {
        Ok(Optimizers::new(self.duplicate()?))
    }

    pub fn mem2reg(&self) -> Result<Self, Error> {
        self.run_function_pass("mem2reg")
    }

    pub fn instcombine(&self) -> Result<Self, Error> {
        self.run_function_pass("instcombine")
    }

    pub fn cfg(&self) -> Result<Self, Error> {
        self.run_function_pass("simplifycfg")
    }

    pub fn gvn(&self) -> Result<Self, Error> {
        self.run_function_pass("gvn")
    }

    pub fn sroa(&self) -> Result<Self, Error> {
        self.run_function_pass("sroa")
    }

    pub fn dce(&self) -> Result<Self, Error> {
        self.run_function_pass("dce")
    }

    pub fn verify(&self) -> Result<(), Error> {
        self.module
            .verify()
            .map_err(|err| Error::other(err.to_string()))
    }

    fn add_void_function(&self, name: &str) -> FunctionValue<'static> {
        if let Some(function) = self.module.get_function(name) {
            return function;
        }
        let fn_type = self.context.void_type().fn_type(&[], false);
        self.module.add_function(name, fn_type, None)
    }

    fn lowering_context(&self, function: FunctionValue<'static>) -> LoweringContext<'static, '_> {
        let builder = self.context.create_builder();
        let entry = self.context.append_basic_block(function, "entry");
        builder.position_at_end(entry);
        LoweringContext {
            context: self.context,
            module: &self.module,
            builder,
            function,
            slots: HashMap::new(),
        }
    }

    fn verify_if_enabled(&self) -> Result<(), Error> {
        if self.config.lifters.llvm.verify {
            self.verify()
        } else {
            Ok(())
        }
    }

    fn duplicate(&self) -> Result<Self, Error> {
        let context: &'static Context = Box::leak(Box::new(Context::create()));
        let buffer = MemoryBuffer::create_from_memory_range_copy(&self.bitcode(), "binlex.bc");
        let module = Module::parse_bitcode_from_buffer(&buffer, context)
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(Self {
            config: self.config.clone(),
            context,
            module,
            emitted: self.emitted.clone(),
        })
    }

    fn run_function_pass(&self, pass_pipeline: &str) -> Result<Self, Error> {
        let optimized = self.duplicate()?;
        let machine = optimized.target_machine()?;
        for function in optimized.module.get_functions() {
            if function.get_first_basic_block().is_none() {
                continue;
            }
            let options = PassBuilderOptions::create();
            options.set_verify_each(optimized.config.lifters.llvm.verify);
            function
                .run_passes(pass_pipeline, &machine, options)
                .map_err(|err| Error::other(err.to_string()))?;
        }
        optimized.verify_if_enabled()?;
        Ok(optimized)
    }

    fn target_machine(&self) -> Result<TargetMachine, Error> {
        Target::initialize_native(&InitializationConfig::default())
            .map_err(|err| Error::other(err.to_string()))?;
        let triple = TargetMachine::get_default_triple();
        let target = Target::from_triple(&triple).map_err(|err| Error::other(err.to_string()))?;
        target
            .create_target_machine(
                &triple,
                "generic",
                "",
                OptimizationLevel::Default,
                RelocMode::Default,
                CodeModel::Default,
            )
            .ok_or_else(|| Error::other("failed to create llvm target machine"))
    }
}

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    fn lower_function(&mut self, function: &Function<'_>) -> Result<(), Error> {
        let mut block_map = HashMap::<u64, BasicBlock<'ctx>>::new();
        for block in function.blocks() {
            let llvm_block = self
                .context
                .append_basic_block(self.function, &format!("block_{:x}", block.address()));
            block_map.insert(block.address(), llvm_block);
        }

        let exit_block = self.context.append_basic_block(self.function, "exit");
        let entry = self
            .function
            .get_first_basic_block()
            .expect("function should have entry block");
        let block_addresses = function.block_addresses();
        let entry_address = block_addresses
            .iter()
            .copied()
            .find(|address| *address == function.address())
            .or_else(|| block_addresses.first().copied())
            .ok_or_else(|| Error::other("function contains no basic blocks"))?;
        let entry_target = *block_map.get(&entry_address).ok_or_else(|| {
            Error::other("function entry block is missing from llvm block map")
        })?;
        self.builder.position_at_end(entry);
        self.builder
            .build_unconditional_branch(entry_target)
            .map_err(|err| Error::other(err.to_string()))?;

        for block in function.blocks() {
            let llvm_block = *block_map
                .get(&block.address())
                .ok_or_else(|| Error::other("missing llvm block for binlex block"))?;
            self.builder.position_at_end(llvm_block);
            for instruction in block.instructions() {
                self.lower_instruction(&instruction)?;
            }
            if self
                .builder
                .get_insert_block()
                .and_then(|current| current.get_terminator())
                .is_none()
            {
                self.lower_block_cfg_terminator(&block, &block_map, exit_block)?;
            }
        }

        self.builder.position_at_end(exit_block);
        if exit_block.get_terminator().is_none() {
            self.builder
                .build_return(None)
                .map_err(|err| Error::other(err.to_string()))?;
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), Error> {
        let needs_return = self
            .builder
            .get_insert_block()
            .and_then(|block| block.get_terminator())
            .is_none();
        if needs_return {
            self.builder
                .build_return(None)
                .map_err(|err| Error::other(err.to_string()))?;
        }
        Ok(())
    }

    fn lower_block_cfg_terminator(
        &mut self,
        block: &Block<'_>,
        block_map: &HashMap<u64, BasicBlock<'ctx>>,
        exit_block: BasicBlock<'ctx>,
    ) -> Result<(), Error> {
        let fallback_jump_target = block
            .to()
            .iter()
            .next()
            .and_then(|address| block_map.get(address).copied())
            .unwrap_or(exit_block);
        let fallback_fallthrough_target = block
            .next()
            .and_then(|address| block_map.get(&address).copied())
            .unwrap_or(exit_block);

        let Some(semantics) = block.terminator.semantics.as_ref() else {
            if block.terminator.is_return {
                self.builder
                    .build_return(None)
                    .map_err(|err| Error::other(err.to_string()))?;
            } else if block.terminator.is_conditional {
                return Err(Error::other(
                    "conditional block terminator requires semantics for llvm lowering",
                ));
            } else if block.terminator.is_jump {
                self.builder
                    .build_unconditional_branch(fallback_jump_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            } else {
                self.builder
                    .build_unconditional_branch(fallback_fallthrough_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            return Ok(());
        };

        match &semantics.terminator {
            SemanticTerminator::FallThrough => {
                self.builder
                    .build_unconditional_branch(fallback_fallthrough_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Jump { target } => {
                let target = self
                    .resolve_block_target(target, block_map)
                    .unwrap_or(fallback_jump_target);
                self.builder
                    .build_unconditional_branch(target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                let condition = self.lower_expression(condition)?;
                let condition = self.to_bool(condition);
                let true_target = self
                    .resolve_block_target(true_target, block_map)
                    .unwrap_or(fallback_jump_target);
                let false_target = self
                    .resolve_block_target(false_target, block_map)
                    .unwrap_or(fallback_fallthrough_target);
                self.builder
                    .build_conditional_branch(condition, true_target, false_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Call { does_return, .. } => {
                if does_return.unwrap_or(true) {
                    let target = block
                        .next()
                        .and_then(|address| block_map.get(&address).copied())
                        .unwrap_or(exit_block);
                    self.builder
                        .build_unconditional_branch(target)
                        .map_err(|err| Error::other(err.to_string()))?;
                } else {
                    self.builder
                        .build_unreachable()
                        .map_err(|err| Error::other(err.to_string()))?;
                }
            }
            SemanticTerminator::Return { .. } => {
                self.builder
                    .build_return(None)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Unreachable | SemanticTerminator::Trap => {
                self.builder
                    .build_unreachable()
                    .map_err(|err| Error::other(err.to_string()))?;
            }
        }
        Ok(())
    }

    fn lower_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        let helper = self.declare_void_helper(
            "binlex_instruction_address",
            &[self.context.i64_type().into()],
            false,
        );
        let address = self
            .context
            .i64_type()
            .const_int(instruction.address, false);
        self.builder
            .build_call(helper, &[address.into()], "")
            .map_err(|err| Error::other(err.to_string()))?;

        if let Some(semantics) = instruction.semantics.as_ref() {
            self.lower_semantics(semantics)?;
        }
        Ok(())
    }

    fn lower_semantics(&mut self, semantics: &InstructionSemantics) -> Result<(), Error> {
        for effect in &semantics.effects {
            self.lower_effect(effect)?;
        }
        self.lower_terminator(&semantics.terminator)
    }

    fn lower_effect(&mut self, effect: &SemanticEffect) -> Result<(), Error> {
        match effect {
            SemanticEffect::Set { dst, expression } => match dst {
                SemanticLocation::Memory { space, addr, bits } => {
                    self.emit_store(space, addr, expression, *bits)?;
                }
                _ => {
                    let value = self.lower_expression(expression)?;
                    let slot = self.slot_for_location(dst)?;
                    self.builder
                        .build_store(slot, value)
                        .map_err(|err| Error::other(err.to_string()))?;
                }
            },
            SemanticEffect::Store {
                space,
                addr,
                expression,
                bits,
            } => self.emit_store(space, addr, expression, *bits)?,
            SemanticEffect::Fence { kind } => {
                let helper = self.declare_void_helper(
                    &format!("binlex_fence_{}", render_fence_kind(kind)),
                    &[],
                    false,
                );
                self.builder
                    .build_call(helper, &[], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::Trap { kind } => {
                let helper = self.declare_void_helper(
                    &format!("binlex_trap_{}", render_trap_kind(kind)),
                    &[],
                    false,
                );
                self.builder
                    .build_call(helper, &[], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::Intrinsic { name, args, .. } => {
                let helper = self.declare_void_helper(
                    &format!("binlex_effect_{}", sanitize_symbol(name)),
                    &[],
                    true,
                );
                let args = self.lower_arg_values(args)?;
                self.builder
                    .build_call(helper, &args, "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::Nop => {}
        }
        Ok(())
    }

    fn lower_terminator(&mut self, terminator: &SemanticTerminator) -> Result<(), Error> {
        match terminator {
            SemanticTerminator::FallThrough => {}
            SemanticTerminator::Jump { target } => {
                let helper = self.declare_void_helper(
                    "binlex_term_jump",
                    &[self.context.i64_type().into()],
                    false,
                );
                let target = self.lower_expression(target)?;
                let target = self.to_i64(target);
                self.builder
                    .build_call(helper, &[target.into()], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                let helper = self.declare_void_helper(
                    "binlex_term_branch",
                    &[
                        self.context.bool_type().into(),
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                    ],
                    false,
                );
                let condition = self.lower_expression(condition)?;
                let condition = self.to_bool(condition);
                let true_target = self.lower_expression(true_target)?;
                let true_target = self.to_i64(true_target);
                let false_target = self.lower_expression(false_target)?;
                let false_target = self.to_i64(false_target);
                self.builder
                    .build_call(
                        helper,
                        &[condition.into(), true_target.into(), false_target.into()],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Call {
                target,
                return_target,
                does_return,
            } => {
                let helper = self.declare_void_helper(
                    "binlex_term_call",
                    &[
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.context.bool_type().into(),
                    ],
                    false,
                );
                let target = self.lower_expression(target)?;
                let target = self.to_i64(target);
                let return_target = return_target
                    .as_ref()
                    .map(|expr| self.lower_expression(expr))
                    .transpose()?
                    .map(|value| self.to_i64(value))
                    .unwrap_or_else(|| self.context.i64_type().const_zero());
                let does_return = self
                    .context
                    .bool_type()
                    .const_int(does_return.unwrap_or(true) as u64, false);
                self.builder
                    .build_call(
                        helper,
                        &[target.into(), return_target.into(), does_return.into()],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Return { expression } => {
                if let Some(expression) = expression {
                    let value = self.lower_expression(expression)?;
                    let helper = self.declare_void_helper(
                        "binlex_term_return",
                        &[value.get_type().into()],
                        false,
                    );
                    self.builder
                        .build_call(helper, &[value.into()], "")
                        .map_err(|err| Error::other(err.to_string()))?;
                }
            }
            SemanticTerminator::Unreachable => {
                self.builder
                    .build_unreachable()
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Trap => {
                let helper = self.declare_void_helper("binlex_term_trap", &[], false);
                self.builder
                    .build_call(helper, &[], "")
                    .map_err(|err| Error::other(err.to_string()))?;
            }
        }
        Ok(())
    }

    fn emit_store(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        expression: &SemanticExpression,
        bits: u16,
    ) -> Result<(), Error> {
        let helper = self.declare_void_helper(
            &format!(
                "binlex_store_{}_{}",
                sanitize_symbol(&render_address_space(space)),
                bits
            ),
            &[self.context.i64_type().into(), self.int_type(bits).into()],
            false,
        );
        let addr = self.lower_expression(addr)?;
        let addr = self.to_i64(addr);
        let value = self.lower_expression(expression)?;
        let value = match value.get_type().get_bit_width().cmp(&(bits as u32)) {
            std::cmp::Ordering::Equal => value,
            std::cmp::Ordering::Less => self
                .builder
                .build_int_z_extend(value, self.int_type(bits), "store_zext")
                .map_err(|err| Error::other(err.to_string()))?,
            std::cmp::Ordering::Greater => self
                .builder
                .build_int_truncate(value, self.int_type(bits), "store_trunc")
                .map_err(|err| Error::other(err.to_string()))?,
        };
        self.builder
            .build_call(helper, &[addr.into(), value.into()], "")
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(())
    }

    fn lower_expression(
        &mut self,
        expression: &SemanticExpression,
    ) -> Result<IntValue<'ctx>, Error> {
        match expression {
            SemanticExpression::Const { value, bits } => {
                Ok(const_int(self.int_type(*bits), *value))
            }
            SemanticExpression::Read(location) => self.read_location(location),
            SemanticExpression::Load { space, addr, bits } => {
                let helper = self.declare_value_helper(
                    &format!(
                        "binlex_load_{}_{}",
                        sanitize_symbol(&render_address_space(space)),
                        bits
                    ),
                    self.int_type(*bits),
                    &[self.context.i64_type().into()],
                    false,
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                self.call_value(helper, &[addr.into()], "loadtmp")
            }
            SemanticExpression::Unary { op, arg, bits } => {
                let arg = self.lower_expression(arg)?;
                self.lower_unary(*op, arg, *bits)
            }
            SemanticExpression::Binary {
                op,
                left,
                right,
                bits,
            } => {
                let left = self.lower_expression(left)?;
                let right = self.lower_expression(right)?;
                self.lower_binary(*op, left, right, *bits)
            }
            SemanticExpression::Cast { op, arg, bits } => {
                let arg = self.lower_expression(arg)?;
                self.lower_cast(*op, arg, *bits)
            }
            SemanticExpression::Compare {
                op, left, right, ..
            } => {
                let left = self.lower_expression(left)?;
                let right = self.lower_expression(right)?;
                self.lower_compare(*op, left, right)
            }
            SemanticExpression::Select {
                condition,
                when_true,
                when_false,
                ..
            } => {
                let condition = self.lower_expression(condition)?;
                let condition = self.to_bool(condition);
                let when_true = self.lower_expression(when_true)?;
                let when_false = self.lower_expression(when_false)?;
                Ok(self
                    .builder
                    .build_select(condition, when_true, when_false, "selecttmp")
                    .map_err(|err| Error::other(err.to_string()))?
                    .into_int_value())
            }
            SemanticExpression::Extract { arg, lsb, bits } => {
                let arg = self.lower_expression(arg)?;
                let shifted = self
                    .builder
                    .build_right_shift(
                        arg,
                        arg.get_type().const_int(*lsb as u64, false),
                        false,
                        "extract_shift",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
                if shifted.get_type().get_bit_width() == *bits as u32 {
                    Ok(shifted)
                } else {
                    self.builder
                        .build_int_truncate(shifted, self.int_type(*bits), "extract_trunc")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            SemanticExpression::Concat { parts, bits } => {
                let target = self.int_type(*bits);
                let mut acc = target.const_zero();
                for part in parts {
                    let value = self.lower_expression(part)?;
                    let zext = if value.get_type().get_bit_width() == *bits as u32 {
                        value
                    } else {
                        self.builder
                            .build_int_z_extend(value, target, "concat_zext")
                            .map_err(|err| Error::other(err.to_string()))?
                    };
                    let shift = target.const_int(value.get_type().get_bit_width() as u64, false);
                    acc = self
                        .builder
                        .build_left_shift(acc, shift, "concat_shift")
                        .map_err(|err| Error::other(err.to_string()))?;
                    acc = self
                        .builder
                        .build_or(acc, zext, "concat_or")
                        .map_err(|err| Error::other(err.to_string()))?;
                }
                Ok(acc)
            }
            SemanticExpression::Undefined { bits } | SemanticExpression::Poison { bits } => {
                Ok(self.int_type(*bits).const_zero())
            }
            SemanticExpression::Intrinsic { name, args, bits } => {
                let helper = self.declare_value_helper(
                    &format!("binlex_expr_{}", sanitize_symbol(name)),
                    self.int_type(*bits),
                    &[],
                    true,
                );
                let args = self.lower_arg_values(args)?;
                self.call_value(helper, &args, "intrinsicexpr")
            }
        }
    }

    fn read_location(&mut self, location: &SemanticLocation) -> Result<IntValue<'ctx>, Error> {
        match location {
            SemanticLocation::Memory { space, addr, bits } => {
                let helper = self.declare_value_helper(
                    &format!(
                        "binlex_load_{}_{}",
                        sanitize_symbol(&render_address_space(space)),
                        bits
                    ),
                    self.int_type(*bits),
                    &[self.context.i64_type().into()],
                    false,
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                self.call_value(helper, &[addr.into()], "memread")
            }
            _ => {
                let slot = self.slot_for_location(location)?;
                let ty = self.location_type(location);
                Ok(self
                    .builder
                    .build_load(ty, slot, "readtmp")
                    .map_err(|err| Error::other(err.to_string()))?
                    .into_int_value())
            }
        }
    }

    fn lower_arg_values(
        &mut self,
        args: &[SemanticExpression],
    ) -> Result<Vec<BasicMetadataValueEnum<'ctx>>, Error> {
        args.iter()
            .map(|arg| self.lower_expression(arg).map(Into::into))
            .collect()
    }

    fn call_value(
        &self,
        function: FunctionValue<'ctx>,
        args: &[BasicMetadataValueEnum<'ctx>],
        name: &str,
    ) -> Result<IntValue<'ctx>, Error> {
        self.builder
            .build_call(function, args, name)
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected value result from helper call"))
            .map(|value| value.into_int_value())
    }

    fn lower_unary(
        &self,
        op: SemanticOperationUnary,
        arg: IntValue<'ctx>,
        bits: u16,
    ) -> Result<IntValue<'ctx>, Error> {
        match op {
            SemanticOperationUnary::Not => self
                .builder
                .build_not(arg, "nottmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationUnary::Neg => self
                .builder
                .build_int_neg(arg, "negtmp")
                .map_err(|err| Error::other(err.to_string())),
            _ => {
                let helper = self.declare_value_helper(
                    &format!("binlex_unary_{:?}", op).to_lowercase(),
                    self.int_type(bits),
                    &[arg.get_type().into()],
                    false,
                );
                self.call_value(helper, &[arg.into()], "unarytmp")
            }
        }
    }

    fn lower_binary(
        &self,
        op: SemanticOperationBinary,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
        bits: u16,
    ) -> Result<IntValue<'ctx>, Error> {
        let shift_amount = |right: IntValue<'ctx>| -> Result<IntValue<'ctx>, Error> {
            let target = left.get_type();
            let right_bits = right.get_type().get_bit_width();
            let target_bits = target.get_bit_width();

            if right_bits == target_bits {
                Ok(right)
            } else if right_bits < target_bits {
                self.builder
                    .build_int_z_extend(right, target, "shift_zext")
                    .map_err(|err| Error::other(err.to_string()))
            } else {
                self.builder
                    .build_int_truncate(right, target, "shift_trunc")
                    .map_err(|err| Error::other(err.to_string()))
            }
        };

        match op {
            SemanticOperationBinary::Add | SemanticOperationBinary::AddWithCarry => self
                .builder
                .build_int_add(left, right, "addtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Sub | SemanticOperationBinary::SubWithBorrow => self
                .builder
                .build_int_sub(left, right, "subtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Mul => self
                .builder
                .build_int_mul(left, right, "multmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::UDiv => self
                .builder
                .build_int_unsigned_div(left, right, "udivtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::SDiv => self
                .builder
                .build_int_signed_div(left, right, "sdivtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::URem => self
                .builder
                .build_int_unsigned_rem(left, right, "uremtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::SRem => self
                .builder
                .build_int_signed_rem(left, right, "sremtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::And => self
                .builder
                .build_and(left, right, "andtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Or => self
                .builder
                .build_or(left, right, "ortmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Xor => self
                .builder
                .build_xor(left, right, "xortmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::Shl => self
                .builder
                .build_left_shift(left, shift_amount(right)?, "shltmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::LShr => self
                .builder
                .build_right_shift(left, shift_amount(right)?, false, "lshrtmp")
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::AShr => self
                .builder
                .build_right_shift(left, shift_amount(right)?, true, "ashrtmp")
                .map_err(|err| Error::other(err.to_string())),
            _ => {
                let helper = self.declare_value_helper(
                    &format!("binlex_binary_{:?}", op).to_lowercase(),
                    self.int_type(bits),
                    &[left.get_type().into(), right.get_type().into()],
                    false,
                );
                self.call_value(helper, &[left.into(), right.into()], "binarytmp")
            }
        }
    }

    fn lower_cast(
        &self,
        op: SemanticOperationCast,
        arg: IntValue<'ctx>,
        bits: u16,
    ) -> Result<IntValue<'ctx>, Error> {
        let target = self.int_type(bits);
        let source_bits = arg.get_type().get_bit_width();
        match op {
            SemanticOperationCast::ZeroExtend => {
                if source_bits == bits as u32 {
                    Ok(arg)
                } else if source_bits > bits as u32 {
                    self.builder
                        .build_int_truncate(arg, target, "trunctmp")
                        .map_err(|err| Error::other(err.to_string()))
                } else {
                    self.builder
                        .build_int_z_extend(arg, target, "zexttmp")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            SemanticOperationCast::SignExtend => {
                if source_bits == bits as u32 {
                    Ok(arg)
                } else if source_bits > bits as u32 {
                    self.builder
                        .build_int_truncate(arg, target, "trunctmp")
                        .map_err(|err| Error::other(err.to_string()))
                } else {
                    self.builder
                        .build_int_s_extend(arg, target, "sexttmp")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            SemanticOperationCast::Truncate => {
                if source_bits == bits as u32 {
                    Ok(arg)
                } else {
                    self.builder
                        .build_int_truncate(arg, target, "trunctmp")
                        .map_err(|err| Error::other(err.to_string()))
                }
            }
            _ => {
                let helper = self.declare_value_helper(
                    &format!("binlex_cast_{:?}", op).to_lowercase(),
                    target,
                    &[arg.get_type().into()],
                    false,
                );
                self.call_value(helper, &[arg.into()], "casttmp")
            }
        }
    }

    fn lower_compare(
        &self,
        op: SemanticOperationCompare,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>, Error> {
        let predicate = match op {
            SemanticOperationCompare::Eq => Some(IntPredicate::EQ),
            SemanticOperationCompare::Ne => Some(IntPredicate::NE),
            SemanticOperationCompare::Ult => Some(IntPredicate::ULT),
            SemanticOperationCompare::Ule => Some(IntPredicate::ULE),
            SemanticOperationCompare::Ugt => Some(IntPredicate::UGT),
            SemanticOperationCompare::Uge => Some(IntPredicate::UGE),
            SemanticOperationCompare::Slt => Some(IntPredicate::SLT),
            SemanticOperationCompare::Sle => Some(IntPredicate::SLE),
            SemanticOperationCompare::Sgt => Some(IntPredicate::SGT),
            SemanticOperationCompare::Sge => Some(IntPredicate::SGE),
            _ => None,
        };
        if let Some(predicate) = predicate {
            self.builder
                .build_int_compare(predicate, left, right, "cmptmp")
                .map_err(|err| Error::other(err.to_string()))
        } else {
            let helper = self.declare_value_helper(
                &format!("binlex_compare_{:?}", op).to_lowercase(),
                self.context.bool_type(),
                &[left.get_type().into(), right.get_type().into()],
                false,
            );
            self.call_value(helper, &[left.into(), right.into()], "cmptmp")
        }
    }

    fn slot_for_location(
        &mut self,
        location: &SemanticLocation,
    ) -> Result<PointerValue<'ctx>, Error> {
        let key = render_location(location);
        if let Some(slot) = self.slots.get(&key) {
            return Ok(*slot);
        }
        let ty = self.location_type(location);
        let slot = self.build_entry_alloca(ty, &sanitize_symbol(&key))?;
        self.builder
            .build_store(slot, ty.const_zero())
            .map_err(|err| Error::other(err.to_string()))?;
        self.slots.insert(key, slot);
        Ok(slot)
    }

    fn build_entry_alloca(
        &self,
        ty: IntType<'ctx>,
        name: &str,
    ) -> Result<PointerValue<'ctx>, Error> {
        let entry = self
            .function
            .get_first_basic_block()
            .expect("function should have entry block");
        let builder = self.context.create_builder();
        if let Some(first) = entry.get_first_instruction() {
            builder.position_before(&first);
        } else {
            builder.position_at_end(entry);
        }
        builder
            .build_alloca(ty, name)
            .map_err(|err| Error::other(err.to_string()))
    }

    fn declare_void_helper(
        &self,
        name: &str,
        args: &[BasicMetadataTypeEnum<'ctx>],
        varargs: bool,
    ) -> FunctionValue<'ctx> {
        let name = sanitize_symbol(name);
        self.module.get_function(&name).unwrap_or_else(|| {
            self.module
                .add_function(&name, self.context.void_type().fn_type(args, varargs), None)
        })
    }

    fn declare_value_helper(
        &self,
        name: &str,
        return_type: IntType<'ctx>,
        args: &[BasicMetadataTypeEnum<'ctx>],
        varargs: bool,
    ) -> FunctionValue<'ctx> {
        let name = sanitize_symbol(name);
        self.module.get_function(&name).unwrap_or_else(|| {
            self.module
                .add_function(&name, return_type.fn_type(args, varargs), None)
        })
    }

    fn int_type(&self, bits: u16) -> IntType<'ctx> {
        match bits {
            0 | 1 => self.context.bool_type(),
            8 => self.context.i8_type(),
            16 => self.context.i16_type(),
            32 => self.context.i32_type(),
            64 => self.context.i64_type(),
            128 => self.context.i128_type(),
            n => self
                .context
                .custom_width_int_type(NonZeroU32::new(n as u32).expect("non-zero width"))
                .expect("valid integer width"),
        }
    }

    fn location_type(&self, location: &SemanticLocation) -> IntType<'ctx> {
        self.int_type(match location {
            SemanticLocation::Register { bits, .. } => *bits,
            SemanticLocation::Flag { bits, .. } => *bits,
            SemanticLocation::ProgramCounter { bits } => *bits,
            SemanticLocation::Temporary { bits, .. } => *bits,
            SemanticLocation::Memory { bits, .. } => *bits,
        })
    }

    fn to_i64(&self, value: IntValue<'ctx>) -> IntValue<'ctx> {
        match value.get_type().get_bit_width().cmp(&64) {
            std::cmp::Ordering::Equal => value,
            std::cmp::Ordering::Less => self
                .builder
                .build_int_z_extend(value, self.context.i64_type(), "zext64")
                .expect("zext"),
            std::cmp::Ordering::Greater => self
                .builder
                .build_int_truncate(value, self.context.i64_type(), "trunc64")
                .expect("trunc"),
        }
    }

    fn to_bool(&self, value: IntValue<'ctx>) -> IntValue<'ctx> {
        if value.get_type().get_bit_width() == 1 {
            value
        } else {
            self.builder
                .build_int_compare(
                    IntPredicate::NE,
                    value,
                    value.get_type().const_zero(),
                    "tobool",
                )
                .expect("bool")
        }
    }

    fn resolve_block_target(
        &self,
        expression: &SemanticExpression,
        block_map: &HashMap<u64, BasicBlock<'ctx>>,
    ) -> Option<BasicBlock<'ctx>> {
        let address = match expression {
            SemanticExpression::Const { value, .. } => u64::try_from(*value).ok()?,
            _ => return None,
        };
        block_map.get(&address).copied()
    }
}

fn const_int(ty: IntType<'_>, value: u128) -> IntValue<'_> {
    let words = [value as u64, (value >> 64) as u64];
    ty.const_int_arbitrary_precision(&words)
}

fn sanitize_symbol(name: &str) -> String {
    name.chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => ch,
            _ => '_',
        })
        .collect()
}

fn render_location(location: &SemanticLocation) -> String {
    match location {
        SemanticLocation::Register { name, bits } => format!("reg_{}_{}", name, bits),
        SemanticLocation::Flag { name, bits } => format!("flag_{}_{}", name, bits),
        SemanticLocation::ProgramCounter { bits } => format!("pc_{}", bits),
        SemanticLocation::Temporary { id, bits } => format!("tmp_{}_{}", id, bits),
        SemanticLocation::Memory { space, bits, .. } => {
            format!("mem_{}_{}", render_address_space(space), bits)
        }
    }
}

fn render_address_space(space: &SemanticAddressSpace) -> String {
    match space {
        SemanticAddressSpace::Default => "default".to_string(),
        SemanticAddressSpace::Stack => "stack".to_string(),
        SemanticAddressSpace::Heap => "heap".to_string(),
        SemanticAddressSpace::Global => "global".to_string(),
        SemanticAddressSpace::Io => "io".to_string(),
        SemanticAddressSpace::Segment { name } => format!("segment_{}", sanitize_symbol(name)),
        SemanticAddressSpace::ArchSpecific { name } => format!("arch_{}", sanitize_symbol(name)),
    }
}

fn render_fence_kind(kind: &SemanticFenceKind) -> String {
    match kind {
        SemanticFenceKind::Acquire => "acquire".to_string(),
        SemanticFenceKind::Release => "release".to_string(),
        SemanticFenceKind::AcquireRelease => "acquire_release".to_string(),
        SemanticFenceKind::SequentiallyConsistent => "seq_cst".to_string(),
        SemanticFenceKind::ArchSpecific { name } => format!("arch_{}", sanitize_symbol(name)),
    }
}

fn render_trap_kind(kind: &SemanticTrapKind) -> String {
    match kind {
        SemanticTrapKind::Breakpoint => "breakpoint".to_string(),
        SemanticTrapKind::DivideError => "divide_error".to_string(),
        SemanticTrapKind::Overflow => "overflow".to_string(),
        SemanticTrapKind::InvalidOpcode => "invalid_opcode".to_string(),
        SemanticTrapKind::GeneralProtection => "general_protection".to_string(),
        SemanticTrapKind::PageFault => "page_fault".to_string(),
        SemanticTrapKind::AlignmentFault => "alignment_fault".to_string(),
        SemanticTrapKind::Syscall => "syscall".to_string(),
        SemanticTrapKind::Interrupt => "interrupt".to_string(),
        SemanticTrapKind::ArchSpecific { name } => format!("arch_{}", sanitize_symbol(name)),
    }
}

fn normalize_ir_text(ir: &str) -> String {
    let mut function_map = HashMap::<String, String>::new();
    let mut block_maps = HashMap::<String, HashMap<String, String>>::new();
    let mut helper_map = HashMap::<String, String>::new();
    let mut helper_counters = HashMap::<String, usize>::new();
    let mut function_index = 0usize;
    let mut current_function: Option<String> = None;
    let mut current_block_index = 0usize;

    for line in ir.lines() {
        if let Some(name) = parse_defined_function_name(line) {
            current_function = Some(name.clone());
            current_block_index = 0;
            block_maps.entry(name.clone()).or_default();
            if is_lifted_symbol(&name) {
                function_map.insert(name, format!("f{}", function_index));
                function_index += 1;
            }
        }

        if let (Some(function_name), Some(label)) = (&current_function, parse_block_label(line)) {
            let normalized = match label.as_str() {
                "entry" => "entry".to_string(),
                "exit" => "exit".to_string(),
                _ => {
                    let name = format!("b{}", current_block_index);
                    current_block_index += 1;
                    name
                }
            };
            block_maps
                .entry(function_name.clone())
                .or_default()
                .insert(label, normalized);
        }
    }

    let mut rewritten_lines = Vec::new();
    let mut address_map = HashMap::<u64, u64>::new();
    let mut token_map = HashMap::<u64, u64>::new();
    let mut next_address = 0u64;
    let mut next_token = 0u64;
    let mut current_function: Option<String> = None;

    for line in ir.lines() {
        if let Some(name) = parse_defined_function_name(line) {
            current_function = Some(name);
        }

        let mut rewritten = line.to_string();
        for (old, new) in &function_map {
            rewritten = rewritten.replace(&format!("@{}", old), &format!("@{}", new));
        }
        if let Some(function_name) = &current_function {
            if let Some(current_block_map) = block_maps.get(function_name) {
                for (old, new) in current_block_map {
                    rewritten = rewritten.replace(&format!("%{}", old), &format!("%{}", new));
                }
                if let Some((old, new)) = current_block_map
                    .iter()
                    .find(|(old, _)| rewritten.trim_start().starts_with(&format!("{}:", old)))
                {
                    let suffix = rewritten[old.len() + 1..].to_string();
                    rewritten = format!("{}:{}", new, suffix);
                }
            }
        }
        rewritten = normalize_helper_names(&rewritten, &mut helper_map, &mut helper_counters);
        rewritten = normalize_helper_addresses(&rewritten, &mut address_map, &mut next_address);
        rewritten = normalize_cil_metadata_tokens(&rewritten, &mut token_map, &mut next_token);
        rewritten_lines.push(rewritten);
    }

    drop_unused_exit_blocks(&rewritten_lines).join("\n")
}

fn parse_defined_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let after_define = trimmed.strip_prefix("define ")?;
    let at = after_define.find('@')?;
    let rest = &after_define[at + 1..];
    let end = rest.find('(')?;
    Some(rest[..end].to_string())
}

fn parse_block_label(line: &str) -> Option<String> {
    if line.starts_with(' ') || line.starts_with('\t') {
        return None;
    }
    let colon = line.find(':')?;
    let label = &line[..colon];
    if label.is_empty() || label.starts_with(';') {
        return None;
    }
    Some(label.to_string())
}

fn is_lifted_symbol(name: &str) -> bool {
    name.starts_with("instruction_") || name.starts_with("block_") || name.starts_with("function_")
}

fn normalize_helper_addresses(
    line: &str,
    address_map: &mut HashMap<u64, u64>,
    next_address: &mut u64,
) -> String {
    const HELPERS: &[&str] = &[
        "@binlex_instruction_address(",
        "@binlex_term_jump(",
        "@binlex_term_branch(",
        "@binlex_term_call(",
    ];

    if !HELPERS.iter().any(|helper| line.contains(helper)) {
        return line.to_string();
    }

    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 4 <= bytes.len() && &line[i..i + 4] == "i64 " {
            let start = i + 4;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                if let Ok(raw) = line[start..end].parse::<u64>() {
                    let normalized = *address_map.entry(raw).or_insert_with(|| {
                        let value = *next_address;
                        *next_address += 1;
                        value
                    });
                    result.push_str("i64 ");
                    result.push_str(&normalized.to_string());
                    i = end;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn normalize_helper_names(
    line: &str,
    helper_map: &mut HashMap<String, String>,
    helper_counters: &mut HashMap<String, usize>,
) -> String {
    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
            {
                end += 1;
            }
            if end > start {
                let symbol = &line[start..end];
                let normalized = normalize_helper_symbol(symbol, helper_map, helper_counters);
                result.push('@');
                result.push_str(&normalized);
                i = end;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn normalize_helper_symbol(
    symbol: &str,
    helper_map: &mut HashMap<String, String>,
    helper_counters: &mut HashMap<String, usize>,
) -> String {
    if !symbol.starts_with("binlex_") {
        return symbol.to_string();
    }
    if symbol == "binlex_instruction_address" || symbol.starts_with("llvm.") {
        return symbol.to_string();
    }
    if let Some(existing) = helper_map.get(symbol) {
        return existing.clone();
    }

    let family = if symbol.starts_with("binlex_effect_cil_") {
        "binlex_effect_cil"
    } else if symbol.starts_with("binlex_expr_cil_") {
        "binlex_expr_cil"
    } else if symbol.starts_with("binlex_term_") {
        "binlex_term"
    } else if symbol.starts_with("binlex_effect_") {
        "binlex_effect"
    } else if symbol.starts_with("binlex_expr_") {
        "binlex_expr"
    } else if symbol.starts_with("binlex_load_") {
        "binlex_load"
    } else if symbol.starts_with("binlex_store_") {
        "binlex_store"
    } else if symbol.starts_with("binlex_fence_") {
        "binlex_fence"
    } else if symbol.starts_with("binlex_trap_") {
        "binlex_trap"
    } else {
        return symbol.to_string();
    };

    let counter = helper_counters.entry(family.to_string()).or_insert(0);
    let normalized = format!("{}_{}", family, *counter);
    *counter += 1;
    helper_map.insert(symbol.to_string(), normalized.clone());
    normalized
}

fn normalize_cil_metadata_tokens(
    line: &str,
    token_map: &mut HashMap<u64, u64>,
    next_token: &mut u64,
) -> String {
    if !(line.contains("@binlex_effect_cil_") || line.contains("@binlex_expr_cil_")) {
        return line.to_string();
    }

    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 4 <= bytes.len() && &line[i..i + 4] == "i32 " {
            let start = i + 4;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                if let Ok(raw) = line[start..end].parse::<u64>() {
                    let normalized = *token_map.entry(raw).or_insert_with(|| {
                        let value = *next_token;
                        *next_token += 1;
                        value
                    });
                    result.push_str("i32 ");
                    result.push_str(&normalized.to_string());
                    i = end;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn drop_unused_exit_blocks(lines: &[String]) -> Vec<String> {
    let exit_referenced = lines.iter().any(|line| line.contains("%exit"));
    if exit_referenced {
        return lines.to_vec();
    }

    let mut result = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        if line.trim_start() == "exit:                                             ; No predecessors!"
            || line.trim_start() == "exit:"
            || line.trim_start().starts_with("exit: ; No predecessors!")
        {
            i += 1;
            while i < lines.len() {
                let next = &lines[i];
                if parse_block_label(next).is_some()
                    || parse_defined_function_name(next).is_some()
                    || next.trim() == "}"
                {
                    break;
                }
                i += 1;
            }
            continue;
        }
        result.push(line.clone());
        i += 1;
    }
    result
}

#[cfg(test)]
mod normalization_tests {
    use super::normalize_ir_text;

    #[test]
    fn normalize_cil_helpers_tokens_and_unused_exit() {
        let ir = r#"; ModuleID = 'binlex'
source_filename = "binlex"

define void @function_1234() {
entry:
  br label %block_1234

block_1234:
  call void @binlex_instruction_address(i64 6442450944)
  call void (...) @binlex_effect_cil_LdArg0()
  call void @binlex_instruction_address(i64 6442450945)
  call void (...) @binlex_effect_cil_Call(i32 167772295)
  %intrinsicexpr = call i64 (...) @binlex_expr_cil_Call_target(i32 167772295)
  call void @binlex_term_call(i64 %intrinsicexpr, i64 6442450946, i1 true)
  call void @binlex_instruction_address(i64 6442450946)
  ret void

exit:                                             ; No predecessors!
  ret void
}

declare void @binlex_instruction_address(i64)
declare void @binlex_effect_cil_LdArg0(...)
declare void @binlex_effect_cil_Call(...)
declare void @binlex_term_call(i64, i64, i1)
declare i64 @binlex_expr_cil_Call_target(...)
"#;

        let normalized = normalize_ir_text(ir);
        assert!(normalized.contains("define void @f0()"));
        assert!(normalized.contains("b0:"));
        assert!(normalized.contains("@binlex_effect_cil_0"));
        assert!(normalized.contains("@binlex_effect_cil_1"));
        assert!(normalized.contains("@binlex_expr_cil_0"));
        assert!(normalized.contains("@binlex_term_0"));
        assert!(normalized.contains("@binlex_instruction_address(i64 0)"));
        assert!(normalized.contains("@binlex_instruction_address(i64 1)"));
        assert!(normalized.contains("@binlex_instruction_address(i64 2)"));
        assert!(normalized.contains("@binlex_effect_cil_1(i32 0)"));
        assert!(normalized.contains("@binlex_expr_cil_0(i32 0)"));
        assert!(!normalized.contains("167772295"));
        assert!(!normalized.contains("No predecessors!"));
        assert!(!normalized.contains("\nexit:"));
    }
}
