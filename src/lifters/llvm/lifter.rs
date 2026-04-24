use crate::Config;
use crate::Architecture;
use crate::controlflow::{Block, Function, Instruction};
use crate::io::Stderr;
use crate::lifters::llvm::abi::coerce_int_value_width;
use crate::lifters::llvm::optimizers::Optimizers;
use crate::lifters::llvm::prepare::prepare_instruction_semantics;
use crate::lifters::llvm::verify::verify_module;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticFenceKind, SemanticLocation, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator, SemanticTrapKind,
};
use inkwell::attributes::AttributeLoc;
use inkwell::IntPredicate;
use inkwell::OptimizationLevel;
use inkwell::basic_block::BasicBlock;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::llvm_sys::core::{
    LLVMContextSetDiagnosticHandler, LLVMDisposeMessage, LLVMGetDiagInfoDescription,
};
use inkwell::llvm_sys::prelude::LLVMDiagnosticInfoRef;
use inkwell::memory_buffer::MemoryBuffer;
use inkwell::module::Module;
use inkwell::passes::PassBuilderOptions;
use inkwell::targets::{CodeModel, InitializationConfig, RelocMode, Target, TargetMachine};
use inkwell::types::{AnyType, BasicMetadataTypeEnum, IntType};
use inkwell::values::{BasicMetadataValueEnum, FunctionValue, IntValue, PointerValue};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::ffi::CStr;
use std::ffi::c_void;
use std::io::Error;
use std::num::NonZeroU32;

pub struct Lifter {
    config: Config,
    context: &'static Context,
    module: Module<'static>,
    emitted: BTreeSet<String>,
    architecture: Option<Architecture>,
}

#[derive(Default)]
struct DiagnosticCapture {
    messages: Vec<String>,
}

extern "C" fn capture_diagnostic(diagnostic_info: LLVMDiagnosticInfoRef, opaque: *mut c_void) {
    if opaque.is_null() {
        return;
    }
    let capture = unsafe { &mut *(opaque as *mut DiagnosticCapture) };
    let description = unsafe { LLVMGetDiagInfoDescription(diagnostic_info) };
    if description.is_null() {
        return;
    }
    let message = unsafe { CStr::from_ptr(description) }
        .to_string_lossy()
        .into_owned();
    unsafe {
        LLVMDisposeMessage(description);
    }
    capture.messages.push(message);
}

struct LoweringContext<'ctx, 'm> {
    context: &'ctx Context,
    module: &'m Module<'ctx>,
    builder: Builder<'ctx>,
    function: FunctionValue<'ctx>,
    function_name: String,
    slots: HashMap<String, PointerValue<'ctx>>,
    slot_locations: HashMap<String, SemanticLocation>,
    written_locations: BTreeSet<String>,
    native_return_adjust: Option<u16>,
    body_begin_emitted: bool,
    cached_flags_register: RefCell<Option<IntValue<'ctx>>>,
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
            architecture: None,
        }
    }

    pub fn lift_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        self.architecture.get_or_insert(instruction.architecture);
        self.bind_architecture()?;
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
        self.architecture.get_or_insert(block.architecture());
        self.bind_architecture()?;
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
        self.architecture.get_or_insert(function.architecture());
        self.bind_architecture()?;
        let name = format!("function_{:x}", function.address());
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let llvm_function = self.add_void_function(&name);
        let mut lowering = self.lowering_context(llvm_function);
        lowering.lower_function(function)?;
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn text(&self) -> String {
        self.module.print_to_string().to_string()
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn bitcode(&self) -> Vec<u8> {
        let buffer = self.module.write_bitcode_to_memory();
        buffer.as_slice().to_vec()
    }

    pub fn object(&self) -> Result<Vec<u8>, Error> {
        let codegen = self.mem2reg().unwrap_or_else(|_| self.duplicate().expect("duplicate lifter"));
        let machine = codegen.target_machine()?;
        let buffer = machine
            .write_to_memory_buffer(&codegen.module, inkwell::targets::FileType::Object)
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(buffer.as_slice().to_vec())
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
            architecture: self.architecture,
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
        self.run_function_pass("instcombine<no-verify-fixpoint>")
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
        verify_module(&self.module)
    }

    fn add_void_function(&self, name: &str) -> FunctionValue<'static> {
        if let Some(function) = self.module.get_function(name) {
            return function;
        }
        let fn_type = self.context.void_type().fn_type(&[], false);
        let function = self.module.add_function(name, fn_type, None);
        function.add_attribute(
            AttributeLoc::Function,
            self.context.create_string_attribute("frame-pointer", "none"),
        );
        function
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
            function_name: function.get_name().to_string_lossy().into_owned(),
            slots: HashMap::new(),
            slot_locations: HashMap::new(),
            written_locations: BTreeSet::new(),
            native_return_adjust: None,
            body_begin_emitted: false,
            cached_flags_register: RefCell::new(None),
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
            architecture: self.architecture,
        })
    }

    fn run_function_pass(&self, pass_pipeline: &str) -> Result<Self, Error> {
        let optimized = self.duplicate()?;
        let machine = optimized.target_machine()?;
        let context = optimized.module.get_context();
        let mut diagnostics = DiagnosticCapture::default();
        unsafe {
            LLVMContextSetDiagnosticHandler(
                context.raw(),
                Some(capture_diagnostic),
                (&mut diagnostics as *mut DiagnosticCapture).cast(),
            );
        }
        for function in optimized.module.get_functions() {
            if function.get_first_basic_block().is_none() {
                continue;
            }
            let options = PassBuilderOptions::create();
            options.set_verify_each(optimized.config.lifters.llvm.verify);
            if let Err(error) = function.run_passes(pass_pipeline, &machine, options) {
                let function_name = function.get_name().to_string_lossy().into_owned();
                let diagnostic = diagnostics
                    .messages
                    .last()
                    .cloned()
                    .unwrap_or_else(|| error.to_string());
                Stderr::print_debug(
                    &optimized.config,
                    format!(
                        "llvm pass pipeline={} function={} failed: {}",
                        pass_pipeline, function_name, diagnostic
                    ),
                );
                unsafe {
                    LLVMContextSetDiagnosticHandler(context.raw(), None, std::ptr::null_mut());
                }
                return Err(Error::other(format!(
                    "llvm pass {} failed for {}: {}",
                    pass_pipeline, function_name, diagnostic
                )));
            }
        }
        unsafe {
            LLVMContextSetDiagnosticHandler(context.raw(), None, std::ptr::null_mut());
        }
        if let Some(diagnostic) = diagnostics
            .messages
            .iter()
            .find(|message| !message.is_empty())
        {
            Stderr::print_debug(
                &optimized.config,
                format!(
                    "llvm pass pipeline={} diagnostic: {}",
                    pass_pipeline, diagnostic
                ),
            );
        }
        optimized.verify_if_enabled()?;
        Ok(optimized)
    }

    fn target_machine(&self) -> Result<TargetMachine, Error> {
        Target::initialize_native(&InitializationConfig::default())
            .map_err(|err| Error::other(err.to_string()))?;
        let triple_string = match self.architecture.unwrap_or(Architecture::AMD64) {
            Architecture::I386 => "i386-pc-linux-gnu",
            Architecture::AMD64 => "x86_64-pc-linux-gnu",
            _ => "x86_64-pc-linux-gnu",
        };
        let triple = inkwell::targets::TargetTriple::create(triple_string);
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

    fn bind_architecture(&self) -> Result<(), Error> {
        let triple_string = match self.architecture.unwrap_or(Architecture::AMD64) {
            Architecture::I386 => "i386-pc-linux-gnu",
            Architecture::AMD64 => "x86_64-pc-linux-gnu",
            _ => "x86_64-pc-linux-gnu",
        };
        self.module
            .set_triple(&inkwell::targets::TargetTriple::create(triple_string));
        Ok(())
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

        let mut exit_block = None;
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
        let entry_target = *block_map
            .get(&entry_address)
            .ok_or_else(|| Error::other("function entry block is missing from llvm block map"))?;
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
                self.lower_block_cfg_terminator(&block, &block_map, &mut exit_block)?;
            }
        }

        if let Some(exit_block) = exit_block {
            self.builder.position_at_end(exit_block);
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
            self.sync_slots_to_architecture()?;
            self.emit_body_marker("body_end")?;
            if let Some(adjust) = self.native_return_adjust {
                self.emit_native_return(adjust)?;
            } else {
                self.builder
                    .build_return(None)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
        }
        Ok(())
    }

    fn lower_block_cfg_terminator(
        &mut self,
        block: &Block<'_>,
        block_map: &HashMap<u64, BasicBlock<'ctx>>,
        exit_block: &mut Option<BasicBlock<'ctx>>,
    ) -> Result<(), Error> {
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
                let fallback_jump_target = block
                    .to()
                    .iter()
                    .next()
                    .and_then(|address| block_map.get(address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                self.builder
                    .build_unconditional_branch(fallback_jump_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            } else {
                let fallback_fallthrough_target = block
                    .next()
                    .and_then(|address| block_map.get(&address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                self.builder
                    .build_unconditional_branch(fallback_fallthrough_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            return Ok(());
        };

        match &semantics.terminator {
            SemanticTerminator::FallThrough => {
                let fallback_fallthrough_target = block
                    .next()
                    .and_then(|address| block_map.get(&address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                self.builder
                    .build_unconditional_branch(fallback_fallthrough_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Jump { target } => {
                let fallback_jump_target = block
                    .to()
                    .iter()
                    .next()
                    .and_then(|address| block_map.get(address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
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
                let fallback_jump_target = block
                    .to()
                    .iter()
                    .next()
                    .and_then(|address| block_map.get(address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                let fallback_fallthrough_target = block
                    .next()
                    .and_then(|address| block_map.get(&address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
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
                        .unwrap_or_else(|| self.ensure_exit_block(exit_block));
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

    fn ensure_exit_block(
        &self,
        exit_block: &mut Option<BasicBlock<'ctx>>,
    ) -> BasicBlock<'ctx> {
        if let Some(block) = *exit_block {
            block
        } else {
            let block = self.context.append_basic_block(self.function, "exit");
            *exit_block = Some(block);
            block
        }
    }

    fn lower_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        if let Some(semantics) = instruction.semantics.as_ref() {
            *self.cached_flags_register.borrow_mut() = None;
            let prepared = prepare_instruction_semantics(semantics)?;
            self.emit_body_marker_if_needed()?;
            self.seed_instruction_inputs(&prepared)?;
            self.lower_semantics(&prepared)?;
            *self.cached_flags_register.borrow_mut() = None;
        }
        Ok(())
    }

    fn emit_body_marker_if_needed(&mut self) -> Result<(), Error> {
        if !self.body_begin_emitted {
            self.emit_body_marker("body_begin")?;
            self.body_begin_emitted = true;
        }
        Ok(())
    }

    fn seed_instruction_inputs(&mut self, semantics: &InstructionSemantics) -> Result<(), Error> {
        let mut registers = Vec::<SemanticLocation>::new();
        let mut program_counters = Vec::<SemanticLocation>::new();
        let mut flags = Vec::<SemanticLocation>::new();
        for effect in &semantics.effects {
            self.collect_effect_reads(effect, &mut registers, &mut program_counters, &mut flags);
        }
        self.collect_terminator_reads(
            &semantics.terminator,
            &mut registers,
            &mut program_counters,
            &mut flags,
        );

        for location in flags {
            let _ = self.slot_for_location(&location)?;
        }
        for location in registers {
            let _ = self.slot_for_location(&location)?;
        }
        for location in program_counters {
            let _ = self.slot_for_location(&location)?;
        }
        Ok(())
    }

    fn collect_effect_reads(
        &self,
        effect: &SemanticEffect,
        registers: &mut Vec<SemanticLocation>,
        program_counters: &mut Vec<SemanticLocation>,
        flags: &mut Vec<SemanticLocation>,
    ) {
        match effect {
            SemanticEffect::Set { dst, expression } => {
                self.collect_expression_reads(expression, registers, program_counters, flags);
                if let Some((parent_name, parent_bits, _)) = self.x86_parent_register_alias(dst) {
                    push_unique_location(
                        registers,
                        SemanticLocation::Register {
                            name: parent_name,
                            bits: parent_bits,
                        },
                    );
                }
            }
            SemanticEffect::Store {
                addr, expression, ..
            } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            SemanticEffect::MemorySet {
                addr,
                value,
                count,
                decrement,
                ..
            } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
                self.collect_expression_reads(value, registers, program_counters, flags);
                self.collect_expression_reads(count, registers, program_counters, flags);
                self.collect_expression_reads(decrement, registers, program_counters, flags);
            }
            SemanticEffect::MemoryCopy {
                src_addr,
                dst_addr,
                count,
                decrement,
                ..
            } => {
                self.collect_expression_reads(src_addr, registers, program_counters, flags);
                self.collect_expression_reads(dst_addr, registers, program_counters, flags);
                self.collect_expression_reads(count, registers, program_counters, flags);
                self.collect_expression_reads(decrement, registers, program_counters, flags);
            }
            SemanticEffect::AtomicCmpXchg {
                addr,
                expected,
                desired,
                ..
            } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
                self.collect_expression_reads(expected, registers, program_counters, flags);
                self.collect_expression_reads(desired, registers, program_counters, flags);
            }
            SemanticEffect::Architecture { args, .. }
            | SemanticEffect::Intrinsic { args, .. } => {
                for arg in args {
                    self.collect_expression_reads(arg, registers, program_counters, flags);
                }
            }
            SemanticEffect::Fence { .. } | SemanticEffect::Trap { .. } | SemanticEffect::Nop => {}
        }
    }

    fn collect_terminator_reads(
        &self,
        terminator: &SemanticTerminator,
        registers: &mut Vec<SemanticLocation>,
        program_counters: &mut Vec<SemanticLocation>,
        flags: &mut Vec<SemanticLocation>,
    ) {
        match terminator {
            SemanticTerminator::Jump { target } => {
                self.collect_expression_reads(target, registers, program_counters, flags);
            }
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                self.collect_expression_reads(condition, registers, program_counters, flags);
                self.collect_expression_reads(true_target, registers, program_counters, flags);
                self.collect_expression_reads(false_target, registers, program_counters, flags);
            }
            SemanticTerminator::Call {
                target,
                return_target,
                ..
            } => {
                self.collect_expression_reads(target, registers, program_counters, flags);
                if let Some(return_target) = return_target {
                    self.collect_expression_reads(
                        return_target,
                        registers,
                        program_counters,
                        flags,
                    );
                }
            }
            SemanticTerminator::Return { expression } => {
                if let Some(expression) = expression {
                    self.collect_expression_reads(
                        expression,
                        registers,
                        program_counters,
                        flags,
                    );
                }
            }
            SemanticTerminator::FallThrough
            | SemanticTerminator::Trap
            | SemanticTerminator::Unreachable => {}
        }
    }

    fn collect_expression_reads(
        &self,
        expression: &SemanticExpression,
        registers: &mut Vec<SemanticLocation>,
        program_counters: &mut Vec<SemanticLocation>,
        flags: &mut Vec<SemanticLocation>,
    ) {
        match expression {
            SemanticExpression::Read(location) => match location.as_ref() {
                SemanticLocation::Register { .. } => {
                    push_unique_location(registers, location.as_ref().clone());
                }
                SemanticLocation::ProgramCounter { .. } => {
                    push_unique_location(program_counters, location.as_ref().clone());
                }
                SemanticLocation::Flag { .. } => {
                    push_unique_location(flags, location.as_ref().clone());
                }
                SemanticLocation::Memory { addr, .. } => {
                    self.collect_expression_reads(addr, registers, program_counters, flags);
                }
                SemanticLocation::Temporary { .. } => {}
            },
            SemanticExpression::Load { addr, .. } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
            }
            SemanticExpression::Unary { arg, .. }
            | SemanticExpression::Cast { arg, .. }
            | SemanticExpression::Extract { arg, .. } => {
                self.collect_expression_reads(arg, registers, program_counters, flags);
            }
            SemanticExpression::Binary { left, right, .. }
            | SemanticExpression::Compare { left, right, .. } => {
                self.collect_expression_reads(left, registers, program_counters, flags);
                self.collect_expression_reads(right, registers, program_counters, flags);
            }
            SemanticExpression::Select {
                condition,
                when_true,
                when_false,
                ..
            } => {
                self.collect_expression_reads(condition, registers, program_counters, flags);
                self.collect_expression_reads(when_true, registers, program_counters, flags);
                self.collect_expression_reads(when_false, registers, program_counters, flags);
            }
            SemanticExpression::Concat { parts, .. } => {
                for part in parts {
                    self.collect_expression_reads(part, registers, program_counters, flags);
                }
            }
            SemanticExpression::Intrinsic { args, .. }
            | SemanticExpression::Architecture { args, .. } => {
                for arg in args {
                    self.collect_expression_reads(arg, registers, program_counters, flags);
                }
            }
            SemanticExpression::Const { .. }
            | SemanticExpression::Undefined { .. }
            | SemanticExpression::Poison { .. } => {}
        }
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
                    let value = coerce_int_value_width(
                        &self.builder,
                        value,
                        self.location_type(dst),
                        "set_dst_zext",
                        "set_dst_trunc",
                    )?;
                    let slot = self.slot_for_location(dst)?;
                    self.builder
                        .build_store(slot, value)
                        .map_err(|err| Error::other(err.to_string()))?;
                    self.written_locations.insert(render_location(dst));
                    if let SemanticLocation::Register { name, bits } = dst {
                        self.merge_partial_register_write(name, *bits, value)?;
                    }
                }
            },
            SemanticEffect::Store {
                space,
                addr,
                expression,
                bits,
            } => self.emit_store(space, addr, expression, *bits)?,
            SemanticEffect::MemorySet {
                space,
                addr,
                value,
                count,
                element_bits,
                decrement,
            } => {
                if self.try_direct_memory_set(space, addr, value, count, *element_bits, decrement)? {
                    return Ok(());
                }
                let helper = self.declare_void_helper(
                    &format!(
                        "binlex_effect_memset_{}_{}",
                        sanitize_symbol(&render_address_space(space)),
                        element_bits
                    ),
                    &[
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.int_type(*element_bits).into(),
                        self.context.bool_type().into(),
                    ],
                    false,
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                let count = self.lower_expression(count)?;
                let count = self.to_i64(count);
                let value = self.lower_expression(value)?;
                let decrement = self.lower_expression(decrement)?;
                let decrement = self.to_bool(decrement);
                self.builder
                    .build_call(
                        helper,
                        &[addr.into(), count.into(), value.into(), decrement.into()],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::MemoryCopy {
                src_space,
                src_addr,
                dst_space,
                dst_addr,
                count,
                element_bits,
                decrement,
            } => {
                if self.try_direct_memory_copy(
                    src_space,
                    src_addr,
                    dst_space,
                    dst_addr,
                    count,
                    *element_bits,
                    decrement,
                )? {
                    return Ok(());
                }
                let helper = self.declare_void_helper(
                    &format!(
                        "binlex_effect_memcpy_{}_{}_{}",
                        sanitize_symbol(&render_address_space(src_space)),
                        sanitize_symbol(&render_address_space(dst_space)),
                        element_bits
                    ),
                    &[
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.context.i64_type().into(),
                        self.context.bool_type().into(),
                    ],
                    false,
                );
                let src_addr = self.lower_expression(src_addr)?;
                let src_addr = self.to_i64(src_addr);
                let dst_addr = self.lower_expression(dst_addr)?;
                let dst_addr = self.to_i64(dst_addr);
                let count = self.lower_expression(count)?;
                let count = self.to_i64(count);
                let decrement = self.lower_expression(decrement)?;
                let decrement = self.to_bool(decrement);
                self.builder
                    .build_call(
                        helper,
                        &[
                            src_addr.into(),
                            dst_addr.into(),
                            count.into(),
                            decrement.into(),
                        ],
                        "",
                    )
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticEffect::AtomicCmpXchg {
                space,
                addr,
                expected,
                desired,
                bits,
                observed,
            } => {
                let helper = self.declare_value_helper(
                    &format!(
                        "binlex_effect_atomic_cmpxchg_{}_{}",
                        sanitize_symbol(&render_address_space(space)),
                        bits
                    ),
                    self.int_type(*bits),
                    &[
                        self.context.i64_type().into(),
                        self.int_type(*bits).into(),
                        self.int_type(*bits).into(),
                    ],
                    false,
                );
                let addr = self.lower_expression(addr)?;
                let addr = self.to_i64(addr);
                let expected = self.lower_expression(expected)?;
                let desired = self.lower_expression(desired)?;
                let observed_value = self.call_value(
                    helper,
                    &[addr.into(), expected.into(), desired.into()],
                    "cmpxchg_observed",
                )?;
                let slot = self.slot_for_location(observed)?;
                self.builder
                    .build_store(slot, observed_value)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
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
            SemanticEffect::Architecture { name, args, .. } => {
                let helper = self.declare_void_helper(
                    &format!("binlex_arch_effect_{}", sanitize_symbol(name)),
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
                if let Some(adjust) = expression
                    .as_ref()
                    .and_then(Self::const_return_adjust)
                {
                    self.native_return_adjust = Some(adjust);
                } else if let Some(expression) = expression {
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

    fn const_return_adjust(expression: &SemanticExpression) -> Option<u16> {
        match expression {
            SemanticExpression::Const { value, .. } => u16::try_from(*value).ok(),
            _ => None,
        }
    }

    fn emit_store(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        expression: &SemanticExpression,
        bits: u16,
    ) -> Result<(), Error> {
        if let Some(()) = self.try_direct_store(space, addr, expression, bits)? {
            return Ok(());
        }
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
        let value = coerce_int_value_width(
            &self.builder,
            value,
            self.int_type(bits),
            "store_zext",
            "store_trunc",
        )?;
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
                if let Some(value) = self.try_direct_load(space, addr, *bits)? {
                    return Ok(value);
                }
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
                if let Some(value) = self.try_lower_i386_div_extract(arg, *lsb, *bits)? {
                    return Ok(value);
                }
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
            SemanticExpression::Architecture { name, args, bits, .. } => {
                let helper = self.declare_value_helper(
                    &format!("binlex_arch_expr_{}", sanitize_symbol(name)),
                    self.int_type(*bits),
                    &[],
                    true,
                );
                let args = self.lower_arg_values(args)?;
                self.call_value(helper, &args, "archexpr")
            }
        }
    }

    fn try_lower_i386_div_extract(
        &mut self,
        arg: &SemanticExpression,
        lsb: u16,
        bits: u16,
    ) -> Result<Option<IntValue<'ctx>>, Error> {
        let is_i386 = matches!(
            self.module.get_triple().as_str().to_str(),
            Ok(triple) if triple.starts_with("i386")
        );
        if !is_i386 || lsb != 0 || bits != 32 {
            return Ok(None);
        }
        let (signed, remainder, dividend, divisor) = match arg {
            SemanticExpression::Binary {
                op,
                left,
                right,
                bits: 64,
            } => match op {
                SemanticOperationBinary::UDiv => (false, false, &**left, &**right),
                SemanticOperationBinary::SDiv => (true, false, &**left, &**right),
                SemanticOperationBinary::URem => (false, true, &**left, &**right),
                SemanticOperationBinary::SRem => (true, true, &**left, &**right),
                _ => return Ok(None),
            },
            _ => return Ok(None),
        };
        let (high, low) = match dividend {
            SemanticExpression::Concat { parts, bits: 64 } if parts.len() == 2 => {
                (&parts[0], &parts[1])
            }
            _ => return Ok(None),
        };
        let divisor = match divisor {
            SemanticExpression::Cast { arg, bits: 64, .. } => &**arg,
            _ => return Ok(None),
        };
        let ty = self.context.i32_type();
        let low_value = self.lower_expression(low)?;
        let low_value = self.lower_cast(SemanticOperationCast::ZeroExtend, low_value, 32)?;
        let high_value = self.lower_expression(high)?;
        let high_value = self.lower_cast(SemanticOperationCast::ZeroExtend, high_value, 32)?;
        let divisor_value = self.lower_expression(divisor)?;
        let divisor_value =
            self.lower_cast(SemanticOperationCast::ZeroExtend, divisor_value, 32)?;
        let low_slot = self.build_entry_alloca(ty, "div_low_slot")?;
        let high_slot = self.build_entry_alloca(ty, "div_high_slot")?;
        let divisor_slot = self.build_entry_alloca(ty, "div_divisor_slot")?;
        let out_slot = self.build_entry_alloca(ty, "div_out_slot")?;
        self.builder
            .build_store(low_slot, low_value)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(high_slot, high_value)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(divisor_slot, divisor_value)
            .map_err(|err| Error::other(err.to_string()))?;
        let fn_ty = self.context.void_type().fn_type(
            &[
                self.context.ptr_type(inkwell::AddressSpace::default()).into(),
                self.context.ptr_type(inkwell::AddressSpace::default()).into(),
                self.context.ptr_type(inkwell::AddressSpace::default()).into(),
                self.context.ptr_type(inkwell::AddressSpace::default()).into(),
            ],
            false,
        );
        let div_mnemonic = if signed { "idivl" } else { "divl" };
        let store_reg = if remainder { "%edx" } else { "%eax" };
        let asm = self.context.create_inline_asm(
            fn_ty,
            format!("movl $0, %eax; movl $1, %edx; {div_mnemonic} $2; movl {store_reg}, $3"),
            "*m,*m,*m,*m,~{eax},~{edx},~{dirflag},~{fpsr},~{flags}".to_string(),
            true,
            false,
            None,
            false,
        );
        let call = self
            .builder
            .build_indirect_call(
                fn_ty,
                asm,
                &[
                    low_slot.into(),
                    high_slot.into(),
                    divisor_slot.into(),
                    out_slot.into(),
                ],
                "",
            )
            .map_err(|err| Error::other(err.to_string()))?;
        for index in 0..4 {
            call.add_attribute(AttributeLoc::Param(index), self.elementtype_attribute(ty));
        }
        Ok(Some(
            self.builder
                .build_load(ty, out_slot, "div_extract")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value(),
        ))
    }

    fn read_location(&mut self, location: &SemanticLocation) -> Result<IntValue<'ctx>, Error> {
        match location {
            SemanticLocation::Memory { space, addr, bits } => {
                if let Some(value) = self.try_direct_load(space, addr, *bits)? {
                    return Ok(value);
                }
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

    fn try_direct_load(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        bits: u16,
    ) -> Result<Option<IntValue<'ctx>>, Error> {
        if !matches!(
            space,
            SemanticAddressSpace::Default | SemanticAddressSpace::Stack
        ) {
            return Ok(None);
        }
        let ptr = self.direct_pointer_from_expression(addr)?;
        let value = self
            .builder
            .build_load(self.int_type(bits), ptr, "direct_loadtmp")
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();
        Ok(Some(value))
    }

    fn try_direct_store(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        expression: &SemanticExpression,
        bits: u16,
    ) -> Result<Option<()>, Error> {
        if !matches!(
            space,
            SemanticAddressSpace::Default | SemanticAddressSpace::Stack
        ) {
            return Ok(None);
        }
        let ptr = self.direct_pointer_from_expression(addr)?;
        let value = self.lower_expression(expression)?;
        let value = coerce_int_value_width(
            &self.builder,
            value,
            self.int_type(bits),
            "direct_store_zext",
            "direct_store_trunc",
        )?;
        self.builder
            .build_store(ptr, value)
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(Some(()))
    }

    fn try_direct_memory_set(
        &mut self,
        space: &SemanticAddressSpace,
        addr: &SemanticExpression,
        value: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<bool, Error> {
        if !matches!(space, SemanticAddressSpace::Default) {
            return Ok(false);
        }

        let pointer_int_type = self.pointer_int_type();
        let lowered_addr = self.lower_expression(addr)?;
        let base_addr = coerce_int_value_width(
            &self.builder,
            lowered_addr,
            pointer_int_type,
            "memset_addr_zext",
            "memset_addr_trunc",
        )?;
        let lowered_count = self.lower_expression(count)?;
        let count = coerce_int_value_width(
            &self.builder,
            lowered_count,
            pointer_int_type,
            "memset_count_zext",
            "memset_count_trunc",
        )?;
        let lowered_decrement = self.lower_expression(decrement)?;
        let decrement = self.to_bool(lowered_decrement);
        let lowered_value = self.lower_expression(value)?;
        let value = coerce_int_value_width(
            &self.builder,
            lowered_value,
            self.int_type(element_bits),
            "memset_value_zext",
            "memset_value_trunc",
        )?;
        self.build_counted_memory_loop(
            "memset",
            base_addr,
            None,
            count,
            element_bits,
            decrement,
            |this, dst_ptr, _| {
                this.builder
                    .build_store(dst_ptr, value)
                    .map_err(|err| Error::other(err.to_string()))?;
                Ok(())
            },
        )?;
        Ok(true)
    }

    fn try_direct_memory_copy(
        &mut self,
        src_space: &SemanticAddressSpace,
        src_addr: &SemanticExpression,
        dst_space: &SemanticAddressSpace,
        dst_addr: &SemanticExpression,
        count: &SemanticExpression,
        element_bits: u16,
        decrement: &SemanticExpression,
    ) -> Result<bool, Error> {
        if !matches!(src_space, SemanticAddressSpace::Default)
            || !matches!(dst_space, SemanticAddressSpace::Default)
        {
            return Ok(false);
        }

        let pointer_int_type = self.pointer_int_type();
        let lowered_src_addr = self.lower_expression(src_addr)?;
        let src_addr = coerce_int_value_width(
            &self.builder,
            lowered_src_addr,
            pointer_int_type,
            "memcpy_src_zext",
            "memcpy_src_trunc",
        )?;
        let lowered_dst_addr = self.lower_expression(dst_addr)?;
        let dst_addr = coerce_int_value_width(
            &self.builder,
            lowered_dst_addr,
            pointer_int_type,
            "memcpy_dst_zext",
            "memcpy_dst_trunc",
        )?;
        let lowered_count = self.lower_expression(count)?;
        let count = coerce_int_value_width(
            &self.builder,
            lowered_count,
            pointer_int_type,
            "memcpy_count_zext",
            "memcpy_count_trunc",
        )?;
        let lowered_decrement = self.lower_expression(decrement)?;
        let decrement = self.to_bool(lowered_decrement);
        self.build_counted_memory_loop(
            "memcpy",
            dst_addr,
            Some(src_addr),
            count,
            element_bits,
            decrement,
            |this, dst_ptr, src_ptr| {
                let src_ptr = src_ptr.expect("memory copy loop requires a source pointer");
                let value = this
                    .builder
                    .build_load(this.int_type(element_bits), src_ptr, "memcpy_load")
                    .map_err(|err| Error::other(err.to_string()))?;
                this.builder
                    .build_store(dst_ptr, value)
                    .map_err(|err| Error::other(err.to_string()))?;
                Ok(())
            },
        )?;
        Ok(true)
    }

    fn build_counted_memory_loop<F>(
        &mut self,
        loop_name: &str,
        dst_base: IntValue<'ctx>,
        src_base: Option<IntValue<'ctx>>,
        count: IntValue<'ctx>,
        element_bits: u16,
        decrement: IntValue<'ctx>,
        mut body: F,
    ) -> Result<(), Error>
    where
        F: FnMut(
            &mut Self,
            PointerValue<'ctx>,
            Option<PointerValue<'ctx>>,
        ) -> Result<(), Error>,
    {
        let pointer_int_type = self.pointer_int_type();
        let element_bytes = pointer_int_type.const_int((element_bits / 8) as u64, false);
        let zero = pointer_int_type.const_zero();
        let one = pointer_int_type.const_int(1, false);

        let current_block = self
            .builder
            .get_insert_block()
            .ok_or_else(|| Error::other("memory loop requires an insertion block"))?;
        let loop_cond = self
            .context
            .append_basic_block(self.function, &format!("{loop_name}_cond"));
        let loop_body = self
            .context
            .append_basic_block(self.function, &format!("{loop_name}_body"));
        let loop_exit = self
            .context
            .append_basic_block(self.function, &format!("{loop_name}_exit"));

        self.builder.position_at_end(current_block);
        let index_slot = self
            .builder
            .build_alloca(pointer_int_type, &format!("{loop_name}_index"))
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(index_slot, zero)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_unconditional_branch(loop_cond)
            .map_err(|err| Error::other(err.to_string()))?;

        self.builder.position_at_end(loop_cond);
        let index = self
            .builder
            .build_load(pointer_int_type, index_slot, &format!("{loop_name}_index_load"))
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();
        let keep_going = self
            .builder
            .build_int_compare(IntPredicate::ULT, index, count, &format!("{loop_name}_keep_going"))
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_conditional_branch(keep_going, loop_body, loop_exit)
            .map_err(|err| Error::other(err.to_string()))?;

        self.builder.position_at_end(loop_body);
        let offset = self
            .builder
            .build_int_mul(index, element_bytes, &format!("{loop_name}_offset"))
            .map_err(|err| Error::other(err.to_string()))?;
        let dst_addr = self.directional_memory_address(
            dst_base,
            offset,
            decrement,
            &format!("{loop_name}_dst"),
        )?;
        let dst_ptr = self
            .builder
            .build_int_to_ptr(
                dst_addr,
                self.context.ptr_type(inkwell::AddressSpace::default()),
                &format!("{loop_name}_dst_ptr"),
            )
            .map_err(|err| Error::other(err.to_string()))?;
        let src_ptr = if let Some(src_base) = src_base {
            let src_addr = self.directional_memory_address(
                src_base,
                offset,
                decrement,
                &format!("{loop_name}_src"),
            )?;
            Some(
                self.builder
                    .build_int_to_ptr(
                        src_addr,
                        self.context.ptr_type(inkwell::AddressSpace::default()),
                        &format!("{loop_name}_src_ptr"),
                    )
                    .map_err(|err| Error::other(err.to_string()))?,
            )
        } else {
            None
        };
        body(self, dst_ptr, src_ptr)?;
        let next_index = self
            .builder
            .build_int_add(index, one, &format!("{loop_name}_next_index"))
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(index_slot, next_index)
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_unconditional_branch(loop_cond)
            .map_err(|err| Error::other(err.to_string()))?;

        self.builder.position_at_end(loop_exit);
        Ok(())
    }

    fn directional_memory_address(
        &self,
        base: IntValue<'ctx>,
        offset: IntValue<'ctx>,
        decrement: IntValue<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>, Error> {
        let forward = self
            .builder
            .build_int_add(base, offset, &format!("{name}_forward"))
            .map_err(|err| Error::other(err.to_string()))?;
        let backward = self
            .builder
            .build_int_sub(base, offset, &format!("{name}_backward"))
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_select(decrement, backward, forward, &format!("{name}_select"))
            .map_err(|err| Error::other(err.to_string()))
            .map(|value| value.into_int_value())
    }

    fn direct_pointer_from_expression(
        &mut self,
        expression: &SemanticExpression,
    ) -> Result<PointerValue<'ctx>, Error> {
        let address = self.lower_expression(expression)?;
        let pointer_int_type = self.pointer_int_type();
        let address = coerce_int_value_width(
            &self.builder,
            address,
            pointer_int_type,
            "direct_ptr_zext",
            "direct_ptr_trunc",
        )?;
        self.builder
            .build_int_to_ptr(
                address,
                self.context.ptr_type(inkwell::AddressSpace::default()),
                "direct_ptr",
            )
            .map_err(|err| Error::other(err.to_string()))
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
            SemanticOperationUnary::ByteSwap => {
                let name = format!("llvm.bswap.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits)
                            .fn_type(&[self.int_type(bits).into()], false),
                        None,
                    )
                });
                self.call_value(function, &[arg.into()], "bswaptmp")
            }
            SemanticOperationUnary::CountLeadingZeros => {
                let name = format!("llvm.ctlz.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[self.int_type(bits).into(), self.context.bool_type().into()],
                            false,
                        ),
                        None,
                    )
                });
                self.call_value(
                    function,
                    &[arg.into(), self.context.bool_type().const_zero().into()],
                    "ctlztmp",
                )
            }
            SemanticOperationUnary::CountTrailingZeros => {
                let name = format!("llvm.cttz.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[self.int_type(bits).into(), self.context.bool_type().into()],
                            false,
                        ),
                        None,
                    )
                });
                self.call_value(
                    function,
                    &[arg.into(), self.context.bool_type().const_zero().into()],
                    "cttztmp",
                )
            }
            SemanticOperationUnary::PopCount => {
                let name = format!("llvm.ctpop.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits)
                            .fn_type(&[self.int_type(bits).into()], false),
                        None,
                    )
                });
                self.call_value(function, &[arg.into()], "ctpoptmp")
            }
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
                .build_left_shift(
                    left,
                    coerce_int_value_width(
                        &self.builder,
                        right,
                        left.get_type(),
                        "shift_zext",
                        "shift_trunc",
                    )?,
                    "shltmp",
                )
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::LShr => self
                .builder
                .build_right_shift(
                    left,
                    coerce_int_value_width(
                        &self.builder,
                        right,
                        left.get_type(),
                        "shift_zext",
                        "shift_trunc",
                    )?,
                    false,
                    "lshrtmp",
                )
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::AShr => self
                .builder
                .build_right_shift(
                    left,
                    coerce_int_value_width(
                        &self.builder,
                        right,
                        left.get_type(),
                        "shift_zext",
                        "shift_trunc",
                    )?,
                    true,
                    "ashrtmp",
                )
                .map_err(|err| Error::other(err.to_string())),
            SemanticOperationBinary::RotateLeft => {
                let name = format!("llvm.fshl.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                            ],
                            false,
                        ),
                        None,
                    )
                });
                let right = coerce_int_value_width(
                    &self.builder,
                    right,
                    left.get_type(),
                    "rotate_zext",
                    "rotate_trunc",
                )?;
                self.call_value(function, &[left.into(), left.into(), right.into()], "roltmp")
            }
            SemanticOperationBinary::RotateRight => {
                let name = format!("llvm.fshr.i{}", bits);
                let function = self.module.get_function(&name).unwrap_or_else(|| {
                    self.module.add_function(
                        &name,
                        self.int_type(bits).fn_type(
                            &[
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                                self.int_type(bits).into(),
                            ],
                            false,
                        ),
                        None,
                    )
                });
                let right = coerce_int_value_width(
                    &self.builder,
                    right,
                    left.get_type(),
                    "rotate_zext",
                    "rotate_trunc",
                )?;
                self.call_value(function, &[left.into(), left.into(), right.into()], "rortmp")
            }
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
        if let Some((parent_name, parent_bits, _)) = self.x86_parent_register_alias(location) {
            let parent = SemanticLocation::Register {
                name: parent_name,
                bits: parent_bits,
            };
            let parent_key = render_location(&parent);
            if !self.slots.contains_key(&parent_key) {
                let _ = self.slot_for_location(&parent)?;
            }
        }
        let ty = self.location_type(location);
        let slot = self.build_entry_alloca(ty, &sanitize_symbol(&key))?;
        let initial = self.initial_location_value(location)?;
        self.builder
            .build_store(slot, initial)
            .map_err(|err| Error::other(err.to_string()))?;
        self.slots.insert(key, slot);
        self.slot_locations
            .insert(render_location(location), location.clone());
        Ok(slot)
    }

    fn merge_partial_register_write(
        &mut self,
        name: &str,
        bits: u16,
        value: IntValue<'ctx>,
    ) -> Result<(), Error> {
        let location = SemanticLocation::Register {
            name: name.to_string(),
            bits,
        };
        let Some((parent_name, parent_bits, shift)) = self.x86_parent_register_alias(&location)
        else {
            return Ok(());
        };
        let parent = SemanticLocation::Register {
            name: parent_name,
            bits: parent_bits,
        };
        let parent_slot = self.slot_for_location(&parent)?;
        let parent_key = render_location(&parent);
        let parent_value = self
            .builder
            .build_load(self.int_type(parent_bits), parent_slot, "partial_parent")
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();
        let parent_type = self.int_type(parent_bits);
        let value = coerce_int_value_width(
            &self.builder,
            value,
            parent_type,
            "partial_merge_zext",
            "partial_merge_trunc",
        )?;
        let shifted = if shift == 0 {
            value
        } else {
            self.builder
                .build_left_shift(
                    value,
                    parent_type.const_int(shift as u64, false),
                    "partial_shift",
                )
                .map_err(|err| Error::other(err.to_string()))?
        };
        let bit_mask = if bits == 64 {
            u64::MAX
        } else {
            ((1u64 << bits) - 1) << shift
        };
        let cleared = self
            .builder
            .build_and(
                parent_value,
                parent_type.const_int(!bit_mask, false),
                "partial_cleared",
            )
            .map_err(|err| Error::other(err.to_string()))?;
        let merged = self
            .builder
            .build_or(cleared, shifted, "partial_merged")
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(parent_slot, merged)
            .map_err(|err| Error::other(err.to_string()))?;
        self.written_locations.insert(parent_key);
        Ok(())
    }

    fn initial_location_value(
        &self,
        location: &SemanticLocation,
    ) -> Result<IntValue<'ctx>, Error> {
        match location {
            SemanticLocation::Register { name, bits } => {
                self.read_native_register(name, *bits).or_else(|_| Ok(self.int_type(*bits).const_zero()))
            }
            SemanticLocation::Flag { name, bits } => self
                .read_native_flag(name, *bits)
                .or_else(|_| Ok(self.int_type(*bits).const_zero())),
            _ => Ok(self.location_type(location).const_zero()),
        }
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

    fn elementtype_attribute(&self, ty: IntType<'ctx>) -> inkwell::attributes::Attribute {
        let kind_id = inkwell::attributes::Attribute::get_named_enum_kind_id("elementtype");
        self.context.create_type_attribute(kind_id, ty.as_any_type_enum())
    }

    fn emit_body_marker(&self, suffix: &str) -> Result<(), Error> {
        let symbol = sanitize_symbol(&format!("{}__{}", self.function_name, suffix));
        let fn_ty = self.context.void_type().fn_type(&[], false);
        let asm = self.context.create_inline_asm(
            fn_ty,
            format!(".globl {symbol}\n{symbol}:\nnop"),
            "~{memory},~{dirflag},~{fpsr},~{flags}".to_string(),
            true,
            false,
            None,
            false,
        );
        self.builder
            .build_indirect_call(fn_ty, asm, &[], "")
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(())
    }

    fn emit_native_return(&self, adjust: u16) -> Result<(), Error> {
        if adjust == 0 {
            self.builder
                .build_return(None)
                .map_err(|err| Error::other(err.to_string()))?;
            return Ok(());
        }
        let fn_ty = self.context.void_type().fn_type(&[], false);
        let asm = self.context.create_inline_asm(
            fn_ty,
            format!("ret $${adjust}"),
            "".to_string(),
            true,
            false,
            None,
            false,
        );
        self.builder
            .build_indirect_call(fn_ty, asm, &[], "")
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_unreachable()
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(())
    }

    fn read_native_register(&self, name: &str, bits: u16) -> Result<IntValue<'ctx>, Error> {
        if let Some(value) = self.read_native_frame_anchored_register(name, bits)? {
            return Ok(value);
        }
        let Some(register) = self.x86_register_asm_name(name, bits) else {
            return Err(Error::other(format!(
                "unsupported native register read: {name}/{bits}"
            )));
        };
        let ty = self.int_type(bits);
        if bits == 128 && register.starts_with("xmm") {
            let slot = self.build_entry_alloca(ty, "regread_xmm_slot")?;
            let fn_ty = self.context.void_type().fn_type(
                &[self.context.ptr_type(inkwell::AddressSpace::default()).into()],
                false,
            );
            let asm = self.context.create_inline_asm(
                fn_ty,
                format!("movdqu %{register}, $0"),
                format!("=*m,~{{{register}}}"),
                true,
                false,
                None,
                false,
            );
            let call = self
                .builder
                .build_indirect_call(fn_ty, asm, &[slot.into()], "regread")
                .map_err(|err| Error::other(err.to_string()))?;
            call.add_attribute(AttributeLoc::Param(0), self.elementtype_attribute(ty));
            return self
                .builder
                .build_load(ty, slot, "regread_xmm_value")
                .map_err(|err| Error::other(err.to_string()))
                .map(|value| value.into_int_value());
        }
        let fn_ty = ty.fn_type(&[], false);
        let asm = self.context.create_inline_asm(
            fn_ty,
            format!("mov{} %{}, $0", self.asm_width_suffix(bits), register),
            format!("=r,~{{{register}}}"),
            true,
            false,
            None,
            false,
        );
        self.builder
            .build_indirect_call(fn_ty, asm, &[], "regread")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected value result from register read"))
            .map(|value| value.into_int_value())
    }

    fn read_native_frame_anchored_register(
        &self,
        name: &str,
        bits: u16,
    ) -> Result<Option<IntValue<'ctx>>, Error> {
        let triple_is_64 = matches!(
            self.module.get_triple().as_str().to_str(),
            Ok(triple) if triple.starts_with("x86_64")
        );

        let frame_register = match (triple_is_64, name) {
            (false, "esp" | "sp" | "ebp" | "bp") => Some(("ebp", 32u16)),
            (true, "rsp" | "sp" | "rbp" | "bp") => Some(("rbp", 64u16)),
            _ => None,
        };
        let Some((frame_register, frame_bits)) = frame_register else {
            return Ok(None);
        };

        let frame_value = {
            let ty = self.int_type(frame_bits);
            let fn_ty = ty.fn_type(&[], false);
            let asm = self.context.create_inline_asm(
                fn_ty,
                format!("mov{} %{}, $0", self.asm_width_suffix(frame_bits), frame_register),
                format!("=r,~{{{frame_register}}}"),
                true,
                false,
                None,
                false,
            );
            self.builder
                .build_indirect_call(fn_ty, asm, &[], "frameread")
                .map_err(|err| Error::other(err.to_string()))?
                .try_as_basic_value()
                .basic()
                .ok_or_else(|| Error::other("expected value result from frame register read"))?
                .into_int_value()
        };

        let native_bits = if triple_is_64 { 64u16 } else { 32u16 };
        let native_ty = self.int_type(native_bits);
        let frame_value = coerce_int_value_width(
            &self.builder,
            frame_value,
            native_ty,
            "frame_zext",
            "frame_trunc",
        )?;

        let saved_frame_value = {
            let ptr = self
                .builder
                .build_int_to_ptr(
                    frame_value,
                    self.context.ptr_type(inkwell::AddressSpace::default()),
                    "recover_bp_ptr",
                )
                .map_err(|err| Error::other(err.to_string()))?;
            self.builder
                .build_load(native_ty, ptr, "recover_bp_saved")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value()
        };
        let uses_saved_frame = self
            .builder
            .build_int_compare(
                IntPredicate::UGT,
                saved_frame_value,
                frame_value,
                "recover_bp_uses_saved",
            )
            .map_err(|err| Error::other(err.to_string()))?;
        let original_frame_value = self
            .builder
            .build_select(
                uses_saved_frame,
                saved_frame_value,
                frame_value,
                "recover_bp_original",
            )
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();

        let stack_bias = native_ty.const_int((native_bits / 8) as u64, false);
        let recovered = match (triple_is_64, name) {
            (false, "esp" | "sp") | (true, "rsp" | "sp") => self
                .builder
                .build_int_add(frame_value, stack_bias, "recover_sp_original")
                .map_err(|err| Error::other(err.to_string()))?,
            (false, "ebp" | "bp") | (true, "rbp" | "bp") => original_frame_value,
            _ => return Ok(None),
        };

        let result_ty = self.int_type(bits);
        let result = coerce_int_value_width(
            &self.builder,
            recovered,
            result_ty,
            "frame_reg_zext",
            "frame_reg_trunc",
        )?;
        Ok(Some(result))
    }

    fn read_native_flags_register(&self) -> Result<IntValue<'ctx>, Error> {
        let is_64 = matches!(self.module.get_triple().as_str().to_str(), Ok(triple) if triple.starts_with("x86_64"));
        let ty = if is_64 {
            self.context.i64_type()
        } else {
            self.context.i32_type()
        };
        let slot = self.build_entry_alloca(ty, "flagsread_slot")?;
        let fn_ty = self.context.void_type().fn_type(
            &[self.context.ptr_type(inkwell::AddressSpace::default()).into()],
            false,
        );
        let asm = self.context.create_inline_asm(
            fn_ty,
            if is_64 {
                "pushfq; popq $0".to_string()
            } else {
                "pushfd; popl $0".to_string()
            },
            "=*m,~{dirflag},~{fpsr},~{flags}".to_string(),
            true,
            false,
            None,
            false,
        );
        let call = self
            .builder
            .build_indirect_call(fn_ty, asm, &[slot.into()], "flagsread")
            .map_err(|err| Error::other(err.to_string()))?;
        call.add_attribute(AttributeLoc::Param(0), self.elementtype_attribute(ty));
        self.builder
            .build_load(ty, slot, "flagsread_value")
            .map_err(|err| Error::other(err.to_string()))
            .map(|value| value.into_int_value())
    }

    fn read_native_flag(&self, name: &str, bits: u16) -> Result<IntValue<'ctx>, Error> {
        let bit = match name {
            "cf" => 0,
            "pf" => 2,
            "af" => 4,
            "zf" => 6,
            "sf" => 7,
            "if" => 9,
            "df" => 10,
            "of" => 11,
            _ => return Err(Error::other(format!("unsupported native flag read: {name}"))),
        };
        let flags = if let Some(flags) = *self.cached_flags_register.borrow() {
            flags
        } else {
            let flags = self.read_native_flags_register()?;
            *self.cached_flags_register.borrow_mut() = Some(flags);
            flags
        };
        let shifted = self
            .builder
            .build_right_shift(
                flags,
                flags.get_type().const_int(bit, false),
                false,
                "flagread_shift",
            )
            .map_err(|err| Error::other(err.to_string()))?;
        let truncated = self
            .builder
            .build_int_truncate(shifted, self.int_type(bits), "flagread_trunc")
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(truncated)
    }

    fn write_native_register(
        &self,
        register: &str,
        bits: u16,
        value: IntValue<'ctx>,
    ) -> Result<(), Error> {
        let ty = self.int_type(bits);
        let value = coerce_int_value_width(
            &self.builder,
            value,
            ty,
            "regwrite_zext",
            "regwrite_trunc",
        )?;
        if bits == 128 && register.starts_with("xmm") {
            let slot = self.build_entry_alloca(ty, "regwrite_xmm_slot")?;
            self.builder
                .build_store(slot, value)
                .map_err(|err| Error::other(err.to_string()))?;
            let fn_ty = self.context.void_type().fn_type(
                &[self.context.ptr_type(inkwell::AddressSpace::default()).into()],
                false,
            );
            let asm = self.context.create_inline_asm(
                fn_ty,
                format!("movdqu $0, %{register}"),
                format!("*m,~{{{register}}}"),
                true,
                false,
                None,
                false,
            );
            let call = self
                .builder
                .build_indirect_call(fn_ty, asm, &[slot.into()], "")
                .map_err(|err| Error::other(err.to_string()))?;
            call.add_attribute(AttributeLoc::Param(0), self.elementtype_attribute(ty));
            return Ok(());
        }
        if matches!(register, "ebp" | "rbp" | "bp") {
            let fn_ty = self.context.void_type().fn_type(&[ty.into()], false);
            let asm = self.context.create_inline_asm(
                fn_ty,
                format!("mov{} $0, %{}", self.asm_width_suffix(bits), register),
                "r".to_string(),
                true,
                false,
                None,
                false,
            );
            self.builder
                .build_indirect_call(fn_ty, asm, &[value.into()], "")
                .map_err(|err| Error::other(err.to_string()))?;
            return Ok(());
        }
        if matches!(register, "esp" | "rsp" | "sp") {
            let slot = self.build_entry_alloca(ty, "regwrite_stack_slot")?;
            self.builder
                .build_store(slot, value)
                .map_err(|err| Error::other(err.to_string()))?;
            let fn_ty = self
                .context
                .void_type()
                .fn_type(&[self.context.ptr_type(inkwell::AddressSpace::default()).into()], false);
            let asm = self.context.create_inline_asm(
                fn_ty,
                format!("mov{} $0, %{}", self.asm_width_suffix(bits), register),
                format!("*m,~{{{register}}}"),
                true,
                false,
                None,
                false,
            );
            let call = self
                .builder
                .build_indirect_call(fn_ty, asm, &[slot.into()], "")
                .map_err(|err| Error::other(err.to_string()))?;
            call.add_attribute(AttributeLoc::Param(0), self.elementtype_attribute(ty));
            return Ok(());
        }
        let fn_ty = self
            .context
            .void_type()
            .fn_type(&[ty.into()], false);
        let asm = self.context.create_inline_asm(
            fn_ty,
            format!("mov{} $0, %{}", self.asm_width_suffix(bits), register),
            format!("r,~{{{register}}}"),
            true,
            false,
            None,
            false,
        );
        self.builder
            .build_indirect_call(fn_ty, asm, &[value.into()], "")
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(())
    }

    fn write_native_flags_register(&self, value: IntValue<'ctx>) -> Result<(), Error> {
        let is_64 = matches!(self.module.get_triple().as_str().to_str(), Ok(triple) if triple.starts_with("x86_64"));
        let bits = if is_64 { 64u16 } else { 32u16 };
        let ty = self.int_type(bits);
        let value = coerce_int_value_width(
            &self.builder,
            value,
            ty,
            "flagswrite_zext",
            "flagswrite_trunc",
        )?;
        let slot = self.build_entry_alloca(ty, "flagswrite_slot")?;
        self.builder
            .build_store(slot, value)
            .map_err(|err| Error::other(err.to_string()))?;
        let fn_ty = self
            .context
            .void_type()
            .fn_type(&[self.context.ptr_type(inkwell::AddressSpace::default()).into()], false);
        let asm = self.context.create_inline_asm(
            fn_ty,
            if is_64 {
                "pushq $0; popfq".to_string()
            } else {
                "pushl $0; popfd".to_string()
            },
            "*m,~{dirflag},~{fpsr},~{flags}".to_string(),
            true,
            false,
            None,
            false,
        );
        let call = self
            .builder
            .build_indirect_call(fn_ty, asm, &[slot.into()], "")
            .map_err(|err| Error::other(err.to_string()))?;
        call.add_attribute(AttributeLoc::Param(0), self.elementtype_attribute(ty));
        Ok(())
    }

    fn sync_slots_to_architecture(&self) -> Result<(), Error> {
        let mut flags_value = self.context.i32_type().const_int(1 << 1, false);
        let mut has_flags = false;
        for (flag, bit) in [
            ("cf", 0u64),
            ("pf", 2),
            ("af", 4),
            ("zf", 6),
            ("sf", 7),
            ("if", 9),
            ("df", 10),
            ("of", 11),
        ] {
            let key = render_location(&SemanticLocation::Flag {
                name: flag.to_string(),
                bits: 1,
            });
            let Some(slot) = self.slots.get(&key) else {
                continue;
            };
            has_flags = true;
            let bit_value = self
                .builder
                .build_load(self.context.bool_type(), *slot, "sync_flag")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value();
            let bit_value = self
                .builder
                .build_int_z_extend(bit_value, self.context.i32_type(), "sync_flag_zext")
                .map_err(|err| Error::other(err.to_string()))?;
            let shifted = self
                .builder
                .build_left_shift(
                    bit_value,
                    self.context.i32_type().const_int(bit, false),
                    "sync_flag_shift",
                )
                .map_err(|err| Error::other(err.to_string()))?;
            flags_value = self
                .builder
                .build_or(flags_value, shifted, "sync_flag_or")
                .map_err(|err| Error::other(err.to_string()))?;
        }

        let mut register_writes = Vec::new();
        for (key, slot) in &self.slots {
            if !self.written_locations.contains(key) {
                continue;
            }
            let Some(SemanticLocation::Register { name, bits }) = self.slot_locations.get(key) else {
                continue;
            };
            if self
                .x86_parent_register_alias(&SemanticLocation::Register {
                    name: name.clone(),
                    bits: *bits,
                })
                .is_some()
            {
                continue;
            }
            let Some(register) = self.x86_register_asm_name(name, *bits) else {
                continue;
            };
            register_writes.push((name.clone(), *bits, register, *slot));
        }
        register_writes.sort_by_key(|(name, _, _, _)| {
            if matches!(name.as_str(), "esp" | "rsp" | "sp") {
                0u8
            } else {
                1u8
            }
        });
        if has_flags
            && [
                "cf", "pf", "af", "zf", "sf", "if", "df", "of",
            ]
            .iter()
            .any(|flag| {
                self.written_locations.contains(&render_location(&SemanticLocation::Flag {
                    name: (*flag).to_string(),
                    bits: 1,
                }))
            })
        {
            self.write_native_flags_register(flags_value)?;
        }
        for (_, bits, register, slot) in register_writes {
            let value = self
                .builder
                .build_load(self.int_type(bits), slot, "sync_reg")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value();
            self.write_native_register(register, bits, value)?;
        }
        Ok(())
    }

    fn asm_width_suffix(&self, bits: u16) -> &'static str {
        match bits {
            8 => "b",
            16 => "w",
            32 => "l",
            64 => "q",
            _ => "q",
        }
    }

    fn x86_register_asm_name(&self, name: &str, bits: u16) -> Option<&'static str> {
        match bits {
            8 if name == "al" => Some("al"),
            8 if name == "ah" => Some("ah"),
            8 if name == "bl" => Some("bl"),
            8 if name == "bh" => Some("bh"),
            8 if name == "cl" => Some("cl"),
            8 if name == "ch" => Some("ch"),
            8 if name == "dl" => Some("dl"),
            8 if name == "dh" => Some("dh"),
            16 if name == "ax" => Some("ax"),
            16 if name == "bx" => Some("bx"),
            16 if name == "cx" => Some("cx"),
            16 if name == "dx" => Some("dx"),
            16 if name == "si" => Some("si"),
            16 if name == "di" => Some("di"),
            16 if name == "sp" => Some("sp"),
            16 if name == "bp" => Some("bp"),
            32 if name == "eax" => Some("eax"),
            32 if name == "ebx" => Some("ebx"),
            32 if name == "ecx" => Some("ecx"),
            32 if name == "edx" => Some("edx"),
            32 if name == "esi" => Some("esi"),
            32 if name == "edi" => Some("edi"),
            32 if name == "esp" => Some("esp"),
            32 if name == "ebp" => Some("ebp"),
            64 if name == "rax" => Some("rax"),
            64 if name == "rbx" => Some("rbx"),
            64 if name == "rcx" => Some("rcx"),
            64 if name == "rdx" => Some("rdx"),
            64 if name == "rsi" => Some("rsi"),
            64 if name == "rdi" => Some("rdi"),
            64 if name == "rsp" => Some("rsp"),
            64 if name == "rbp" => Some("rbp"),
            128 if name == "xmm0" => Some("xmm0"),
            128 if name == "xmm1" => Some("xmm1"),
            128 if name == "xmm2" => Some("xmm2"),
            _ => None,
        }
    }

    fn x86_parent_register_alias(
        &self,
        location: &SemanticLocation,
    ) -> Option<(String, u16, u16)> {
        let SemanticLocation::Register { name, bits } = location else {
            return None;
        };
        match *bits {
            8 if name == "al" => Some(("eax".to_string(), 32, 0)),
            8 if name == "ah" => Some(("eax".to_string(), 32, 8)),
            16 if name == "ax" => Some(("eax".to_string(), 32, 0)),
            8 if name == "bl" => Some(("ebx".to_string(), 32, 0)),
            8 if name == "bh" => Some(("ebx".to_string(), 32, 8)),
            16 if name == "bx" => Some(("ebx".to_string(), 32, 0)),
            8 if name == "cl" => Some(("ecx".to_string(), 32, 0)),
            8 if name == "ch" => Some(("ecx".to_string(), 32, 8)),
            16 if name == "cx" => Some(("ecx".to_string(), 32, 0)),
            8 if name == "dl" => Some(("edx".to_string(), 32, 0)),
            8 if name == "dh" => Some(("edx".to_string(), 32, 8)),
            16 if name == "dx" => Some(("edx".to_string(), 32, 0)),
            _ => None,
        }
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
        let args_suffix = args
            .iter()
            .map(|arg| match arg {
                BasicMetadataTypeEnum::IntType(ty) => format!("i{}", ty.get_bit_width()),
                _ => "x".to_string(),
            })
            .collect::<Vec<_>>()
            .join("_");
        let name = sanitize_symbol(&format!(
            "{}__ret_i{}__args_{}",
            name,
            return_type.get_bit_width(),
            args_suffix
        ));
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

    fn pointer_int_type(&self) -> IntType<'ctx> {
        match self.module.get_triple().as_str().to_str() {
            Ok(triple) if triple.starts_with("x86_64") => self.context.i64_type(),
            _ => self.context.i32_type(),
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

fn push_unique_location(locations: &mut Vec<SemanticLocation>, location: SemanticLocation) {
    if !locations.iter().any(|existing| existing == &location) {
        locations.push(location);
    }
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
        SemanticAddressSpace::State => "state".to_string(),
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
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
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
        if line.trim_start()
            == "exit:                                             ; No predecessors!"
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
