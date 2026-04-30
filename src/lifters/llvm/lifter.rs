use crate::Abi;
use crate::Architecture;
use crate::Config;
use crate::controlflow::{Block, Function, Instruction};
use crate::io::Stderr;
use self::helpers::push_unique_location;
use crate::lifters::llvm::optimizers::Optimizers;
use crate::lifters::llvm::prepare::prepare_instruction_semantics;
use crate::lifters::llvm::verify::verify_module;
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticTerminator,
};
use inkwell::OptimizationLevel;
use inkwell::attributes::AttributeLoc;
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
use inkwell::values::{FunctionValue, IntValue, PointerValue};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::CStr;
use std::ffi::c_void;
use std::io::Error;

mod encoding;
mod effects;
mod expr;
mod helpers;
mod memory;
mod native;
mod returns;
mod state;
mod support;
mod syscalls;

pub struct Lifter {
    config: Config,
    context: &'static Context,
    module: Module<'static>,
    emitted: BTreeSet<String>,
    architecture: Architecture,
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
    architecture: Architecture,
    debug: bool,
    builder: Builder<'ctx>,
    function: FunctionValue<'ctx>,
    function_name: String,
    current_instruction_address: Option<u64>,
    lowering_summary: BTreeMap<(String, String), LoweringSummaryEntry>,
    slots: HashMap<String, PointerValue<'ctx>>,
    slot_locations: HashMap<String, SemanticLocation>,
    written_locations: BTreeSet<String>,
    native_return_adjust: Option<u16>,
    body_begin_emitted: bool,
    cached_flags_register: RefCell<Option<IntValue<'ctx>>>,
    emit_terminator_helpers: bool,
    abi: Option<Abi>,
    current_semantics_abi: Option<Abi>,
}

#[derive(Default)]
struct LoweringSummaryEntry {
    count: usize,
    sample_addresses: Vec<u64>,
}

impl Lifter {
    pub fn new(architecture: Architecture, config: Config) -> Self {
        let context: &'static Context = Box::leak(Box::new(Context::create()));
        let module = context.create_module(&config.lifters.llvm.module_name);
        let lifter = Self {
            config,
            context,
            module,
            emitted: BTreeSet::new(),
            architecture,
        };
        let _ = lifter.bind_architecture();
        lifter
    }

    pub fn lift_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        if self.architecture != instruction.architecture {
            return Err(Error::other(format!(
                "llvm lift instruction architecture mismatch: lifter={} instruction={}",
                self.architecture.to_string(),
                instruction.architecture.to_string()
            )));
        }
        self.bind_architecture()?;
        let name = format!("instruction_{:x}", instruction.address);
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let function = self.add_void_function(&name);
        let mut lowering = self.lowering_context(function, None);
        lowering.lower_instruction(instruction)?;
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_block(&mut self, block: &Block<'_>) -> Result<(), Error> {
        if self.architecture != block.architecture() {
            return Err(Error::other(format!(
                "llvm lift block architecture mismatch: lifter={} block={}",
                self.architecture.to_string(),
                block.architecture().to_string()
            )));
        }
        self.bind_architecture()?;
        let name = format!("block_{:x}", block.address());
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let function = self.add_void_function(&name);
        let mut lowering = self.lowering_context(function, None);
        for instruction in block.instructions() {
            lowering.lower_instruction(&instruction)?;
        }
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_function(&mut self, function: &Function<'_>) -> Result<(), Error> {
        if self.architecture != function.architecture() {
            return Err(Error::other(format!(
                "llvm lift function architecture mismatch: lifter={} function={}",
                self.architecture.to_string(),
                function.architecture().to_string()
            )));
        }
        self.bind_architecture()?;
        let name = format!("function_{:x}", function.address());
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let abi = self.resolve_function_abi(function);
        let llvm_function = self.add_function_for_lift(&name, abi);
        let mut lowering = self.lowering_context(llvm_function, abi);
        lowering.emit_terminator_helpers = false;
        lowering.lower_function(function)?;
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_semantics(&mut self, semantics: &InstructionSemantics) -> Result<(), Error> {
        self.bind_architecture()?;
        let name = format!("semantics_{}", self.emitted.len());
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let function = self.add_function_for_lift(&name, semantics.abi);
        let mut lowering = self.lowering_context(function, semantics.abi);
        lowering.lower_instruction_semantics(semantics)?;
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
        let codegen = self
            .mem2reg()
            .unwrap_or_else(|_| self.duplicate().expect("duplicate lifter"));
        let machine = codegen.target_machine()?;
        let buffer = machine
            .write_to_memory_buffer(&codegen.module, inkwell::targets::FileType::Object)
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(buffer.as_slice().to_vec())
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

    fn resolve_function_abi(&self, function: &Function<'_>) -> Option<Abi> {
        let abi = function
            .reconstruction_instructions()
            .into_iter()
            .find(|instruction| instruction.address == function.address())
            .or_else(|| function.reconstruction_instructions().into_iter().next())?
            .semantics
            .as_ref()?
            .abi?;
        if abi.supports(self.architecture) {
            Some(abi)
        } else {
            Stderr::print_debug(
                &self.config,
                format!(
                    "semantics abi={} unsupported for architecture={}",
                    abi, self.architecture
                ),
            );
            None
        }
    }

    fn add_void_function(&self, name: &str) -> FunctionValue<'static> {
        if let Some(function) = self.module.get_function(name) {
            return function;
        }
        let fn_type = self.context.void_type().fn_type(&[], false);
        let function = self.module.add_function(name, fn_type, None);
        function.add_attribute(
            AttributeLoc::Function,
            self.context
                .create_string_attribute("frame-pointer", "none"),
        );
        function
    }

    fn add_function_for_lift(&self, name: &str, abi: Option<Abi>) -> FunctionValue<'static> {
        if let Some(function) = self.module.get_function(name) {
            return function;
        }
        let fn_type = match (self.architecture, abi) {
            (Architecture::ARM64, Some(Abi::SysV)) => self.context.i64_type().fn_type(&[], false),
            (Architecture::AMD64, Some(Abi::Windows64)) => {
                self.context.i64_type().fn_type(&[], false)
            }
            _ => self.context.void_type().fn_type(&[], false),
        };
        let function = self.module.add_function(name, fn_type, None);
        function.add_attribute(
            AttributeLoc::Function,
            self.context
                .create_string_attribute("frame-pointer", "none"),
        );
        function
    }

    fn lowering_context(
        &self,
        function: FunctionValue<'static>,
        abi: Option<Abi>,
    ) -> LoweringContext<'static, '_> {
        let builder = self.context.create_builder();
        let entry = self.context.append_basic_block(function, "entry");
        builder.position_at_end(entry);
        LoweringContext {
            context: self.context,
            module: &self.module,
            architecture: self.architecture,
            debug: self.config.debug,
            builder,
            function,
            function_name: function.get_name().to_string_lossy().into_owned(),
            current_instruction_address: None,
            lowering_summary: BTreeMap::new(),
            slots: HashMap::new(),
            slot_locations: HashMap::new(),
            written_locations: BTreeSet::new(),
            native_return_adjust: None,
            body_begin_emitted: false,
            cached_flags_register: RefCell::new(None),
            emit_terminator_helpers: true,
            abi,
            current_semantics_abi: None,
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
        Target::initialize_all(&InitializationConfig::default());
        let triple_string = match self.architecture {
            Architecture::I386 => "i386-unknown-unknown",
            Architecture::AMD64 => "x86_64-unknown-unknown",
            Architecture::ARM64 => "aarch64-unknown-unknown",
            _ => "x86_64-unknown-unknown",
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
        let triple_string = match self.architecture {
            Architecture::I386 => "i386-unknown-unknown",
            Architecture::AMD64 => "x86_64-unknown-unknown",
            Architecture::ARM64 => "aarch64-unknown-unknown",
            _ => "x86_64-unknown-unknown",
        };
        self.module
            .set_triple(&inkwell::targets::TargetTriple::create(triple_string));
        if let Ok(machine) = self.target_machine() {
            let data_layout = machine.get_target_data().get_data_layout();
            self.module.set_data_layout(&data_layout);
        }
        Ok(())
    }
}

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    fn record_semantic_lowering(&mut self, kind: &str, detail: impl Into<String>) {
        if !self.debug {
            return;
        }
        let detail = detail.into();
        let entry = self
            .lowering_summary
            .entry((kind.to_string(), detail))
            .or_default();
        entry.count += 1;
        if let Some(address) = self.current_instruction_address {
            if !entry.sample_addresses.contains(&address) && entry.sample_addresses.len() < 5 {
                entry.sample_addresses.push(address);
            }
        }
    }

    fn emit_lowering_summary(&self) {
        if !self.debug || self.lowering_summary.is_empty() {
            return;
        }
        for ((kind, detail), entry) in self
            .lowering_summary
            .iter()
            .filter(|((kind, _), _)| kind != "terminator_helper")
        {
            let addresses = if entry.sample_addresses.is_empty() {
                "[]".to_string()
            } else {
                format!(
                    "[{}]",
                    entry
                        .sample_addresses
                        .iter()
                        .map(|address| format!("0x{address:x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            Stderr::print(format!(
                "llvm semantic summary function={} kind={} count={} sample_addresses={} detail={}",
                self.function_name, kind, entry.count, addresses, detail
            ));
        }
    }

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

    fn finish(&mut self) -> Result<(), Error> {
        let needs_return = self
            .builder
            .get_insert_block()
            .and_then(|block| block.get_terminator())
            .is_none();
        if needs_return {
            self.sync_slots_to_architecture()?;
            self.emit_body_marker("body_end")?;
            if self.emit_abi_return()? {
            } else if let Some(adjust) = self.native_return_adjust {
                self.emit_native_return(adjust)?;
            } else {
                self.emit_default_return()?;
            }
        }
        self.emit_lowering_summary();
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
                let target = self.ensure_exit_block(exit_block);
                self.builder
                    .build_unconditional_branch(target)
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

    fn ensure_exit_block(&self, exit_block: &mut Option<BasicBlock<'ctx>>) -> BasicBlock<'ctx> {
        if let Some(block) = *exit_block {
            block
        } else {
            let block = self.context.append_basic_block(self.function, "exit");
            *exit_block = Some(block);
            block
        }
    }

    fn lower_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        self.current_instruction_address = Some(instruction.address);
        if let Some(semantics) = instruction.semantics.as_ref() {
            if self.debug
                && (matches!(semantics.status, crate::semantics::SemanticStatus::Partial)
                    || !semantics.diagnostics.is_empty())
            {
                let diagnostics = semantics
                    .diagnostics
                    .iter()
                    .map(|diagnostic| format!("{:?}: {}", diagnostic.kind, diagnostic.message))
                    .collect::<Vec<_>>()
                    .join(" | ");
                self.record_semantic_lowering(
                    "semantics_status",
                    format!(
                        "status={:?} diagnostics=[{}]",
                        semantics.status, diagnostics
                    ),
                );
            }
            *self.cached_flags_register.borrow_mut() = None;
            let prepared = prepare_instruction_semantics(semantics)?;
            self.emit_body_marker_if_needed(prepared.encoding.is_none())?;
            if let Some(encoding) = prepared.encoding.as_ref() {
                self.emit_instruction_encoding(encoding)?;
            }
            let previous_semantics_abi = self.current_semantics_abi;
            self.current_semantics_abi = prepared.abi;
            let result = (|| -> Result<(), Error> {
                self.seed_instruction_inputs(&prepared)?;
                self.lower_semantics(&prepared)
            })();
            self.current_semantics_abi = previous_semantics_abi;
            result?;
            *self.cached_flags_register.borrow_mut() = None;
        }
        self.current_instruction_address = None;
        Ok(())
    }

    fn lower_instruction_semantics(
        &mut self,
        semantics: &InstructionSemantics,
    ) -> Result<(), Error> {
        if self.debug
            && (matches!(semantics.status, crate::semantics::SemanticStatus::Partial)
                || !semantics.diagnostics.is_empty())
        {
            let diagnostics = semantics
                .diagnostics
                .iter()
                .map(|diagnostic| format!("{:?}: {}", diagnostic.kind, diagnostic.message))
                .collect::<Vec<_>>()
                .join(" | ");
            self.record_semantic_lowering(
                "semantics_status",
                format!(
                    "status={:?} diagnostics=[{}]",
                    semantics.status, diagnostics
                ),
            );
        }
        *self.cached_flags_register.borrow_mut() = None;
        let prepared = prepare_instruction_semantics(semantics)?;
        self.emit_body_marker_if_needed(prepared.encoding.is_none())?;
        if let Some(encoding) = prepared.encoding.as_ref() {
            self.emit_instruction_encoding(encoding)?;
        }
        let previous_semantics_abi = self.current_semantics_abi;
        self.current_semantics_abi = prepared.abi;
        let result = (|| -> Result<(), Error> {
            self.seed_instruction_inputs(&prepared)?;
            self.lower_semantics(&prepared)
        })();
        self.current_semantics_abi = previous_semantics_abi;
        result?;
        *self.cached_flags_register.borrow_mut() = None;
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
            SemanticEffect::Intrinsic { args, .. } => {
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
                    self.collect_expression_reads(expression, registers, program_counters, flags);
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
            SemanticExpression::Intrinsic { args, .. } => {
                for arg in args {
                    self.collect_expression_reads(arg, registers, program_counters, flags);
                }
            }
            SemanticExpression::Const { .. }
            | SemanticExpression::Undefined { .. }
            | SemanticExpression::Poison { .. } => {}
        }
    }

}
