use self::helpers::{push_unique_location, render_location, sanitize_symbol};
use crate::Architecture;
use crate::Configuration;
use crate::controlflow::{Block, Function, Instruction};
use crate::io::Stderr;
use crate::lifters::llvm::optimizers::Optimizers;
use crate::lifters::llvm::prepare::prepare_instruction_semantics;
use crate::lifters::llvm::verify::verify_module;
use crate::semantics::{
    Semantic, SemanticAbi, SemanticCpu, SemanticCpuKind, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticTerminator,
};
use inkwell::execution_engine::ExecutionEngine;
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
use std::num::NonZeroU32;

mod effects;
mod encoding;
mod expr;
mod helpers;
mod memory;
mod native;
mod returns;
mod state;
mod support;
mod syscalls;

pub struct Lifter {
    config: Configuration,
    context: &'static Context,
    module: Module<'static>,
    emitted: BTreeSet<String>,
    function_abis: HashMap<String, SemanticAbi>,
    cpu: SemanticCpu,
    architecture: Architecture,
    triple: String,
}

pub struct JittedFunction {
    engine: ExecutionEngine<'static>,
    address: usize,
    name: String,
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
    stack_regions: HashMap<String, PointerValue<'ctx>>,
    written_locations: BTreeSet<String>,
    native_return_adjust: Option<u16>,
    cached_flags_register: RefCell<Option<IntValue<'ctx>>>,
    emit_terminator_helpers: bool,
    abi: Option<SemanticAbi>,
    current_semantics_abi: Option<SemanticAbi>,
    function_arguments: Vec<SemanticLocation>,
    known_function_abis: HashMap<String, SemanticAbi>,
    stack_layouts: HashMap<String, u32>,
}

#[derive(Default)]
struct LoweringSummaryEntry {
    count: usize,
    sample_addresses: Vec<u64>,
}

impl Lifter {
    pub fn new(
        cpu: SemanticCpu,
        config: Configuration,
        triple: Option<String>,
    ) -> Result<Self, Error> {
        let architecture = match cpu.kind() {
            Some(SemanticCpuKind::I386) => Architecture::I386,
            Some(SemanticCpuKind::Amd64) => Architecture::AMD64,
            Some(SemanticCpuKind::Arm64) => Architecture::ARM64,
            Some(SemanticCpuKind::Cil) => Architecture::CIL,
            None => {
                return Err(Error::other(
                    "llvm lifter requires a built-in semantic CPU kind",
                ))
            }
        };
        let context: &'static Context = Box::leak(Box::new(Context::create()));
        let module = context.create_module(&config.lifters.llvm.module_name);
        let triple =
            triple.unwrap_or_else(|| Self::default_triple_for_architecture(architecture).to_string());
        let lifter = Self {
            config,
            context,
            module,
            emitted: BTreeSet::new(),
            function_abis: HashMap::new(),
            cpu,
            architecture,
            triple,
        };
        let _ = lifter.bind_architecture();
        Ok(lifter)
    }

    pub fn from_architecture(architecture: Architecture, config: Configuration) -> Self {
        let cpu = SemanticCpu::from_architecture(architecture).expect("builtin cpu");
        Self::new(cpu, config, None).expect("llvm lifter")
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
        let mut lowering = self.lowering_context(function, None, Vec::new(), HashMap::new())?;
        lowering.lower_instruction(instruction)?;
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_block(&mut self, block: &Block<'_>, abi: Option<&SemanticAbi>) -> Result<(), Error> {
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
        let abi = self.resolve_override_abi(abi)?.or_else(|| self.resolve_block_abi(block));
        let function_arguments = self.active_function_arguments_for_block(block, abi.as_ref());
        let function = self.add_function_for_lift(&name, abi.clone(), &function_arguments);
        let stack_layouts = self.collect_stack_layouts_for_block(block, abi.as_ref());
        let mut lowering =
            self.lowering_context(function, abi, function_arguments, stack_layouts)?;
        for instruction in block.instructions() {
            lowering.lower_instruction(&instruction)?;
        }
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_function(
        &mut self,
        function: &Function<'_>,
        abi: Option<&SemanticAbi>,
    ) -> Result<(), Error> {
        let name = format!("function_{:x}", function.address());
        self.lift_function_named(function, abi, &name, None)
    }

    pub fn lift_function_named(
        &mut self,
        function: &Function<'_>,
        abi: Option<&SemanticAbi>,
        name: &str,
        block_names: Option<&BTreeMap<u64, String>>,
    ) -> Result<(), Error> {
        if self.architecture != function.architecture() {
            return Err(Error::other(format!(
                "llvm lift function architecture mismatch: lifter={} function={}",
                self.architecture.to_string(),
                function.architecture().to_string()
            )));
        }
        self.bind_architecture()?;
        if !self.emitted.insert(name.to_string()) {
            return Ok(());
        }
        let abi = self
            .resolve_override_abi(abi)?
            .or_else(|| self.resolve_function_abi(function));
        let function_arguments = self.active_function_arguments_for_function(function, abi.as_ref());
        let llvm_function = self.add_function_for_lift(name, abi.clone(), &function_arguments);
        let stack_layouts = self.collect_stack_layouts_for_function(function, abi.as_ref());
        let mut lowering =
            self.lowering_context(llvm_function, abi, function_arguments, stack_layouts)?;
        lowering.emit_terminator_helpers = false;
        lowering.lower_function(function, block_names)?;
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_block_semantics(
        &mut self,
        semantics: &[Semantic],
        abi: Option<&SemanticAbi>,
    ) -> Result<(), Error> {
        self.bind_architecture()?;
        let abi = self
            .resolve_override_abi(abi)?
            .or_else(|| self.resolve_semantics_abi(semantics));
        let name = self.next_emitted_name("semantic_block");
        let function_arguments =
            self.active_function_arguments_for_semantics(semantics, abi.as_ref());
        let function = self.add_function_for_lift(&name, abi.clone(), &function_arguments);
        let stack_layouts = self.collect_stack_layouts_for_semantics(semantics, abi.as_ref());
        let mut lowering =
            self.lowering_context(function, abi, function_arguments, stack_layouts)?;
        for semantics in semantics {
            lowering.lower_instruction_semantics(semantics)?;
        }
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn lift_function_semantics(
        &mut self,
        semantics: &[Semantic],
        abi: Option<&SemanticAbi>,
    ) -> Result<(), Error> {
        let name = self.next_emitted_name("semantic_function");
        self.lift_function_semantics_named(semantics, abi, &name)
    }

    pub fn lift_function_semantics_named(
        &mut self,
        semantics: &[Semantic],
        abi: Option<&SemanticAbi>,
        name: &str,
    ) -> Result<(), Error> {
        self.bind_architecture()?;
        let abi = self
            .resolve_override_abi(abi)?
            .or_else(|| self.resolve_semantics_abi(semantics));
        if !self.emitted.insert(name.to_string()) {
            return Ok(());
        }
        let function_arguments =
            self.active_function_arguments_for_semantics(semantics, abi.as_ref());
        let function = self.add_function_for_lift(name, abi.clone(), &function_arguments);
        let stack_layouts = self.collect_stack_layouts_for_semantics(semantics, abi.as_ref());
        let mut lowering =
            self.lowering_context(function, abi, function_arguments, stack_layouts)?;
        for semantics in semantics {
            lowering.lower_instruction_semantics(semantics)?;
        }
        lowering.finish()?;
        self.verify_if_enabled()?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), Error> {
        self.module = self.context.create_module(&self.config.lifters.llvm.module_name);
        self.emitted.clear();
        self.function_abis.clear();
        self.bind_architecture()
    }

    pub fn ir(&self) -> String {
        self.module.print_to_string().to_string()
    }

    pub fn set_ir(&mut self, ir: &str) -> Result<(), Error> {
        let buffer = MemoryBuffer::create_from_memory_range_copy(ir.as_bytes(), "binlex.ll");
        let module = self
            .context
            .create_module_from_ir(buffer)
            .map_err(|err| Error::other(err.to_string()))?;
        self.module = module;
        self.function_abis.clear();
        self.refresh_emitted_from_module();
        Ok(())
    }

    pub fn set_bitcode(&mut self, bitcode: &[u8]) -> Result<(), Error> {
        let buffer = MemoryBuffer::create_from_memory_range_copy(bitcode, "binlex.bc");
        let module = Module::parse_bitcode_from_buffer(&buffer, self.context)
            .map_err(|err| Error::other(err.to_string()))?;
        self.module = module;
        self.function_abis.clear();
        self.refresh_emitted_from_module();
        Ok(())
    }

    pub fn link_ir_module(
        &mut self,
        ir: &str,
        required_function: Option<&str>,
    ) -> Result<(), Error> {
        let buffer = MemoryBuffer::create_from_memory_range_copy(ir.as_bytes(), "binlex.ll");
        let module = self
            .context
            .create_module_from_ir(buffer)
            .map_err(|err| Error::other(err.to_string()))?;
        self.validate_imported_module(&module, required_function)?;
        self.module
            .link_in_module(module)
            .map_err(|err| Error::other(err.to_string()))?;
        self.refresh_emitted_from_module();
        Ok(())
    }

    pub fn link_bitcode_module(
        &mut self,
        bitcode: &[u8],
        required_function: Option<&str>,
    ) -> Result<(), Error> {
        let buffer = MemoryBuffer::create_from_memory_range_copy(bitcode, "binlex.bc");
        let module = Module::parse_bitcode_from_buffer(&buffer, self.context)
            .map_err(|err| Error::other(err.to_string()))?;
        self.validate_imported_module(&module, required_function)?;
        self.module
            .link_in_module(module)
            .map_err(|err| Error::other(err.to_string()))?;
        self.refresh_emitted_from_module();
        Ok(())
    }

    pub fn text(&self) -> String {
        self.ir()
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

    pub fn jit_function(self, function_name: &str) -> Result<JittedFunction, Error> {
        self.ensure_native_jit_supported()?;
        let function = self
            .module
            .get_function(function_name)
            .ok_or_else(|| Error::other(format!("llvm function {function_name} does not exist")))?;
        if function.get_first_basic_block().is_none() {
            return Err(Error::other(format!(
                "llvm function {function_name} has no body"
            )));
        }
        Target::initialize_native(&InitializationConfig::default())
            .map_err(|err| Error::other(err.to_string()))?;
        let engine = self
            .module
            .create_jit_execution_engine(OptimizationLevel::Default)
            .map_err(|err| Error::other(err.to_string()))?;
        let address = engine
            .get_function_address(function_name)
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(JittedFunction {
            engine,
            address,
            name: function_name.to_string(),
        })
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

    pub fn optimize_mem2reg(&mut self) -> Result<(), Error> {
        *self = self.mem2reg()?;
        Ok(())
    }

    pub fn optimize_instcombine(&mut self) -> Result<(), Error> {
        *self = self.instcombine()?;
        Ok(())
    }

    pub fn optimize_cfg(&mut self) -> Result<(), Error> {
        *self = self.cfg()?;
        Ok(())
    }

    pub fn optimize_gvn(&mut self) -> Result<(), Error> {
        *self = self.gvn()?;
        Ok(())
    }

    pub fn optimize_sroa(&mut self) -> Result<(), Error> {
        *self = self.sroa()?;
        Ok(())
    }

    pub fn optimize_dce(&mut self) -> Result<(), Error> {
        *self = self.dce()?;
        Ok(())
    }

    pub fn mem2reg_function(&self, function_name: &str) -> Result<Self, Error> {
        self.run_named_function_pass("mem2reg", function_name)
    }

    pub fn instcombine_function(&self, function_name: &str) -> Result<Self, Error> {
        self.run_named_function_pass("instcombine<no-verify-fixpoint>", function_name)
    }

    pub fn cfg_function(&self, function_name: &str) -> Result<Self, Error> {
        self.run_named_function_pass("simplifycfg", function_name)
    }

    pub fn gvn_function(&self, function_name: &str) -> Result<Self, Error> {
        self.run_named_function_pass("gvn", function_name)
    }

    pub fn sroa_function(&self, function_name: &str) -> Result<Self, Error> {
        self.run_named_function_pass("sroa", function_name)
    }

    pub fn dce_function(&self, function_name: &str) -> Result<Self, Error> {
        self.run_named_function_pass("dce", function_name)
    }

    pub fn verify(&self) -> Result<(), Error> {
        verify_module(&self.module)
    }

    fn resolve_override_abi(&self, abi: Option<&SemanticAbi>) -> Result<Option<SemanticAbi>, Error> {
        let Some(abi) = abi else {
            return Ok(None);
        };
        if abi.supports_architecture(self.architecture) {
            Ok(Some(abi.clone()))
        } else {
            Err(Error::other(format!(
                "semantics abi={} unsupported for architecture={}",
                abi, self.architecture
            )))
        }
    }

    fn resolve_block_abi(&self, block: &Block<'_>) -> Option<SemanticAbi> {
        block.instructions()
            .into_iter()
            .find_map(|instruction| instruction.semantics.as_ref()?.abi.clone())
            .and_then(|abi| self.resolve_embedded_abi(abi))
    }

    fn resolve_function_abi(&self, function: &Function<'_>) -> Option<SemanticAbi> {
        let abi = function
            .reconstruction_instructions()
            .into_iter()
            .find(|instruction| instruction.address == function.address())
            .or_else(|| function.reconstruction_instructions().into_iter().next())?
            .semantics
            .as_ref()?
            .abi
            .clone()?;
        self.resolve_embedded_abi(abi)
    }

    fn resolve_semantics_abi(&self, semantics: &[Semantic]) -> Option<SemanticAbi> {
        semantics
            .iter()
            .find_map(|semantics| semantics.abi.clone())
            .and_then(|abi| self.resolve_embedded_abi(abi))
    }

    fn resolve_embedded_abi(&self, abi: SemanticAbi) -> Option<SemanticAbi> {
        if abi.supports_architecture(self.architecture) {
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

    fn next_emitted_name(&mut self, prefix: &str) -> String {
        let mut index = self.emitted.len();
        loop {
            let name = format!("{prefix}_{index}");
            if !self.emitted.contains(&name) {
                return name;
            }
            index += 1;
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

    fn add_function_for_lift(
        &mut self,
        name: &str,
        abi: Option<SemanticAbi>,
        function_arguments: &[SemanticLocation],
    ) -> FunctionValue<'static> {
        if let Some(function) = self.module.get_function(name) {
            if let Some(abi) = abi {
                self.function_abis.insert(name.to_string(), abi);
            }
            return function;
        }
        let args = function_arguments
            .iter()
            .map(|location| self.int_type(location.bits()).into())
            .collect::<Vec<_>>();
        let fn_type = match abi.as_ref().and_then(|abi| abi.function_return_bits) {
            Some(bits) if bits > 0 => self.int_type(bits).fn_type(&args, false),
            _ => self.context.void_type().fn_type(&args, false),
        };
        let function = self.module.add_function(name, fn_type, None);
        function.add_attribute(
            AttributeLoc::Function,
            self.context
                .create_string_attribute("frame-pointer", "none"),
        );
        if let Some(abi) = abi {
            self.function_abis.insert(name.to_string(), abi);
        }
        function
    }

    fn int_type(&self, bits: u16) -> inkwell::types::IntType<'static> {
        match bits {
            1 => self.context.bool_type(),
            8 => self.context.i8_type(),
            16 => self.context.i16_type(),
            32 => self.context.i32_type(),
            64 => self.context.i64_type(),
            128 => self.context.i128_type(),
            width => self
                .context
                .custom_width_int_type(NonZeroU32::new(width as u32).expect("non-zero int width"))
                .expect("custom width int type"),
        }
    }

    fn lowering_context(
        &self,
        function: FunctionValue<'static>,
        abi: Option<SemanticAbi>,
        function_arguments: Vec<SemanticLocation>,
        stack_layouts: HashMap<String, u32>,
    ) -> Result<LoweringContext<'static, '_>, Error> {
        let builder = self.context.create_builder();
        let entry = self.context.append_basic_block(function, "entry");
        builder.position_at_end(entry);
        let mut lowering = LoweringContext {
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
            stack_regions: HashMap::new(),
            written_locations: BTreeSet::new(),
            native_return_adjust: None,
            cached_flags_register: RefCell::new(None),
            emit_terminator_helpers: true,
            abi,
            current_semantics_abi: None,
            function_arguments,
            known_function_abis: self.function_abis.clone(),
            stack_layouts,
        };
        lowering.bind_function_arguments()?;
        Ok(lowering)
    }

    fn verify_if_enabled(&self) -> Result<(), Error> {
        if self.config.lifters.llvm.verify {
            self.verify()
        } else {
            Ok(())
        }
    }

    fn refresh_emitted_from_module(&mut self) {
        self.emitted.clear();
        for function in self.module.get_functions() {
            self.emitted
                .insert(function.get_name().to_string_lossy().into_owned());
        }
        self.function_abis.retain(|name, _| self.emitted.contains(name));
    }

    fn validate_imported_module(
        &self,
        module: &Module<'static>,
        required_function: Option<&str>,
    ) -> Result<(), Error> {
        let Some(required_function) = required_function else {
            return Ok(());
        };
        if module
            .get_functions()
            .any(|function| function.get_name().to_string_lossy() == required_function)
        {
            Ok(())
        } else {
            Err(Error::other(format!(
                "imported llvm module is missing function {}",
                required_function
            )))
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
            function_abis: self.function_abis.clone(),
            cpu: self.cpu.clone(),
            architecture: self.architecture,
            triple: self.triple.clone(),
        })
    }

    pub fn duplicate_function_view(&self, function_name: &str) -> Result<Self, Error> {
        let mut duplicate = self.duplicate()?;
        let target_exists = duplicate
            .module
            .get_function(function_name)
            .filter(|function| function.get_first_basic_block().is_some())
            .is_some();
        if !target_exists {
            return Err(Error::other(format!(
                "llvm function {function_name} does not exist"
            )));
        }

        let functions = duplicate.module.get_functions().collect::<Vec<_>>();
        for function in functions {
            let name = function.get_name().to_string_lossy().into_owned();
            if name == function_name || function.get_first_basic_block().is_none() {
                continue;
            }
            unsafe {
                function.delete();
            }
        }
        duplicate.refresh_emitted_from_module();
        duplicate.verify_if_enabled()?;
        Ok(duplicate)
    }

    fn default_triple_for_architecture(architecture: Architecture) -> &'static str {
        match architecture {
            Architecture::I386 => "i386-unknown-unknown",
            Architecture::AMD64 => "x86_64-unknown-unknown",
            Architecture::ARM64 => "aarch64-unknown-unknown",
            _ => "x86_64-unknown-unknown",
        }
    }

    fn ensure_native_jit_supported(&self) -> Result<(), Error> {
        match self.architecture {
            Architecture::I386 => {
                #[cfg(target_arch = "x86")]
                {
                    Ok(())
                }
                #[cfg(not(target_arch = "x86"))]
                {
                    Err(Error::other(
                        "native llvm jit for i386 requires an x86 host process",
                    ))
                }
            }
            Architecture::AMD64 => {
                #[cfg(target_arch = "x86_64")]
                {
                    Ok(())
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    Err(Error::other(
                        "native llvm jit for amd64 requires an x86_64 host process",
                    ))
                }
            }
            Architecture::ARM64 => {
                #[cfg(target_arch = "aarch64")]
                {
                    Ok(())
                }
                #[cfg(not(target_arch = "aarch64"))]
                {
                    Err(Error::other(
                        "native llvm jit for arm64 requires an aarch64 host process",
                    ))
                }
            }
            _ => Err(Error::other(
                "native llvm jit is unsupported for this architecture",
            )),
        }
    }

    fn active_function_arguments_for_semantics(
        &self,
        semantics: &[Semantic],
        abi: Option<&SemanticAbi>,
    ) -> Vec<SemanticLocation> {
        let Some(abi) = abi else {
            return Vec::new();
        };
        let mut read_locations = std::collections::HashSet::new();
        for semantic in semantics {
            collect_semantic_read_locations(semantic, &mut read_locations);
        }
        active_function_arguments(&read_locations, abi)
    }

    fn collect_stack_layouts_for_semantics(
        &self,
        semantics: &[Semantic],
        abi: Option<&SemanticAbi>,
    ) -> HashMap<String, u32> {
        let mut layouts = HashMap::new();
        for semantic in semantics {
            collect_semantic_stack_layouts(semantic, &mut layouts);
        }
        if let Some(abi) = abi {
            collect_abi_stack_layouts(abi, &mut layouts);
        }
        layouts
    }

    fn active_function_arguments_for_block(
        &self,
        block: &Block<'_>,
        abi: Option<&SemanticAbi>,
    ) -> Vec<SemanticLocation> {
        let Some(abi) = abi else {
            return Vec::new();
        };
        let mut read_locations = std::collections::HashSet::new();
        for instruction in block.instructions() {
            if let Some(semantics) = instruction.semantics.as_ref() {
                collect_semantic_read_locations(semantics, &mut read_locations);
            }
        }
        if let Some(semantics) = block.terminator.semantics.as_ref() {
            collect_semantic_read_locations(semantics, &mut read_locations);
        }
        active_function_arguments(&read_locations, abi)
    }

    fn collect_stack_layouts_for_block(
        &self,
        block: &Block<'_>,
        abi: Option<&SemanticAbi>,
    ) -> HashMap<String, u32> {
        let mut layouts = HashMap::new();
        for instruction in block.instructions() {
            if let Some(semantics) = instruction.semantics.as_ref() {
                collect_semantic_stack_layouts(semantics, &mut layouts);
            }
        }
        if let Some(semantics) = block.terminator.semantics.as_ref() {
            collect_semantic_stack_layouts(semantics, &mut layouts);
        }
        if let Some(abi) = abi {
            collect_abi_stack_layouts(abi, &mut layouts);
        }
        layouts
    }

    fn active_function_arguments_for_function(
        &self,
        function: &Function<'_>,
        abi: Option<&SemanticAbi>,
    ) -> Vec<SemanticLocation> {
        let Some(abi) = abi else {
            return Vec::new();
        };
        let mut read_locations = std::collections::HashSet::new();
        for block in function.blocks() {
            for instruction in block.instructions() {
                if let Some(semantics) = instruction.semantics.as_ref() {
                    collect_semantic_read_locations(semantics, &mut read_locations);
                }
            }
            if let Some(semantics) = block.terminator.semantics.as_ref() {
                collect_semantic_read_locations(semantics, &mut read_locations);
            }
        }
        active_function_arguments(&read_locations, abi)
    }

    fn collect_stack_layouts_for_function(
        &self,
        function: &Function<'_>,
        abi: Option<&SemanticAbi>,
    ) -> HashMap<String, u32> {
        let mut layouts = HashMap::new();
        for block in function.blocks() {
            for instruction in block.instructions() {
                if let Some(semantics) = instruction.semantics.as_ref() {
                    collect_semantic_stack_layouts(semantics, &mut layouts);
                }
            }
            if let Some(semantics) = block.terminator.semantics.as_ref() {
                collect_semantic_stack_layouts(semantics, &mut layouts);
            }
        }
        if let Some(abi) = abi {
            collect_abi_stack_layouts(abi, &mut layouts);
        }
        layouts
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

    fn run_named_function_pass(&self, pass_pipeline: &str, function_name: &str) -> Result<Self, Error> {
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
        let function = optimized
            .module
            .get_function(function_name)
            .ok_or_else(|| Error::other(format!("llvm function {function_name} does not exist")))?;
        if function.get_first_basic_block().is_some() {
            let options = PassBuilderOptions::create();
            options.set_verify_each(optimized.config.lifters.llvm.verify);
            if let Err(error) = function.run_passes(pass_pipeline, &machine, options) {
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
        optimized.verify_if_enabled()?;
        Ok(optimized)
    }

    fn target_machine(&self) -> Result<TargetMachine, Error> {
        let config = InitializationConfig::default();
        match self.architecture {
            Architecture::I386 | Architecture::AMD64 => Target::initialize_x86(&config),
            Architecture::ARM64 => Target::initialize_aarch64(&config),
            _ => Target::initialize_x86(&config),
        }
        let triple = inkwell::targets::TargetTriple::create(&self.triple);
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
        self.module
            .set_triple(&inkwell::targets::TargetTriple::create(&self.triple));
        if let Ok(machine) = self.target_machine() {
            let data_layout = machine.get_target_data().get_data_layout();
            self.module.set_data_layout(&data_layout);
        }
        Ok(())
    }
}

#[cfg(test)]
mod jit_tests {
    use super::Lifter;
    use crate::semantics::{
        Semantic, SemanticAbi, SemanticCpu, SemanticEffect, SemanticExpression, SemanticLocation,
        SemanticOperationBinary, SemanticStatus, SemanticTerminator,
    };
    use crate::Configuration;

    #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
    #[test]
    fn jit_function_executes_amd64_add_two() {
        let cpu = SemanticCpu::amd64().expect("cpu");
        let abi = SemanticAbi::sysv(&cpu).expect("sysv abi");
        let mut lifter = Lifter::new(cpu, Configuration::default(), None).expect("lifter");

        let semantics = [Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "rax".to_string(),
                    bits: 64,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Add,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rdi".to_string(),
                            bits: 64,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rsi".to_string(),
                            bits: 64,
                        },
                    ))),
                    bits: 64,
                },
            }],
            terminator: SemanticTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        }];

        lifter
            .lift_function_semantics_named(&semantics, Some(&abi), "add_two")
            .expect("function lift");
        lifter.optimize_mem2reg().expect("mem2reg");
        lifter.optimize_sroa().expect("sroa");
        lifter.optimize_instcombine().expect("instcombine");
        lifter.optimize_gvn().expect("gvn");
        lifter.optimize_dce().expect("dce");

        let jitted = lifter
            .duplicate_function_view("add_two")
            .expect("function view")
            .jit_function("add_two")
            .expect("jit function");

        let function: extern "C" fn(u64, u64) -> u64 =
            unsafe { std::mem::transmute(jitted.address()) };
        assert_eq!(function(1, 1), 2);
        assert_eq!(jitted.name(), "add_two");
    }
}

impl JittedFunction {
    pub fn address(&self) -> usize {
        self.address
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn keepalive_token(&self) -> usize {
        (&self.engine as *const ExecutionEngine<'static>) as usize
    }
}

fn active_function_arguments(
    read_locations: &std::collections::HashSet<SemanticLocation>,
    abi: &SemanticAbi,
) -> Vec<SemanticLocation> {
    let mut highest_used = None;
    for (index, location) in abi.function_arguments.iter().enumerate() {
        if read_locations
            .iter()
            .any(|read| location_matches_abi_argument(read, location))
        {
            highest_used = Some(index);
        }
    }
    highest_used
        .map(|index| abi.function_arguments[..=index].to_vec())
        .unwrap_or_default()
}

fn location_matches_abi_argument(read: &SemanticLocation, argument: &SemanticLocation) -> bool {
    if read == argument {
        return true;
    }
    match (x86_argument_register_alias(read), x86_argument_register_alias(argument)) {
        (Some(read), Some(argument)) => read == argument,
        _ => false,
    }
}

fn x86_argument_register_alias(location: &SemanticLocation) -> Option<(String, u16)> {
    let SemanticLocation::Register { name, bits } = location else {
        return None;
    };
    match (*bits, name.as_str()) {
        (8, "al") | (8, "ah") | (16, "ax") => Some(("eax".to_string(), 32)),
        (8, "bl") | (8, "bh") | (16, "bx") => Some(("ebx".to_string(), 32)),
        (8, "cl") | (8, "ch") | (16, "cx") => Some(("ecx".to_string(), 32)),
        (8, "dl") | (8, "dh") | (16, "dx") => Some(("edx".to_string(), 32)),
        _ => Some((name.clone(), *bits)),
    }
}

fn collect_abi_stack_layouts(abi: &SemanticAbi, layouts: &mut HashMap<String, u32>) {
    for location in &abi.function_arguments {
        collect_stack_layout_for_location(location, layouts);
    }
    for location in &abi.return_locations {
        collect_stack_layout_for_location(location, layouts);
    }
    for trap in &abi.traps {
        if let Some(location) = &trap.number_register {
            collect_stack_layout_for_location(location, layouts);
        }
        for location in &trap.argument_registers {
            collect_stack_layout_for_location(location, layouts);
        }
        for location in &trap.result_registers {
            collect_stack_layout_for_location(location, layouts);
        }
        for location in &trap.shadow_registers {
            collect_stack_layout_for_location(location, layouts);
        }
    }
}

fn collect_semantic_read_locations(
    semantics: &Semantic,
    reads: &mut std::collections::HashSet<SemanticLocation>,
) {
    for effect in &semantics.effects {
        collect_effect_read_locations(effect, reads);
    }
    collect_terminator_read_locations(&semantics.terminator, reads);
}

fn collect_semantic_stack_layouts(semantics: &Semantic, layouts: &mut HashMap<String, u32>) {
    for temporary in &semantics.temporaries {
        let _ = temporary;
    }
    for effect in &semantics.effects {
        collect_effect_stack_layouts(effect, layouts);
    }
    collect_terminator_stack_layouts(&semantics.terminator, layouts);
}

fn collect_effect_read_locations(
    effect: &SemanticEffect,
    reads: &mut std::collections::HashSet<SemanticLocation>,
) {
    match effect {
        SemanticEffect::Set { expression, .. } => collect_expression_read_locations(expression, reads),
        SemanticEffect::Store { addr, expression, .. } => {
            collect_expression_read_locations(addr, reads);
            collect_expression_read_locations(expression, reads);
        }
        SemanticEffect::MemorySet {
            addr,
            value,
            count,
            decrement,
            ..
        } => {
            collect_expression_read_locations(addr, reads);
            collect_expression_read_locations(value, reads);
            collect_expression_read_locations(count, reads);
            collect_expression_read_locations(decrement, reads);
        }
        SemanticEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            decrement,
            ..
        } => {
            collect_expression_read_locations(src_addr, reads);
            collect_expression_read_locations(dst_addr, reads);
            collect_expression_read_locations(count, reads);
            collect_expression_read_locations(decrement, reads);
        }
        SemanticEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            ..
        } => {
            collect_expression_read_locations(addr, reads);
            collect_expression_read_locations(expected, reads);
            collect_expression_read_locations(desired, reads);
        }
        SemanticEffect::WriteProperty {
            reference,
            expression,
            ..
        } => {
            collect_expression_read_locations(reference, reads);
            collect_expression_read_locations(expression, reads);
        }
        SemanticEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => {
            collect_expression_read_locations(reference, reads);
            collect_expression_read_locations(index, reads);
            collect_expression_read_locations(expression, reads);
        }
        SemanticEffect::Push { expression, .. } => collect_expression_read_locations(expression, reads),
        SemanticEffect::Intrinsic { args, .. } => {
            for arg in args {
                collect_expression_read_locations(arg, reads);
            }
        }
        SemanticEffect::Pop { .. }
        | SemanticEffect::Fence { .. }
        | SemanticEffect::Trap { .. }
        | SemanticEffect::Nop => {}
    }
}

fn collect_effect_stack_layouts(effect: &SemanticEffect, layouts: &mut HashMap<String, u32>) {
    match effect {
        SemanticEffect::Set { dst, expression } => {
            collect_stack_layout_for_location(dst, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        SemanticEffect::Store { addr, expression, .. } => {
            collect_expression_stack_layouts(addr, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        SemanticEffect::MemorySet {
            addr,
            value,
            count,
            decrement,
            ..
        } => {
            collect_expression_stack_layouts(addr, layouts);
            collect_expression_stack_layouts(value, layouts);
            collect_expression_stack_layouts(count, layouts);
            collect_expression_stack_layouts(decrement, layouts);
        }
        SemanticEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            decrement,
            ..
        } => {
            collect_expression_stack_layouts(src_addr, layouts);
            collect_expression_stack_layouts(dst_addr, layouts);
            collect_expression_stack_layouts(count, layouts);
            collect_expression_stack_layouts(decrement, layouts);
        }
        SemanticEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            observed,
            ..
        } => {
            collect_expression_stack_layouts(addr, layouts);
            collect_expression_stack_layouts(expected, layouts);
            collect_expression_stack_layouts(desired, layouts);
            collect_stack_layout_for_location(observed, layouts);
        }
        SemanticEffect::WriteProperty {
            reference,
            expression,
            ..
        } => {
            collect_expression_stack_layouts(reference, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        SemanticEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => {
            collect_expression_stack_layouts(reference, layouts);
            collect_expression_stack_layouts(index, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        SemanticEffect::Push { expression, .. } => collect_expression_stack_layouts(expression, layouts),
        SemanticEffect::Pop { dst, .. } => collect_stack_layout_for_location(dst, layouts),
        SemanticEffect::Intrinsic { args, outputs, .. } => {
            for arg in args {
                collect_expression_stack_layouts(arg, layouts);
            }
            for output in outputs {
                collect_stack_layout_for_location(output, layouts);
            }
        }
        SemanticEffect::Fence { .. } | SemanticEffect::Trap { .. } | SemanticEffect::Nop => {}
    }
}

fn collect_terminator_read_locations(
    terminator: &SemanticTerminator,
    reads: &mut std::collections::HashSet<SemanticLocation>,
) {
    match terminator {
        SemanticTerminator::Jump { target } => collect_expression_read_locations(target, reads),
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_read_locations(condition, reads);
            collect_expression_read_locations(true_target, reads);
            collect_expression_read_locations(false_target, reads);
        }
        SemanticTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_read_locations(target, reads);
            if let Some(return_target) = return_target {
                collect_expression_read_locations(return_target, reads);
            }
        }
        SemanticTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_read_locations(expression, reads);
            }
        }
        SemanticTerminator::FallThrough
        | SemanticTerminator::Trap
        | SemanticTerminator::Unreachable => {}
    }
}

fn collect_terminator_stack_layouts(
    terminator: &SemanticTerminator,
    layouts: &mut HashMap<String, u32>,
) {
    match terminator {
        SemanticTerminator::Jump { target } => collect_expression_stack_layouts(target, layouts),
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_stack_layouts(condition, layouts);
            collect_expression_stack_layouts(true_target, layouts);
            collect_expression_stack_layouts(false_target, layouts);
        }
        SemanticTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_stack_layouts(target, layouts);
            if let Some(return_target) = return_target {
                collect_expression_stack_layouts(return_target, layouts);
            }
        }
        SemanticTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_stack_layouts(expression, layouts);
            }
        }
        SemanticTerminator::FallThrough
        | SemanticTerminator::Trap
        | SemanticTerminator::Unreachable => {}
    }
}

fn collect_expression_read_locations(
    expression: &SemanticExpression,
    reads: &mut std::collections::HashSet<SemanticLocation>,
) {
    match expression {
        SemanticExpression::AddressOf { .. } => {}
        SemanticExpression::Read(location) => {
            reads.insert(location.as_ref().clone());
            match location.as_ref() {
                SemanticLocation::Memory { addr, .. } => collect_expression_read_locations(addr, reads),
                SemanticLocation::IndexedMemory { index, .. } => {
                    collect_expression_read_locations(index, reads)
                }
                SemanticLocation::Register { .. }
                | SemanticLocation::Flag { .. }
                | SemanticLocation::ProgramCounter { .. }
                | SemanticLocation::Temporary { .. }
                | SemanticLocation::StackMemory { .. } => {}
            }
        }
        SemanticExpression::Load { addr, .. } => collect_expression_read_locations(addr, reads),
        SemanticExpression::ReadProperty { reference, .. } => {
            collect_expression_read_locations(reference, reads)
        }
        SemanticExpression::ReadElement {
            reference, index, ..
        } => {
            collect_expression_read_locations(reference, reads);
            collect_expression_read_locations(index, reads);
        }
        SemanticExpression::Unary { arg, .. }
        | SemanticExpression::Cast { arg, .. }
        | SemanticExpression::Extract { arg, .. } => collect_expression_read_locations(arg, reads),
        SemanticExpression::Binary { left, right, .. }
        | SemanticExpression::Compare { left, right, .. } => {
            collect_expression_read_locations(left, reads);
            collect_expression_read_locations(right, reads);
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_read_locations(condition, reads);
            collect_expression_read_locations(when_true, reads);
            collect_expression_read_locations(when_false, reads);
        }
        SemanticExpression::Concat { parts, .. } | SemanticExpression::Intrinsic { args: parts, .. } => {
            for part in parts {
                collect_expression_read_locations(part, reads);
            }
        }
        SemanticExpression::Const { .. }
        | SemanticExpression::Function { .. }
        | SemanticExpression::Undefined { .. }
        | SemanticExpression::Poison { .. }
        | SemanticExpression::Null { .. }
        | SemanticExpression::Allocate { .. } => {}
    }
}

fn collect_expression_stack_layouts(
    expression: &SemanticExpression,
    layouts: &mut HashMap<String, u32>,
) {
    match expression {
        SemanticExpression::AddressOf { location, .. } => {
            collect_stack_layout_for_location(location, layouts);
        }
        SemanticExpression::Read(location) => collect_stack_layout_for_location(location, layouts),
        SemanticExpression::Load { addr, .. } => collect_expression_stack_layouts(addr, layouts),
        SemanticExpression::ReadProperty { reference, .. } => {
            collect_expression_stack_layouts(reference, layouts)
        }
        SemanticExpression::ReadElement {
            reference, index, ..
        } => {
            collect_expression_stack_layouts(reference, layouts);
            collect_expression_stack_layouts(index, layouts);
        }
        SemanticExpression::Unary { arg, .. }
        | SemanticExpression::Cast { arg, .. }
        | SemanticExpression::Extract { arg, .. } => collect_expression_stack_layouts(arg, layouts),
        SemanticExpression::Binary { left, right, .. }
        | SemanticExpression::Compare { left, right, .. } => {
            collect_expression_stack_layouts(left, layouts);
            collect_expression_stack_layouts(right, layouts);
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_stack_layouts(condition, layouts);
            collect_expression_stack_layouts(when_true, layouts);
            collect_expression_stack_layouts(when_false, layouts);
        }
        SemanticExpression::Concat { parts, .. } | SemanticExpression::Intrinsic { args: parts, .. } => {
            for part in parts {
                collect_expression_stack_layouts(part, layouts);
            }
        }
        SemanticExpression::Const { .. }
        | SemanticExpression::Function { .. }
        | SemanticExpression::Undefined { .. }
        | SemanticExpression::Poison { .. }
        | SemanticExpression::Null { .. }
        | SemanticExpression::Allocate { .. } => {}
    }
}

fn collect_stack_layout_for_location(location: &SemanticLocation, layouts: &mut HashMap<String, u32>) {
    match location {
        SemanticLocation::StackMemory { name, offset, bits } => {
            let bytes = u32::from((*bits).div_ceil(8));
            let end = offset.saturating_add(bytes.max(1));
            layouts
                .entry(name.clone())
                .and_modify(|current| *current = (*current).max(end))
                .or_insert(end);
        }
        SemanticLocation::Memory { addr, .. } => collect_expression_stack_layouts(addr, layouts),
        SemanticLocation::IndexedMemory { index, .. } => {
            collect_expression_stack_layouts(index, layouts)
        }
        SemanticLocation::Register { .. }
        | SemanticLocation::Flag { .. }
        | SemanticLocation::ProgramCounter { .. }
        | SemanticLocation::Temporary { .. } => {}
    }
}

fn should_emit_instruction_encoding(semantics: &Semantic) -> bool {
    matches!(semantics.status, crate::semantics::SemanticStatus::Partial)
}

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    fn uses_pure_callable_abi(&self) -> bool {
        self.abi.is_some()
            && (self.function.get_first_param().is_some()
                || self
                    .abi
                    .as_ref()
                    .and_then(|abi| abi.function_return_bits)
                    .is_some())
    }

    fn is_callable_abi_boundary_location(&self, location: &SemanticLocation) -> bool {
        let Some(abi) = &self.abi else {
            return false;
        };
        abi.function_arguments.iter().any(|arg| arg == location)
            || abi.return_locations.iter().any(|ret| ret == location)
    }

    fn bind_function_arguments(&mut self) -> Result<(), Error> {
        for (index, (param, location)) in self
            .function
            .get_param_iter()
            .zip(self.function_arguments.iter())
            .enumerate()
        {
            let key = render_location(location);
            let slot = self.build_entry_alloca(
                self.location_type(location),
                &sanitize_symbol(&format!("abi_arg_{}_{}", index, key)),
            )?;
            self.builder
                .build_store(slot, param.into_int_value())
                .map_err(|err| Error::other(err.to_string()))?;
            self.slots.insert(key.clone(), slot);
            self.slot_locations.insert(key, location.clone());
        }
        Ok(())
    }

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

    fn lower_function(
        &mut self,
        function: &Function<'_>,
        block_names: Option<&BTreeMap<u64, String>>,
    ) -> Result<(), Error> {
        let mut block_map = HashMap::<u64, BasicBlock<'ctx>>::new();
        for block in function.blocks() {
            let block_name = block_names
                .and_then(|names| names.get(&block.address()).map(|name| name.as_str()))
                .map(str::to_string)
                .unwrap_or_else(|| format!("block_{:x}", block.address()));
            let llvm_block = self
                .context
                .append_basic_block(self.function, &block_name);
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
                let target = self.ensure_exit_block(exit_block);
                self.builder
                    .build_unconditional_branch(target)
                    .map_err(|err| Error::other(err.to_string()))?;
            } else if block.terminator.is_conditional {
                return Err(Error::other(
                    "conditional block terminator requires semantics for llvm lowering",
                ));
            } else if block.terminator.is_jump {
                let fallback_jump_target = block
                    .branches()
                    .iter()
                    .next()
                    .and_then(|address| block_map.get(address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                self.builder
                    .build_unconditional_branch(fallback_jump_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            } else {
                let fallback_fallthrough_target = block
                    .fallthrough()
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
                    .fallthrough()
                    .and_then(|address| block_map.get(&address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                self.builder
                    .build_unconditional_branch(fallback_fallthrough_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            SemanticTerminator::Jump { target } => {
                let fallback_jump_target = block
                    .branches()
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
                    .branches()
                    .iter()
                    .next()
                    .and_then(|address| block_map.get(address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                let fallback_fallthrough_target = block
                    .fallthrough()
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
                        .fallthrough()
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
            let emit_encoding = should_emit_instruction_encoding(&prepared);
            if emit_encoding {
                let Some(encoding) = prepared.encoding.as_ref() else {
                    return Err(Error::other(
                        "partial instruction semantics require encoding for llvm lowering",
                    ));
                };
                self.emit_instruction_encoding(encoding)?;
            }
            let previous_semantics_abi = self.current_semantics_abi.clone();
            self.current_semantics_abi = prepared.abi.clone();
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

    fn lower_instruction_semantics(&mut self, semantics: &Semantic) -> Result<(), Error> {
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
        let emit_encoding = should_emit_instruction_encoding(&prepared);
        if emit_encoding {
            let Some(encoding) = prepared.encoding.as_ref() else {
                return Err(Error::other(
                    "partial instruction semantics require encoding for llvm lowering",
                ));
            };
            self.emit_instruction_encoding(encoding)?;
        }
        let previous_semantics_abi = self.current_semantics_abi.clone();
        self.current_semantics_abi = prepared.abi.clone();
        let result = (|| -> Result<(), Error> {
            self.seed_instruction_inputs(&prepared)?;
            self.lower_semantics(&prepared)
        })();
        self.current_semantics_abi = previous_semantics_abi;
        result?;
        *self.cached_flags_register.borrow_mut() = None;
        Ok(())
    }

    fn seed_instruction_inputs(&mut self, semantics: &Semantic) -> Result<(), Error> {
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
            SemanticEffect::WriteProperty {
                reference,
                expression,
                ..
            } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            SemanticEffect::WriteElement {
                reference,
                index,
                expression,
                ..
            } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
                self.collect_expression_reads(index, registers, program_counters, flags);
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            SemanticEffect::Push { expression, .. } => {
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            SemanticEffect::Pop { .. } => {}
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
            SemanticExpression::Function { .. } => {}
            SemanticExpression::AddressOf { .. } => {}
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
                SemanticLocation::IndexedMemory { index, .. } => {
                    self.collect_expression_reads(index, registers, program_counters, flags);
                }
                SemanticLocation::StackMemory { .. } => {}
                SemanticLocation::Temporary { .. } => {}
            },
            SemanticExpression::Load { addr, .. } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
            }
            SemanticExpression::ReadProperty { reference, .. } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
            }
            SemanticExpression::ReadElement {
                reference, index, ..
            } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
                self.collect_expression_reads(index, registers, program_counters, flags);
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
            | SemanticExpression::Poison { .. }
            | SemanticExpression::Null { .. }
            | SemanticExpression::Allocate { .. } => {}
        }
    }
}
