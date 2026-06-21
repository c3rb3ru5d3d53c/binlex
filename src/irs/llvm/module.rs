use self::helpers::{push_unique_location, sanitize_symbol};
use crate::Architecture;
use crate::Configuration;
use crate::controlflow::{Block, Function, Instruction};
use crate::io::Stderr;
use crate::irs::lir::{
    LirCpu, LirCpuKind, LirData, LirEffect, LirExpression, LirInstruction, LirLocation, LirModule,
    LirTerminator,
};
use crate::irs::llvm::optimizers::Optimizers;
use crate::irs::llvm::prepare::prepare_instruction_lir;
use crate::irs::llvm::verify::verify_module;
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
use std::sync::{Mutex, Once, OnceLock};

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

pub struct LlvmModule {
    config: Configuration,
    context: &'static Context,
    module: Module<'static>,
    emitted: BTreeSet<String>,
    data_symbols: HashMap<String, Vec<u8>>,
    cpu: LirCpu,
    architecture: Architecture,
    triple: String,
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
    slot_locations: HashMap<String, LirLocation>,
    stack_regions: HashMap<String, PointerValue<'ctx>>,
    written_locations: BTreeSet<String>,
    native_return_adjust: Option<u16>,
    cached_flags_register: RefCell<Option<IntValue<'ctx>>>,
    emit_terminator_helpers: bool,
    stack_layouts: HashMap<String, u32>,
}

#[derive(Default)]
struct LoweringSummaryEntry {
    count: usize,
    sample_addresses: Vec<u64>,
}

static LLVM_X86_INIT: Once = Once::new();
static LLVM_AARCH64_INIT: Once = Once::new();
static LLVM_DATA_LAYOUTS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

impl LlvmModule {
    pub fn new(name: Option<String>, cpu: LirCpu, triple: Option<String>) -> Result<Self, Error> {
        Self::with_config(name, cpu, Configuration::default(), triple)
    }

    pub fn with_config(
        name: Option<String>,
        cpu: LirCpu,
        config: Configuration,
        triple: Option<String>,
    ) -> Result<Self, Error> {
        let architecture = match cpu.kind() {
            Some(LirCpuKind::I386) => Architecture::I386,
            Some(LirCpuKind::Amd64) => Architecture::AMD64,
            Some(LirCpuKind::Arm64) => Architecture::ARM64,
            Some(LirCpuKind::Cil) => Architecture::CIL,
            None => {
                return Err(Error::other("llvm module requires a built-in lir CPU kind"));
            }
        };
        let context: &'static Context = Box::leak(Box::new(Context::create()));
        let module_name = name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| config.irs.llvm.module_name.clone());
        let module = context.create_module(&module_name);
        let triple = triple
            .unwrap_or_else(|| Self::default_triple_for_architecture(architecture).to_string());
        let lifter = Self {
            config,
            context,
            module,
            emitted: BTreeSet::new(),
            data_symbols: HashMap::new(),
            cpu,
            architecture,
            triple,
        };
        let _ = lifter.bind_architecture();
        Ok(lifter)
    }

    pub fn from_architecture(architecture: Architecture) -> Self {
        Self::from_architecture_with_config(architecture, Configuration::default())
    }

    pub fn from_architecture_with_config(
        architecture: Architecture,
        config: Configuration,
    ) -> Self {
        let cpu = LirCpu::from_architecture(architecture).expect("builtin cpu");
        Self::with_config(None, cpu, config, None).expect("llvm module")
    }

    pub fn from_lir(&mut self, lir: &LirModule, config: Configuration) -> Result<(), Error> {
        let module = crate::irs::llvm::lower::from_lir(
            lir,
            self.cpu.clone(),
            config,
            Some(self.triple.clone()),
        )?;
        *self = module;
        Ok(())
    }

    pub fn populate_instruction(&mut self, instruction: &Instruction) -> Result<(), Error> {
        if self.architecture != instruction.architecture {
            return Err(Error::other(format!(
                "llvm lift instruction architecture mismatch: module={} instruction={}",
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
        let mut lowering = self.lowering_context(function, HashMap::new())?;
        lowering
            .lower_prepared_instruction_record(instruction.address, instruction.prepared_lir()?)?;
        lowering.finish()?;
        Ok(())
    }

    pub fn populate_block(&mut self, block: &Block<'_>) -> Result<(), Error> {
        if self.architecture != block.architecture() {
            return Err(Error::other(format!(
                "llvm lift block architecture mismatch: module={} block={}",
                self.architecture.to_string(),
                block.architecture().to_string()
            )));
        }
        self.bind_architecture()?;
        let name = format!("block_{:x}", block.address());
        if !self.emitted.insert(name.clone()) {
            return Ok(());
        }
        let function = self.add_function_for_lift(&name, None);
        let stack_layouts = self.collect_stack_layouts_for_block(block);
        let mut lowering = self.lowering_context(function, stack_layouts)?;
        for instruction_address in block.instruction_addresses() {
            let lowered = block
                .cfg
                .with_instruction_record(instruction_address, |record| {
                    lowering
                        .lower_prepared_instruction_record(record.address, record.prepared_lir()?)
                })
                .ok_or_else(|| Error::other("prepared block instruction should exist"))?;
            lowered?;
        }
        lowering.finish()?;
        Ok(())
    }

    pub fn populate_function(&mut self, function: &Function<'_>) -> Result<(), Error> {
        let name = format!("function_{:x}", function.address());
        self.populate_function_named(function, &name, None)
    }

    pub fn populate_function_named(
        &mut self,
        function: &Function<'_>,
        name: &str,
        block_names: Option<&BTreeMap<u64, String>>,
    ) -> Result<(), Error> {
        if self.architecture != function.architecture() {
            return Err(Error::other(format!(
                "llvm lift function architecture mismatch: module={} function={}",
                self.architecture.to_string(),
                function.architecture().to_string()
            )));
        }
        self.bind_architecture()?;
        if !self.emitted.insert(name.to_string()) {
            return Ok(());
        }
        let prepared_blocks = self.prepare_function_blocks(function);
        let llvm_function =
            self.add_function_for_lift(name, infer_return_bits_from_blocks(&prepared_blocks));
        let stack_layouts = self.collect_stack_layouts_for_function(&prepared_blocks);
        let mut lowering = self.lowering_context(llvm_function, stack_layouts)?;
        lowering.emit_terminator_helpers = false;
        lowering.lower_function(function.address(), &prepared_blocks, block_names)?;
        lowering.finish()?;
        Ok(())
    }

    pub fn populate_block_lir(&mut self, lir: &LirModule) -> Result<(), Error> {
        self.bind_architecture()?;
        self.declare_lir_data(&lir.data)?;
        let instructions = lir.instructions().into_iter().cloned().collect::<Vec<_>>();
        let name = self.next_emitted_name("lir_block");
        let function = self.add_function_for_lift(&name, infer_return_bits(&instructions));
        let stack_layouts = self.collect_stack_layouts_for_lir(&instructions);
        let mut lowering = self.lowering_context(function, stack_layouts)?;
        for lir in &instructions {
            lowering.lower_instruction_lir(lir)?;
        }
        lowering.finish()?;
        Ok(())
    }

    pub fn populate_function_lir(&mut self, lir: &LirModule) -> Result<(), Error> {
        let name = self.next_emitted_name("lir_function");
        self.populate_function_lir_named(lir, &name)
    }

    pub fn populate_function_lir_named(
        &mut self,
        lir: &LirModule,
        name: &str,
    ) -> Result<(), Error> {
        self.bind_architecture()?;
        self.declare_lir_data(&lir.data)?;
        let instructions = lir.instructions().into_iter().cloned().collect::<Vec<_>>();
        if !self.emitted.insert(name.to_string()) {
            return Ok(());
        }
        let function = self.add_function_for_lift(name, infer_return_bits(&instructions));
        let stack_layouts = self.collect_stack_layouts_for_lir(&instructions);
        let mut lowering = self.lowering_context(function, stack_layouts)?;
        for lir in &instructions {
            lowering.lower_instruction_lir(lir)?;
        }
        lowering.finish()?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), Error> {
        self.module = self.context.create_module(&self.module_name());
        self.emitted.clear();
        self.data_symbols.clear();
        self.bind_architecture()
    }

    pub fn text(&self) -> String {
        let _ = self.verify_if_enabled();
        self.module.print_to_string().to_string()
    }

    pub fn set_text(&mut self, text: &str) -> Result<(), Error> {
        let text = format!("{text}\0");
        let buffer = MemoryBuffer::create_from_memory_range_copy(text.as_bytes(), "binlex.ll");
        let module = self
            .context
            .create_module_from_ir(buffer)
            .map_err(|err| Error::other(err.to_string()))?;
        self.module = module;
        self.refresh_emitted_from_module();
        Ok(())
    }

    pub fn set_bitcode(&mut self, bitcode: &[u8]) -> Result<(), Error> {
        let buffer = MemoryBuffer::create_from_memory_range_copy(bitcode, "binlex.bc");
        let module = Module::parse_bitcode_from_buffer(&buffer, self.context)
            .map_err(|err| Error::other(err.to_string()))?;
        self.module = module;
        self.refresh_emitted_from_module();
        Ok(())
    }

    pub fn link_ir_module(
        &mut self,
        ir: &str,
        required_function: Option<&str>,
    ) -> Result<(), Error> {
        let ir = format!("{ir}\0");
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

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn bitcode(&self) -> Vec<u8> {
        let _ = self.verify_if_enabled();
        let buffer = self.module.write_bitcode_to_memory();
        buffer.as_slice().to_vec()
    }

    pub fn object(&self) -> Result<Vec<u8>, Error> {
        self.verify_if_enabled()?;
        let codegen = self
            .mem2reg()
            .unwrap_or_else(|_| self.duplicate().expect("duplicate llvm module"));
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
        return_bits: Option<u16>,
    ) -> FunctionValue<'static> {
        if let Some(function) = self.module.get_function(name) {
            return function;
        }
        let args = [];
        let fn_type = match return_bits {
            Some(bits) if bits > 0 => self.int_type(bits).fn_type(&args, false),
            _ => self.context.void_type().fn_type(&args, false),
        };
        let function = self.module.add_function(name, fn_type, None);
        function.add_attribute(
            AttributeLoc::Function,
            self.context
                .create_string_attribute("frame-pointer", "none"),
        );
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
        stack_layouts: HashMap<String, u32>,
    ) -> Result<LoweringContext<'static, '_>, Error> {
        let builder = self.context.create_builder();
        let entry = self.context.append_basic_block(function, "entry");
        builder.position_at_end(entry);
        let lowering = LoweringContext {
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
            stack_layouts,
        };
        Ok(lowering)
    }

    fn verify_if_enabled(&self) -> Result<(), Error> {
        if self.config.irs.llvm.verify {
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

    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        let context: &'static Context = Box::leak(Box::new(Context::create()));
        let module_name = self.module_name();
        let source_file_name = self.source_file_name();
        let buffer = MemoryBuffer::create_from_memory_range_copy(&self.bitcode(), &module_name);
        let module = Module::parse_bitcode_from_buffer(&buffer, context)
            .map_err(|err| Error::other(err.to_string()))?;
        module.set_name(&module_name);
        module.set_source_file_name(&source_file_name);
        Ok(Self {
            config: self.config.clone(),
            context,
            module,
            emitted: self.emitted.clone(),
            data_symbols: self.data_symbols.clone(),
            cpu: self.cpu.clone(),
            architecture: self.architecture,
            triple: self.triple.clone(),
        })
    }

    fn module_name(&self) -> String {
        self.module.get_name().to_string_lossy().into_owned()
    }

    fn source_file_name(&self) -> String {
        self.module
            .get_source_file_name()
            .to_string_lossy()
            .into_owned()
    }

    fn declare_lir_data(&mut self, data: &[LirData]) -> Result<(), Error> {
        for item in data {
            if item.name.trim().is_empty() {
                return Err(Error::other("lir data item has empty name"));
            }
            if let Some(existing) = self.data_symbols.get(&item.name) {
                if existing != &item.bytes {
                    return Err(Error::other(format!(
                        "lir data symbol {} already exists with different contents",
                        item.name
                    )));
                }
                continue;
            }
            let global_name = sanitize_symbol(&format!("binlex_data_{}", item.name));
            if self.module.get_global(&global_name).is_none() {
                let bytes = self.context.i8_type().const_array(
                    &item
                        .bytes
                        .iter()
                        .map(|byte| self.context.i8_type().const_int(u64::from(*byte), false))
                        .collect::<Vec<_>>(),
                );
                let global = self.module.add_global(bytes.get_type(), None, &global_name);
                global.set_linkage(inkwell::module::Linkage::Private);
                global.set_constant(true);
                global.set_initializer(&bytes);
            }
            self.data_symbols
                .insert(item.name.clone(), item.bytes.clone());
        }
        Ok(())
    }

    fn default_triple_for_architecture(architecture: Architecture) -> &'static str {
        match architecture {
            Architecture::I386 => "i386-unknown-unknown",
            Architecture::AMD64 => "x86_64-unknown-unknown",
            Architecture::ARM64 => "aarch64-unknown-unknown",
            _ => "x86_64-unknown-unknown",
        }
    }

    fn collect_stack_layouts_for_lir(&self, lir: &[LirInstruction]) -> HashMap<String, u32> {
        let mut layouts = HashMap::new();
        for lir in lir {
            collect_lir_stack_layouts(lir, &mut layouts);
        }
        layouts
    }

    fn collect_stack_layouts_for_block(&self, block: &Block<'_>) -> HashMap<String, u32> {
        let mut layouts = HashMap::new();
        for instruction_address in block.instruction_addresses() {
            block
                .cfg
                .with_instruction_record(instruction_address, |record| {
                    if let Some(lir) = record.lir.as_ref() {
                        collect_lir_stack_layouts(lir, &mut layouts);
                    }
                });
        }
        if let Some(lir) = block.terminator.lir.as_ref() {
            collect_lir_stack_layouts(lir, &mut layouts);
        }
        layouts
    }

    fn prepare_function_blocks<'a>(
        &self,
        function: &'a Function<'a>,
    ) -> Vec<(Block<'a>, Vec<u64>)> {
        function
            .blocks
            .values()
            .cloned()
            .map(|block| (block.clone(), block.instruction_addresses()))
            .collect()
    }

    fn collect_stack_layouts_for_function(
        &self,
        blocks: &[(Block<'_>, Vec<u64>)],
    ) -> HashMap<String, u32> {
        let mut layouts = HashMap::new();
        for (block, instruction_addresses) in blocks {
            for instruction_address in instruction_addresses {
                block
                    .cfg
                    .with_instruction_record(*instruction_address, |record| {
                        if let Some(lir) = record.lir.as_ref() {
                            collect_lir_stack_layouts(lir, &mut layouts);
                        }
                    });
            }
            if let Some(lir) = block.terminator.lir.as_ref() {
                collect_lir_stack_layouts(lir, &mut layouts);
            }
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
            options.set_verify_each(optimized.config.irs.llvm.verify);
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

    fn run_named_function_pass(
        &self,
        pass_pipeline: &str,
        function_name: &str,
    ) -> Result<Self, Error> {
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
            options.set_verify_each(optimized.config.irs.llvm.verify);
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
        Self::ensure_target_initialized(self.architecture);
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
        let data_layout = Self::cached_data_layout(self.architecture, &self.triple)?;
        self.module
            .set_data_layout(&inkwell::targets::TargetData::create(&data_layout).get_data_layout());
        Ok(())
    }

    fn ensure_target_initialized(architecture: Architecture) {
        let config = InitializationConfig::default();
        match architecture {
            Architecture::I386 | Architecture::AMD64 => {
                LLVM_X86_INIT.call_once(|| Target::initialize_x86(&config));
            }
            Architecture::ARM64 => {
                LLVM_AARCH64_INIT.call_once(|| Target::initialize_aarch64(&config));
            }
            _ => {
                LLVM_X86_INIT.call_once(|| Target::initialize_x86(&config));
            }
        }
    }

    fn cached_data_layout(architecture: Architecture, triple: &str) -> Result<String, Error> {
        let cache = LLVM_DATA_LAYOUTS.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(layout) = cache.lock().unwrap().get(triple).cloned() {
            return Ok(layout);
        }

        Self::ensure_target_initialized(architecture);
        let triple_ref = inkwell::targets::TargetTriple::create(triple);
        let target =
            Target::from_triple(&triple_ref).map_err(|err| Error::other(err.to_string()))?;
        let machine = target
            .create_target_machine(
                &triple_ref,
                "generic",
                "",
                OptimizationLevel::Default,
                RelocMode::Default,
                CodeModel::Default,
            )
            .ok_or_else(|| Error::other("failed to create llvm target machine"))?;
        let layout = machine
            .get_target_data()
            .get_data_layout()
            .as_str()
            .to_str()
            .map_err(|error| Error::other(error.to_string()))?
            .to_string();
        cache
            .lock()
            .unwrap()
            .insert(triple.to_string(), layout.clone());
        Ok(layout)
    }
}

fn infer_return_bits(lir: &[LirInstruction]) -> Option<u16> {
    lir.iter()
        .rev()
        .find_map(|instruction| match &instruction.terminator {
            LirTerminator::Return {
                expression: Some(expression),
            } => Some(expression.bits()),
            _ => None,
        })
}

fn infer_return_bits_from_blocks(blocks: &[(Block<'_>, Vec<u64>)]) -> Option<u16> {
    blocks
        .iter()
        .rev()
        .find_map(|(block, instruction_addresses)| {
            if let Some(bits) = block
                .terminator
                .lir
                .as_ref()
                .and_then(|lir| infer_return_bits(std::slice::from_ref(lir)))
            {
                return Some(bits);
            }

            instruction_addresses.iter().rev().find_map(|address| {
                block.cfg.with_instruction_record(*address, |record| {
                    record
                        .lir
                        .as_ref()
                        .and_then(|lir| infer_return_bits(std::slice::from_ref(lir)))
                })?
            })
        })
}

fn collect_lir_stack_layouts(lir: &LirInstruction, layouts: &mut HashMap<String, u32>) {
    for effect in &lir.effects {
        collect_effect_stack_layouts(effect, layouts);
    }
    collect_terminator_stack_layouts(&lir.terminator, layouts);
}

fn collect_effect_stack_layouts(effect: &LirEffect, layouts: &mut HashMap<String, u32>) {
    match effect {
        LirEffect::Set { dst, expression } => {
            collect_stack_layout_for_location(dst, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        LirEffect::Store {
            addr, expression, ..
        } => {
            collect_expression_stack_layouts(addr, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        LirEffect::MemorySet {
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
        LirEffect::MemoryCopy {
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
        LirEffect::AtomicCmpXchg {
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
        LirEffect::WriteProperty {
            reference,
            expression,
            ..
        } => {
            collect_expression_stack_layouts(reference, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => {
            collect_expression_stack_layouts(reference, layouts);
            collect_expression_stack_layouts(index, layouts);
            collect_expression_stack_layouts(expression, layouts);
        }
        LirEffect::Push { expression, .. } => collect_expression_stack_layouts(expression, layouts),
        LirEffect::Pop { dst, .. } => collect_stack_layout_for_location(dst, layouts),
        LirEffect::Intrinsic { args, outputs, .. } => {
            for arg in args {
                collect_expression_stack_layouts(arg, layouts);
            }
            for output in outputs {
                collect_stack_layout_for_location(output, layouts);
            }
        }
        LirEffect::Fence { .. } | LirEffect::Trap { .. } | LirEffect::Nop => {}
    }
}

fn collect_terminator_stack_layouts(
    terminator: &LirTerminator,
    layouts: &mut HashMap<String, u32>,
) {
    match terminator {
        LirTerminator::Jump { target } => collect_expression_stack_layouts(target, layouts),
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            collect_expression_stack_layouts(condition, layouts);
            collect_expression_stack_layouts(true_target, layouts);
            collect_expression_stack_layouts(false_target, layouts);
        }
        LirTerminator::Call {
            target,
            return_target,
            ..
        } => {
            collect_expression_stack_layouts(target, layouts);
            if let Some(return_target) = return_target {
                collect_expression_stack_layouts(return_target, layouts);
            }
        }
        LirTerminator::Return { expression } => {
            if let Some(expression) = expression {
                collect_expression_stack_layouts(expression, layouts);
            }
        }
        LirTerminator::FallThrough | LirTerminator::Trap | LirTerminator::Unreachable => {}
    }
}

fn collect_expression_stack_layouts(
    expression: &LirExpression,
    layouts: &mut HashMap<String, u32>,
) {
    match expression {
        LirExpression::DataAddress { .. } => {}
        LirExpression::AddressOf { location, .. } => {
            collect_stack_layout_for_location(location, layouts);
        }
        LirExpression::Read(location) => collect_stack_layout_for_location(location, layouts),
        LirExpression::Load { addr, .. } => collect_expression_stack_layouts(addr, layouts),
        LirExpression::ReadProperty { reference, .. } => {
            collect_expression_stack_layouts(reference, layouts)
        }
        LirExpression::ReadElement {
            reference, index, ..
        } => {
            collect_expression_stack_layouts(reference, layouts);
            collect_expression_stack_layouts(index, layouts);
        }
        LirExpression::Unary { arg, .. }
        | LirExpression::Cast { arg, .. }
        | LirExpression::Extract { arg, .. } => collect_expression_stack_layouts(arg, layouts),
        LirExpression::Binary { left, right, .. } | LirExpression::Compare { left, right, .. } => {
            collect_expression_stack_layouts(left, layouts);
            collect_expression_stack_layouts(right, layouts);
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_expression_stack_layouts(condition, layouts);
            collect_expression_stack_layouts(when_true, layouts);
            collect_expression_stack_layouts(when_false, layouts);
        }
        LirExpression::Concat { parts, .. } | LirExpression::Intrinsic { args: parts, .. } => {
            for part in parts {
                collect_expression_stack_layouts(part, layouts);
            }
        }
        LirExpression::Const { .. }
        | LirExpression::Function { .. }
        | LirExpression::Undefined { .. }
        | LirExpression::Poison { .. }
        | LirExpression::Null { .. }
        | LirExpression::Allocate { .. } => {}
    }
}

fn collect_stack_layout_for_location(location: &LirLocation, layouts: &mut HashMap<String, u32>) {
    match location {
        LirLocation::StackMemory { name, offset, bits } => {
            let bytes = u32::from((*bits).div_ceil(8));
            let end = offset.saturating_add(bytes.max(1));
            layouts
                .entry(name.clone())
                .and_modify(|current| *current = (*current).max(end))
                .or_insert(end);
        }
        LirLocation::Memory { addr, .. } => collect_expression_stack_layouts(addr, layouts),
        LirLocation::IndexedMemory { index, .. } => {
            collect_expression_stack_layouts(index, layouts)
        }
        LirLocation::Register { .. }
        | LirLocation::Flag { .. }
        | LirLocation::ProgramCounter { .. }
        | LirLocation::Temporary { .. } => {}
    }
}

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    fn record_lir_lowering(&mut self, kind: &str, detail: impl Into<String>) {
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
                "llvm lir summary function={} kind={} count={} sample_addresses={} detail={}",
                self.function_name, kind, entry.count, addresses, detail
            ));
        }
    }

    fn lower_function(
        &mut self,
        function_address: u64,
        blocks: &[(Block<'_>, Vec<u64>)],
        block_names: Option<&BTreeMap<u64, String>>,
    ) -> Result<(), Error> {
        let mut block_map = HashMap::<u64, BasicBlock<'ctx>>::new();
        for (block, _) in blocks {
            let block_name = block_names
                .and_then(|names| names.get(&block.address()).map(|name| name.as_str()))
                .map(str::to_string)
                .unwrap_or_else(|| format!("block_{:x}", block.address()));
            let llvm_block = self.context.append_basic_block(self.function, &block_name);
            block_map.insert(block.address(), llvm_block);
        }

        let mut exit_block = None;
        let entry = self
            .function
            .get_first_basic_block()
            .expect("function should have entry block");
        let block_addresses = blocks
            .iter()
            .map(|(block, _)| block.address())
            .collect::<Vec<_>>();
        let entry_address = block_addresses
            .iter()
            .copied()
            .find(|address| *address == function_address)
            .or_else(|| block_addresses.first().copied())
            .ok_or_else(|| Error::other("function contains no basic blocks"))?;
        let entry_target = *block_map
            .get(&entry_address)
            .ok_or_else(|| Error::other("function entry block is missing from llvm block map"))?;
        self.builder.position_at_end(entry);
        self.builder
            .build_unconditional_branch(entry_target)
            .map_err(|err| Error::other(err.to_string()))?;

        for (block, instruction_addresses) in blocks {
            let llvm_block = *block_map
                .get(&block.address())
                .ok_or_else(|| Error::other("missing llvm block for binlex block"))?;
            self.builder.position_at_end(llvm_block);
            for instruction_address in instruction_addresses {
                let lowered = block
                    .cfg
                    .with_instruction_record(*instruction_address, |record| {
                        self.lower_prepared_instruction_record(
                            record.address,
                            record.prepared_lir()?,
                        )
                    })
                    .ok_or_else(|| Error::other("prepared function instruction should exist"))?;
                lowered?;
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
            if let Some(adjust) = self.native_return_adjust {
                self.sync_slots_to_architecture()?;
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
        let lir = block
            .terminator
            .lir
            .clone()
            .or_else(|| block.terminator.build_lir());
        let Some(lir) = lir.as_ref() else {
            if block.terminator.is_return {
                let target = self.ensure_exit_block(exit_block);
                self.builder
                    .build_unconditional_branch(target)
                    .map_err(|err| Error::other(err.to_string()))?;
            } else if block.terminator.is_conditional {
                return Err(Error::other(
                    "conditional block terminator requires lir for llvm lowering",
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

        match &lir.terminator {
            LirTerminator::FallThrough => {
                let fallback_fallthrough_target = block
                    .fallthrough()
                    .and_then(|address| block_map.get(&address).copied())
                    .unwrap_or_else(|| self.ensure_exit_block(exit_block));
                self.builder
                    .build_unconditional_branch(fallback_fallthrough_target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            LirTerminator::Jump { target } => {
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
            LirTerminator::Branch {
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
            LirTerminator::Call { does_return, .. } => {
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
            LirTerminator::Return { .. } => {
                let target = self.ensure_exit_block(exit_block);
                self.builder
                    .build_unconditional_branch(target)
                    .map_err(|err| Error::other(err.to_string()))?;
            }
            LirTerminator::Unreachable | LirTerminator::Trap => {
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

    fn lower_prepared_instruction_record(
        &mut self,
        instruction_address: u64,
        lir: Option<&LirInstruction>,
    ) -> Result<(), Error> {
        self.current_instruction_address = Some(instruction_address);
        if let Some(lir) = lir {
            if self.debug && matches!(lir.status, crate::irs::lir::LirStatus::Partial) {
                self.record_lir_lowering("lir_status", format!("status={:?}", lir.status));
            }
            *self.cached_flags_register.borrow_mut() = None;
            let prepared = prepare_instruction_lir(lir)?;
            let result = (|| -> Result<(), Error> {
                self.seed_instruction_inputs(&prepared)?;
                self.lower_lir(&prepared)
            })();
            result?;
            *self.cached_flags_register.borrow_mut() = None;
        }
        self.current_instruction_address = None;
        Ok(())
    }

    fn lower_instruction_lir(&mut self, lir: &LirInstruction) -> Result<(), Error> {
        if self.debug && matches!(lir.status, crate::irs::lir::LirStatus::Partial) {
            self.record_lir_lowering("lir_status", format!("status={:?}", lir.status));
        }
        *self.cached_flags_register.borrow_mut() = None;
        let prepared = prepare_instruction_lir(lir)?;
        let result = (|| -> Result<(), Error> {
            self.seed_instruction_inputs(&prepared)?;
            self.lower_lir(&prepared)
        })();
        result?;
        *self.cached_flags_register.borrow_mut() = None;
        Ok(())
    }

    fn seed_instruction_inputs(&mut self, lir: &LirInstruction) -> Result<(), Error> {
        let mut registers = Vec::<LirLocation>::new();
        let mut program_counters = Vec::<LirLocation>::new();
        let mut flags = Vec::<LirLocation>::new();
        for effect in &lir.effects {
            self.collect_effect_reads(effect, &mut registers, &mut program_counters, &mut flags);
        }
        self.collect_terminator_reads(
            &lir.terminator,
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
        effect: &LirEffect,
        registers: &mut Vec<LirLocation>,
        program_counters: &mut Vec<LirLocation>,
        flags: &mut Vec<LirLocation>,
    ) {
        match effect {
            LirEffect::Set { dst, expression } => {
                self.collect_expression_reads(expression, registers, program_counters, flags);
                if let Some((parent_name, parent_bits, _)) = self.x86_parent_register_alias(dst) {
                    push_unique_location(
                        registers,
                        LirLocation::Register {
                            name: parent_name,
                            bits: parent_bits,
                        },
                    );
                }
            }
            LirEffect::Store {
                addr, expression, ..
            } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            LirEffect::MemorySet {
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
            LirEffect::MemoryCopy {
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
            LirEffect::AtomicCmpXchg {
                addr,
                expected,
                desired,
                ..
            } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
                self.collect_expression_reads(expected, registers, program_counters, flags);
                self.collect_expression_reads(desired, registers, program_counters, flags);
            }
            LirEffect::WriteProperty {
                reference,
                expression,
                ..
            } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            LirEffect::WriteElement {
                reference,
                index,
                expression,
                ..
            } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
                self.collect_expression_reads(index, registers, program_counters, flags);
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            LirEffect::Push { expression, .. } => {
                self.collect_expression_reads(expression, registers, program_counters, flags);
            }
            LirEffect::Pop { .. } => {}
            LirEffect::Intrinsic { args, .. } => {
                for arg in args {
                    self.collect_expression_reads(arg, registers, program_counters, flags);
                }
            }
            LirEffect::Fence { .. } | LirEffect::Trap { .. } | LirEffect::Nop => {}
        }
    }

    fn collect_terminator_reads(
        &self,
        terminator: &LirTerminator,
        registers: &mut Vec<LirLocation>,
        program_counters: &mut Vec<LirLocation>,
        flags: &mut Vec<LirLocation>,
    ) {
        match terminator {
            LirTerminator::Jump { target } => {
                self.collect_expression_reads(target, registers, program_counters, flags);
            }
            LirTerminator::Branch {
                condition,
                true_target,
                false_target,
            } => {
                self.collect_expression_reads(condition, registers, program_counters, flags);
                self.collect_expression_reads(true_target, registers, program_counters, flags);
                self.collect_expression_reads(false_target, registers, program_counters, flags);
            }
            LirTerminator::Call {
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
            LirTerminator::Return { expression } => {
                if let Some(expression) = expression {
                    self.collect_expression_reads(expression, registers, program_counters, flags);
                }
            }
            LirTerminator::FallThrough | LirTerminator::Trap | LirTerminator::Unreachable => {}
        }
    }

    fn collect_expression_reads(
        &self,
        expression: &LirExpression,
        registers: &mut Vec<LirLocation>,
        program_counters: &mut Vec<LirLocation>,
        flags: &mut Vec<LirLocation>,
    ) {
        match expression {
            LirExpression::Function { .. } => {}
            LirExpression::DataAddress { .. } => {}
            LirExpression::AddressOf { .. } => {}
            LirExpression::Read(location) => match location.as_ref() {
                LirLocation::Register { .. } => {
                    push_unique_location(registers, location.as_ref().clone());
                }
                LirLocation::ProgramCounter { .. } => {
                    push_unique_location(program_counters, location.as_ref().clone());
                }
                LirLocation::Flag { .. } => {
                    push_unique_location(flags, location.as_ref().clone());
                }
                LirLocation::Memory { addr, .. } => {
                    self.collect_expression_reads(addr, registers, program_counters, flags);
                }
                LirLocation::IndexedMemory { index, .. } => {
                    self.collect_expression_reads(index, registers, program_counters, flags);
                }
                LirLocation::StackMemory { .. } => {}
                LirLocation::Temporary { .. } => {}
            },
            LirExpression::Load { addr, .. } => {
                self.collect_expression_reads(addr, registers, program_counters, flags);
            }
            LirExpression::ReadProperty { reference, .. } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
            }
            LirExpression::ReadElement {
                reference, index, ..
            } => {
                self.collect_expression_reads(reference, registers, program_counters, flags);
                self.collect_expression_reads(index, registers, program_counters, flags);
            }
            LirExpression::Unary { arg, .. }
            | LirExpression::Cast { arg, .. }
            | LirExpression::Extract { arg, .. } => {
                self.collect_expression_reads(arg, registers, program_counters, flags);
            }
            LirExpression::Binary { left, right, .. }
            | LirExpression::Compare { left, right, .. } => {
                self.collect_expression_reads(left, registers, program_counters, flags);
                self.collect_expression_reads(right, registers, program_counters, flags);
            }
            LirExpression::Select {
                condition,
                when_true,
                when_false,
                ..
            } => {
                self.collect_expression_reads(condition, registers, program_counters, flags);
                self.collect_expression_reads(when_true, registers, program_counters, flags);
                self.collect_expression_reads(when_false, registers, program_counters, flags);
            }
            LirExpression::Concat { parts, .. } => {
                for part in parts {
                    self.collect_expression_reads(part, registers, program_counters, flags);
                }
            }
            LirExpression::Intrinsic { args, .. } => {
                for arg in args {
                    self.collect_expression_reads(arg, registers, program_counters, flags);
                }
            }
            LirExpression::Const { .. }
            | LirExpression::Undefined { .. }
            | LirExpression::Poison { .. }
            | LirExpression::Null { .. }
            | LirExpression::Allocate { .. } => {}
        }
    }
}
