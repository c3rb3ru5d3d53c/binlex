use super::LoweringContext;
use super::helpers::sanitize_symbol;
use crate::irs::lir::LirEncoding;
use inkwell::module::Linkage;
use inkwell::types::{BasicMetadataTypeEnum, IntType};
use inkwell::values::{FunctionValue, PointerValue};
use std::io::Error;

pub(super) const MAX_ENCODING_BYTES: usize = 16;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn emit_instruction_encoding(&self, encoding: &LirEncoding) -> Result<(), Error> {
        if encoding.bytes.len() > MAX_ENCODING_BYTES {
            return Err(Error::other(format!(
                "instruction encoding byte length {} exceeds max supported {}",
                encoding.bytes.len(),
                MAX_ENCODING_BYTES
            )));
        }
        let helper_name = format!("binlex_encoding_{}", sanitize_symbol(&encoding.mnemonic));
        let helper = self.declare_void_helper(
            &helper_name,
            &[self
                .context
                .ptr_type(inkwell::AddressSpace::default())
                .into()],
            false,
        );
        let payload = self.encoding_payload_global(encoding)?;
        self.builder
            .build_call(helper, &[payload.into()], "")
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(())
    }

    fn encoding_payload_global(&self, encoding: &LirEncoding) -> Result<PointerValue<'ctx>, Error> {
        let ptr_ty = self.context.ptr_type(inkwell::AddressSpace::default());
        let byte_array_ty = self.context.i8_type().array_type(MAX_ENCODING_BYTES as u32);
        let encoding_ty = self.context.struct_type(
            &[
                ptr_ty.into(),
                ptr_ty.into(),
                ptr_ty.into(),
                self.context.i64_type().into(),
                self.context.i32_type().into(),
                byte_array_ty.into(),
            ],
            false,
        );
        let mnemonic_key = encoding
            .mnemonic
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string();
        let record_name = sanitize_symbol(&format!(
            "binlex_encoding_{}_{:x}",
            mnemonic_key, encoding.address
        ));
        if let Some(global) = self.module.get_global(&record_name) {
            return Ok(global.as_pointer_value());
        }

        let arch_ptr = self
            .declare_string_constant(
                &format!("binlex_arch_{}", sanitize_symbol(&encoding.architecture)),
                encoding.architecture.as_bytes(),
            )
            .as_pointer_value();
        let mnemonic_ptr = self
            .declare_string_constant(
                &format!("binlex_mnemonic_{}", sanitize_symbol(&encoding.mnemonic)),
                encoding.mnemonic.as_bytes(),
            )
            .as_pointer_value();
        let disassembly_ptr = self
            .declare_string_constant(
                &format!("binlex_disassembly_{}", record_name),
                encoding.disassembly.as_bytes(),
            )
            .as_pointer_value();

        let mut padded = [0u8; MAX_ENCODING_BYTES];
        padded[..encoding.bytes.len()].copy_from_slice(&encoding.bytes);
        let byte_values = padded
            .iter()
            .copied()
            .map(|byte| self.context.i8_type().const_int(byte as u64, false))
            .collect::<Vec<_>>();
        let bytes_value = self.context.i8_type().const_array(&byte_values);
        let payload = self.context.const_struct(
            &[
                arch_ptr.into(),
                mnemonic_ptr.into(),
                disassembly_ptr.into(),
                self.context
                    .i64_type()
                    .const_int(encoding.address, false)
                    .into(),
                self.context
                    .i32_type()
                    .const_int(encoding.bytes.len() as u64, false)
                    .into(),
                bytes_value.into(),
            ],
            false,
        );

        let global = self.module.add_global(encoding_ty, None, &record_name);
        global.set_linkage(Linkage::Private);
        global.set_constant(true);
        global.set_initializer(&payload);
        Ok(global.as_pointer_value())
    }

    fn declare_string_constant(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> inkwell::values::GlobalValue<'ctx> {
        if let Some(global) = self.module.get_global(name) {
            return global;
        }
        let value = self.context.const_string(bytes, true);
        let global = self.module.add_global(value.get_type(), None, name);
        global.set_linkage(Linkage::Private);
        global.set_constant(true);
        global.set_initializer(&value);
        global
    }

    pub(super) fn declare_void_helper(
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

    pub(super) fn declare_value_helper(
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
}

#[cfg(test)]
mod tests {
    use crate::Architecture;
    use crate::Configuration;
    use crate::controlflow::{Function, Graph};
    use crate::disassemblers::capstone::Disassembler;
    use crate::irs::lir::{
        Lir, LirDiagnostic, LirDiagnosticKind, LirEffect, LirEncoding, LirExpression, LirLocation,
        LirStatus, LirTerminator,
    };
    use crate::irs::lir::{LirAbi, LirAbiKind, LirCpu, LirCpuKind, LirMetadata, LirModule};
    use crate::irs::llvm::LlvmModule;
    use std::collections::BTreeMap;

    #[test]
    fn lowers_instruction_encoding_payload_into_llvm_ir() {
        let mut lifter = LlvmModule::from_architecture(Architecture::ARM64);
        let lir = Lir {
            version: 1,
            status: LirStatus::Partial,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: Some(LirEncoding {
                architecture: "arm64".to_string(),
                mnemonic: "ld4".to_string(),
                disassembly: "ld4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x3]".to_string(),
                address: 0x4010,
                bytes: vec![0x60, 0x00, 0x40, 0x4c],
            }),
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
            diagnostics: vec![LirDiagnostic {
                kind: LirDiagnosticKind::UnsupportedInstruction,
                message: "arm64 encoding passthrough".to_string(),
            }],
        };

        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), None)
            .expect("lift lir");
        let text = lifter.text();

        assert!(text.contains("declare void @binlex_encoding_ld4(ptr)"));
        assert!(text.contains("@binlex_encoding_ld4_4010"));
        assert!(text.contains("c\"arm64\\00\""));
        assert!(text.contains("c\"ld4\\00\""));
        assert!(text.contains("ld4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x3]"));
        assert!(text.contains("call void @binlex_encoding_ld4(ptr @binlex_encoding_ld4_4010)"));
    }

    #[test]
    fn omits_instruction_encoding_for_complete_lir() {
        let mut lifter = LlvmModule::from_architecture(Architecture::AMD64);
        let lir = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: Some(LirEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "xor".to_string(),
                disassembly: "xor al, 0x4d".to_string(),
                address: 0x4010,
                bytes: vec![0x34, 0x4d],
            }),
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), None)
            .expect("lift lir");
        let text = lifter.text();

        assert!(!text.contains("@binlex_encoding_xor("));
        assert!(!text.contains("@binlex_encoding_xor_4010"));
        assert!(text.contains("define void @lir_function_0()"));
    }

    #[test]
    fn builtin_fastcall_function_arguments_become_llvm_parameters() {
        let cpu = LirCpu::from_kind(LirCpuKind::I386).expect("cpu");
        let abi = LirAbi::from_kind(LirAbiKind::Fastcall, &cpu).expect("abi");
        let lir = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Binary {
                    op: crate::irs::lir::LirOperationBinary::Add,
                    left: Box::new(LirExpression::Read(Box::new(LirLocation::Register {
                        name: "ecx".to_string(),
                        bits: 32,
                    }))),
                    right: Box::new(LirExpression::Const { value: 1, bits: 32 }),
                    bits: 32,
                },
            }],
            terminator: LirTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };

        let mut lifter = LlvmModule::new(None, cpu, None).expect("llvm module");
        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), Some(&abi))
            .expect("lift lir");
        let text = lifter.text();

        assert!(text.contains("define i32 @lir_function_0(i32 %0)"));
        assert!(!text.contains("movl %ecx, $0"));
        assert!(text.contains("ret i32 %abi_ret"));
    }

    #[test]
    fn lifted_function_uses_native_cfg_without_terminator_helpers() {
        let bytes = [
            0xa2, 0x02, 0x80, 0x52, 0x42, 0x54, 0x00, 0x11, 0x5f, 0xa8, 0x00, 0x71, 0x60, 0x00,
            0x00, 0x54, 0x60, 0x0c, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x00, 0x80, 0x52,
            0x00, 0x24, 0x00, 0x11, 0xc0, 0x03, 0x5f, 0xd6,
        ];

        let config = Configuration::default();
        let mut ranges = BTreeMap::new();
        ranges.insert(0, bytes.len() as u64);
        let mut graph = Graph::new(Architecture::ARM64, config.clone());
        let disassembler =
            Disassembler::from_bytes(Architecture::ARM64, &bytes, ranges, config.clone())
                .expect("disassembler");
        disassembler
            .disassemble([0].into_iter().collect(), &mut graph)
            .expect("disassemble");
        assert!(graph.set_function(0), "function start should be marked");
        let function = Function::new(0, &graph).expect("function");

        let mut lifter = LlvmModule::from_architecture_with_config(Architecture::ARM64, config);
        lifter
            .populate_function(&function, None)
            .expect("lift function");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("br i1"));
        assert!(!text.contains("@binlex_term_branch("));
        assert!(!text.contains("@binlex_term_jump("));
    }

    #[test]
    fn arm64_sysv_abi_lifted_function_returns_i64() {
        let config = Configuration::default();
        let mut lir = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        lir.set_abi(Some(
            LirAbi::from_kind(
                LirAbiKind::SysV,
                &LirCpu::from_kind(LirCpuKind::Arm64).expect("cpu"),
            )
            .expect("abi"),
        ));
        let abi = lir.abi.clone().expect("abi");

        let mut lifter = LlvmModule::from_architecture_with_config(Architecture::ARM64, config);
        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), Some(&abi))
            .expect("lift lir");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i64"));
        assert!(text.contains("@lir_function_0("));
        assert!(text.contains("ret i64"));
        assert!(!text.contains("ret void"));
    }

    #[test]
    fn amd64_windows64_abi_lifted_function_returns_i64() {
        let config = Configuration::default();
        let mut lir = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        lir.set_abi(Some(
            LirAbi::from_kind(
                LirAbiKind::Windows64,
                &LirCpu::from_kind(LirCpuKind::Amd64).expect("cpu"),
            )
            .expect("abi"),
        ));
        let abi = lir.abi.clone().expect("abi");

        let mut lifter = LlvmModule::from_architecture_with_config(Architecture::AMD64, config);
        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), Some(&abi))
            .expect("lift lir");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i64"));
        assert!(text.contains("@lir_function_0("));
        assert!(text.contains("ret i64"));
        assert!(!text.contains("ret void"));
    }

    #[test]
    fn i386_stdcall_abi_lifted_function_returns_i32() {
        let config = Configuration::default();
        let mut lir = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        lir.set_abi(Some(
            LirAbi::from_kind(
                LirAbiKind::Stdcall,
                &LirCpu::from_kind(LirCpuKind::I386).expect("cpu"),
            )
            .expect("abi"),
        ));
        let abi = lir.abi.clone().expect("abi");

        let mut lifter = LlvmModule::from_architecture_with_config(Architecture::I386, config);
        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), Some(&abi))
            .expect("lift lir");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i32"));
        assert!(text.contains("@lir_function_0("));
        assert!(text.contains("ret i32"));
        assert!(!text.contains("ret void"));
    }

    #[test]
    fn i386_stdcall_return_reads_eax_value() {
        let config = Configuration::default();
        let mut lir = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Const { value: 1, bits: 32 },
            }],
            terminator: LirTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        lir.set_abi(Some(
            LirAbi::from_kind(
                LirAbiKind::Stdcall,
                &LirCpu::from_kind(LirCpuKind::I386).expect("cpu"),
            )
            .expect("abi"),
        ));
        let abi = lir.abi.clone().expect("abi");

        let mut lifter = LlvmModule::from_architecture_with_config(Architecture::I386, config);
        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), Some(&abi))
            .expect("lift lir");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i32"));
        assert!(text.contains("store i32 1"));
        assert!(text.contains("ret i32 1") || text.contains("ret i32 %abi_ret"));
        assert!(!text.contains("ret void"));
    }

    #[test]
    fn explicit_function_lir_abi_controls_return_shape() {
        let config = Configuration::default();
        let lir = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: LirMetadata::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Set {
                dst: LirLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: LirExpression::Const { value: 1, bits: 32 },
            }],
            terminator: LirTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        let cpu = LirCpu::from_kind(LirCpuKind::I386).expect("cpu");
        let abi = LirAbi::from_kind(LirAbiKind::Stdcall, &cpu).expect("abi");

        let mut lifter = LlvmModule::from_architecture_with_config(Architecture::I386, config);
        lifter
            .populate_function_lir(&LirModule::from_instructions(vec![lir]), Some(&abi))
            .expect("lift lir");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i32 @lir_function_0("));
        assert!(text.contains("ret i32"));
        assert!(!text.contains("ret void"));
    }
}
