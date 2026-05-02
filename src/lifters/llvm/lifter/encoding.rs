use super::LoweringContext;
use super::helpers::sanitize_symbol;
use crate::semantics::InstructionEncoding;
use inkwell::module::Linkage;
use inkwell::types::{BasicMetadataTypeEnum, IntType};
use inkwell::values::{FunctionValue, PointerValue};
use std::io::Error;

pub(super) const MAX_ENCODING_BYTES: usize = 16;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn emit_instruction_encoding(
        &self,
        encoding: &InstructionEncoding,
    ) -> Result<(), Error> {
        if encoding.bytes.len() > MAX_ENCODING_BYTES {
            return Err(Error::other(format!(
                "instruction encoding byte length {} exceeds max supported {}",
                encoding.bytes.len(),
                MAX_ENCODING_BYTES
            )));
        }
        let helper_name = format!(
            "binlex_encoding_{}",
            sanitize_symbol(&encoding.mnemonic)
        );
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

    fn encoding_payload_global(
        &self,
        encoding: &InstructionEncoding,
    ) -> Result<PointerValue<'ctx>, Error> {
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
    use crate::Config;
    use crate::controlflow::{Function, Graph};
    use crate::disassemblers::capstone::Disassembler;
    use crate::lifters::llvm::Abi;
    use crate::lifters::llvm::Lifter;
    use crate::semantics::{
        InstructionEncoding, InstructionSemantics, SemanticDiagnostic, SemanticDiagnosticKind,
        SemanticStatus, SemanticTerminator,
    };
    use std::collections::BTreeMap;

    #[test]
    fn lowers_instruction_encoding_payload_into_llvm_ir() {
        let mut lifter = Lifter::new(Architecture::ARM64, Config::default());
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Partial,
            abi: None,
            encoding: Some(InstructionEncoding {
                architecture: "arm64".to_string(),
                mnemonic: "ld4".to_string(),
                disassembly: "ld4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x3]".to_string(),
                address: 0x4010,
                bytes: vec![0x60, 0x00, 0x40, 0x4c],
            }),
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::FallThrough,
            diagnostics: vec![SemanticDiagnostic {
                kind: SemanticDiagnosticKind::UnsupportedInstruction,
                message: "arm64 encoding passthrough".to_string(),
            }],
        };

        lifter.lift_semantics(&semantics).expect("lift semantics");
        let text = lifter.text();

        assert!(text.contains("declare void @binlex_encoding_ld4(ptr)"));
        assert!(text.contains("@binlex_encoding_ld4_4010"));
        assert!(text.contains("c\"arm64\\00\""));
        assert!(text.contains("c\"ld4\\00\""));
        assert!(text.contains("ld4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x3]"));
        assert!(text.contains("call void @binlex_encoding_ld4(ptr @binlex_encoding_ld4_4010)"));
    }

    #[test]
    fn omits_instruction_encoding_for_complete_semantics() {
        let mut lifter = Lifter::new(Architecture::AMD64, Config::default());
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: Some(InstructionEncoding {
                architecture: "amd64".to_string(),
                mnemonic: "xor".to_string(),
                disassembly: "xor al, 0x4d".to_string(),
                address: 0x4010,
                bytes: vec![0x34, 0x4d],
            }),
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        lifter.lift_semantics(&semantics).expect("lift semantics");
        let text = lifter.text();

        assert!(!text.contains("@binlex_encoding_xor("));
        assert!(!text.contains("@binlex_encoding_xor_4010"));
        assert!(text.contains("call void asm sideeffect \"nop\""));
    }

    #[test]
    fn lifted_function_uses_native_cfg_without_terminator_helpers() {
        let bytes = [
            0xa2, 0x02, 0x80, 0x52, 0x42, 0x54, 0x00, 0x11, 0x5f, 0xa8, 0x00, 0x71, 0x60, 0x00,
            0x00, 0x54, 0x60, 0x0c, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x00, 0x80, 0x52,
            0x00, 0x24, 0x00, 0x11, 0xc0, 0x03, 0x5f, 0xd6,
        ];

        let config = Config::default();
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

        let mut lifter = Lifter::new(Architecture::ARM64, config);
        lifter.lift_function(&function).expect("lift function");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("br i1"));
        assert!(!text.contains("@binlex_term_branch("));
        assert!(!text.contains("@binlex_term_jump("));
    }

    #[test]
    fn arm64_sysv_abi_lifted_function_returns_i64() {
        let config = Config::default();
        let mut semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::SysV));

        let mut lifter = Lifter::new(Architecture::ARM64, config);
        lifter.lift_semantics(&semantics).expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i64"));
        assert!(text.contains("@semantics_0("));
        assert!(text.contains("ret i64"));
        assert!(!text.contains("ret void"));
    }

    #[test]
    fn amd64_windows64_abi_lifted_function_returns_i64() {
        let config = Config::default();
        let mut semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::Windows64));

        let mut lifter = Lifter::new(Architecture::AMD64, config);
        lifter.lift_semantics(&semantics).expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i64"));
        assert!(text.contains("@semantics_0("));
        assert!(text.contains("ret i64"));
        assert!(!text.contains("ret void"));
    }
}
