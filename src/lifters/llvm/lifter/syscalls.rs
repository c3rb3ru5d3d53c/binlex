use super::LoweringContext;
use super::helpers::{render_location, render_trap_kind};
use crate::lifters::llvm::abi::coerce_int_value_width;
use crate::semantics::{SemanticExpression, SemanticLocation, SemanticTrapKind};
use crate::{Abi, Architecture};
use inkwell::values::IntValue;
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn lower_native_trap(&mut self, kind: &SemanticTrapKind) -> Result<(), Error> {
        match (kind, self.current_semantics_abi, self.architecture) {
            (SemanticTrapKind::Syscall, Some(Abi::LinuxSyscall), Architecture::ARM64) => {
                self.emit_arm64_linux_syscall_native()
            }
            (SemanticTrapKind::Syscall, Some(Abi::WindowsSyscall), Architecture::ARM64) => {
                self.emit_arm64_windows_syscall_native()
            }
            (SemanticTrapKind::Syscall, Some(Abi::LinuxSyscall), Architecture::AMD64) => {
                self.emit_amd64_linux_syscall_native()
            }
            (SemanticTrapKind::Syscall, Some(Abi::WindowsSyscall), Architecture::AMD64) => {
                self.emit_amd64_windows_syscall_native()
            }
            (SemanticTrapKind::Interrupt, Some(Abi::LinuxSyscall), Architecture::I386) => {
                self.emit_i386_linux_syscall_native()
            }
            (SemanticTrapKind::Interrupt, Some(Abi::WindowsSyscall), Architecture::I386) => {
                self.emit_i386_windows_syscall_native()
            }
            (
                SemanticTrapKind::ArchSpecific { name },
                Some(Abi::LinuxSyscall),
                Architecture::I386,
            ) if name == "x86.sysenter" => self.emit_i386_linux_sysenter_native(),
            (
                SemanticTrapKind::ArchSpecific { name },
                Some(Abi::WindowsSyscall),
                Architecture::I386,
            ) if name == "x86.sysenter" => self.emit_i386_windows_sysenter_native(),
            _ => Err(Error::other(format!(
                "unsupported native trap lowering: kind={} abi={} architecture={}",
                render_trap_kind(kind),
                self.current_semantics_abi
                    .map(|abi| abi.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                self.architecture
            ))),
        }
    }

    fn emit_arm64_linux_syscall_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap syscall lowered as native arm64 linux syscall",
        );
        let i64_type = self.context.i64_type();
        let fn_type = i64_type.fn_type(
            &[
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
            ],
            false,
        );
        let asm = self.context.create_inline_asm(
            fn_type,
            "svc #0".to_string(),
            "={x0},{x0},{x1},{x2},{x3},{x4},{x5},{x8},~{memory},~{dirflag},~{fpsr},~{flags}"
                .to_string(),
            true,
            false,
            None,
            false,
        );
        let x0 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::linux_syscall::X0_SEMANTIC_NAME,
            )?
            .into();
        let x1 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::linux_syscall::X1_SEMANTIC_NAME,
            )?
            .into();
        let x2 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::linux_syscall::X2_SEMANTIC_NAME,
            )?
            .into();
        let x3 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::linux_syscall::X3_SEMANTIC_NAME,
            )?
            .into();
        let x4 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::linux_syscall::X4_SEMANTIC_NAME,
            )?
            .into();
        let x5 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::linux_syscall::X5_SEMANTIC_NAME,
            )?
            .into();
        let x8 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::linux_syscall::X8_SEMANTIC_NAME,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[x0, x1, x2, x3, x4, x5, x8], "linux_syscall")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected arm64 linux syscall return value"))?
            .into_int_value();
        self.store_arm64_syscall_result(
            crate::lifters::llvm::abi::arm64::linux_syscall::X0_SEMANTIC_NAME,
            crate::lifters::llvm::abi::arm64::linux_syscall::W0_SEMANTIC_NAME,
            result,
        )
    }

    fn emit_arm64_windows_syscall_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap syscall lowered as native arm64 windows syscall",
        );
        let i64_type = self.context.i64_type();
        let fn_type = i64_type.fn_type(
            &[
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
            ],
            false,
        );
        let asm = self.context.create_inline_asm(
            fn_type,
            "svc #0".to_string(),
            "={x0},{x0},{x1},{x2},{x3},{x4},{x5},{x6},{x7},{x8},~{memory},~{dirflag},~{fpsr},~{flags}"
                .to_string(),
            true,
            false,
            None,
            false,
        );
        let x0 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X0_SEMANTIC_NAME,
            )?
            .into();
        let x1 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X1_SEMANTIC_NAME,
            )?
            .into();
        let x2 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X2_SEMANTIC_NAME,
            )?
            .into();
        let x3 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X3_SEMANTIC_NAME,
            )?
            .into();
        let x4 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X4_SEMANTIC_NAME,
            )?
            .into();
        let x5 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X5_SEMANTIC_NAME,
            )?
            .into();
        let x6 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X6_SEMANTIC_NAME,
            )?
            .into();
        let x7 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X7_SEMANTIC_NAME,
            )?
            .into();
        let x8 = self
            .load_native_syscall_register(
                crate::lifters::llvm::abi::arm64::windows_syscall::X8_SEMANTIC_NAME,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(
                fn_type,
                asm,
                &[x0, x1, x2, x3, x4, x5, x6, x7, x8],
                "windows_syscall",
            )
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected arm64 windows syscall return value"))?
            .into_int_value();
        self.store_arm64_syscall_result(
            crate::lifters::llvm::abi::arm64::windows_syscall::X0_SEMANTIC_NAME,
            crate::lifters::llvm::abi::arm64::windows_syscall::W0_SEMANTIC_NAME,
            result,
        )
    }

    fn emit_amd64_linux_syscall_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap syscall lowered as native amd64 linux syscall",
        );
        let i64_type = self.context.i64_type();
        let fn_type = i64_type.fn_type(
            &[
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
            ],
            false,
        );
        let asm = self.context.create_inline_asm(
            fn_type,
            "syscall".to_string(),
            "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},~{rcx},~{r11},~{memory},~{dirflag},~{fpsr},~{flags}"
                .to_string(),
            true,
            false,
            None,
            false,
        );
        let rax = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::amd64::RAX_SEMANTIC_NAME,
                64,
            )?
            .into();
        let rdi = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::amd64::RDI_SEMANTIC_NAME,
                64,
            )?
            .into();
        let rsi = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::amd64::RSI_SEMANTIC_NAME,
                64,
            )?
            .into();
        let rdx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::amd64::RDX_SEMANTIC_NAME,
                64,
            )?
            .into();
        let r10 = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::amd64::R10_SEMANTIC_NAME,
                64,
            )?
            .into();
        let r8 = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::amd64::R8_SEMANTIC_NAME,
                64,
            )?
            .into();
        let r9 = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::amd64::R9_SEMANTIC_NAME,
                64,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(
                fn_type,
                asm,
                &[rax, rdi, rsi, rdx, r10, r8, r9],
                "linux_syscall",
            )
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected amd64 linux syscall return value"))?
            .into_int_value();
        self.store_native_syscall_result(
            crate::lifters::llvm::abi::x86::linux_syscall::amd64::RAX_SEMANTIC_NAME,
            64,
            result,
        )
    }

    fn emit_amd64_windows_syscall_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap syscall lowered as native amd64 windows syscall",
        );
        let i64_type = self.context.i64_type();
        let fn_type = i64_type.fn_type(
            &[
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
                i64_type.into(),
            ],
            false,
        );
        let asm = self.context.create_inline_asm(
            fn_type,
            "syscall".to_string(),
            "={rax},{rax},{r10},{rdx},{r8},{r9},~{rcx},~{r11},~{memory},~{dirflag},~{fpsr},~{flags}"
                .to_string(),
            true,
            false,
            None,
            false,
        );
        let rax = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::amd64::RAX_SEMANTIC_NAME,
                64,
            )?
            .into();
        let r10 = self.load_amd64_windows_syscall_r10()?.into();
        let rdx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::amd64::RDX_SEMANTIC_NAME,
                64,
            )?
            .into();
        let r8 = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::amd64::R8_SEMANTIC_NAME,
                64,
            )?
            .into();
        let r9 = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::amd64::R9_SEMANTIC_NAME,
                64,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[rax, r10, rdx, r8, r9], "windows_syscall")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected amd64 windows syscall return value"))?
            .into_int_value();
        self.store_native_syscall_result(
            crate::lifters::llvm::abi::x86::windows_syscall::amd64::RAX_SEMANTIC_NAME,
            64,
            result,
        )
    }

    fn load_amd64_windows_syscall_r10(&mut self) -> Result<IntValue<'ctx>, Error> {
        let r10_location = SemanticLocation::Register {
            name: crate::lifters::llvm::abi::x86::windows_syscall::amd64::R10_SEMANTIC_NAME
                .to_string(),
            bits: 64,
        };
        let r10_key = render_location(&r10_location);
        if self.written_locations.contains(&r10_key) {
            return self.load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::amd64::R10_SEMANTIC_NAME,
                64,
            );
        }

        let rcx_location = SemanticLocation::Register {
            name: crate::lifters::llvm::abi::x86::windows_syscall::amd64::RCX_SEMANTIC_NAME
                .to_string(),
            bits: 64,
        };
        let rcx_key = render_location(&rcx_location);
        if let Some(slot) = self.slots.get(&rcx_key) {
            return self
                .builder
                .build_load(self.context.i64_type(), *slot, "windows_syscall_rcx_as_r10")
                .map_err(|err| Error::other(err.to_string()))
                .map(|value| value.into_int_value());
        }

        Ok(self.context.i64_type().const_zero())
    }

    fn emit_i386_linux_syscall_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap interrupt lowered as native i386 linux syscall",
        );
        let i32_type = self.context.i32_type();
        let fn_type = i32_type.fn_type(
            &[
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
            ],
            false,
        );
        let asm = self.context.create_inline_asm(
            fn_type,
            "int $$0x80".to_string(),
            "={eax},{eax},{ebx},{ecx},{edx},{esi},{edi},{ebp},~{memory},~{dirflag},~{fpsr},~{flags}"
                .to_string(),
            true,
            false,
            None,
            false,
        );
        let eax = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EAX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let ebx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EBX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let ecx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::ECX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let edx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EDX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let esi = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::ESI_SEMANTIC_NAME,
                32,
            )?
            .into();
        let edi = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EDI_SEMANTIC_NAME,
                32,
            )?
            .into();
        let ebp = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EBP_SEMANTIC_NAME,
                32,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(
                fn_type,
                asm,
                &[eax, ebx, ecx, edx, esi, edi, ebp],
                "linux_syscall",
            )
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected i386 linux syscall return value"))?
            .into_int_value();
        self.store_native_syscall_result(
            crate::lifters::llvm::abi::x86::linux_syscall::i386::EAX_SEMANTIC_NAME,
            32,
            result,
        )
    }

    fn emit_i386_windows_syscall_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap interrupt lowered as native i386 windows syscall",
        );
        let i32_type = self.context.i32_type();
        let fn_type = i32_type.fn_type(&[i32_type.into(), i32_type.into()], false);
        let asm = self.context.create_inline_asm(
            fn_type,
            "int $$0x2e".to_string(),
            "={eax},{eax},{edx},~{memory},~{dirflag},~{fpsr},~{flags}".to_string(),
            true,
            false,
            None,
            false,
        );
        let eax = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::i386::EAX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let edx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::i386::EDX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[eax, edx], "windows_syscall")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected i386 windows syscall return value"))?
            .into_int_value();
        self.store_native_syscall_result(
            crate::lifters::llvm::abi::x86::windows_syscall::i386::EAX_SEMANTIC_NAME,
            32,
            result,
        )
    }

    fn emit_i386_linux_sysenter_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap x86.sysenter lowered as native i386 linux sysenter",
        );
        let i32_type = self.context.i32_type();
        let fn_type = i32_type.fn_type(
            &[
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
            ],
            false,
        );
        let asm = self.context.create_inline_asm(
            fn_type,
            "sysenter".to_string(),
            "={eax},{eax},{ebx},{ecx},{edx},{esi},{edi},{ebp},~{memory},~{dirflag},~{fpsr},~{flags}"
                .to_string(),
            true,
            false,
            None,
            false,
        );
        let eax = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EAX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let ebx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EBX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let ecx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::ECX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let edx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EDX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let esi = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::ESI_SEMANTIC_NAME,
                32,
            )?
            .into();
        let edi = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EDI_SEMANTIC_NAME,
                32,
            )?
            .into();
        let ebp = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::linux_syscall::i386::EBP_SEMANTIC_NAME,
                32,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(
                fn_type,
                asm,
                &[eax, ebx, ecx, edx, esi, edi, ebp],
                "linux_sysenter",
            )
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected i386 linux sysenter return value"))?
            .into_int_value();
        self.store_native_syscall_result(
            crate::lifters::llvm::abi::x86::linux_syscall::i386::EAX_SEMANTIC_NAME,
            32,
            result,
        )
    }

    fn emit_i386_windows_sysenter_native(&mut self) -> Result<(), Error> {
        self.record_semantic_lowering(
            "effect_native",
            "Trap x86.sysenter lowered as native i386 windows syscall",
        );
        let i32_type = self.context.i32_type();
        let fn_type = i32_type.fn_type(&[i32_type.into(), i32_type.into(), i32_type.into()], false);
        let asm = self.context.create_inline_asm(
            fn_type,
            "sysenter".to_string(),
            "={eax},{eax},{ecx},{edx},~{memory},~{dirflag},~{fpsr},~{flags}".to_string(),
            true,
            false,
            None,
            false,
        );
        let eax = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::i386::EAX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let ecx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::i386::ECX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let edx = self
            .load_native_syscall_register_bits(
                crate::lifters::llvm::abi::x86::windows_syscall::i386::EDX_SEMANTIC_NAME,
                32,
            )?
            .into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[eax, ecx, edx], "windows_sysenter")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected i386 windows sysenter return value"))?
            .into_int_value();
        self.store_native_syscall_result(
            crate::lifters::llvm::abi::x86::windows_syscall::i386::EAX_SEMANTIC_NAME,
            32,
            result,
        )
    }

    fn load_native_syscall_register(&mut self, name: &str) -> Result<IntValue<'ctx>, Error> {
        self.load_native_syscall_register_bits(name, 64)
    }

    fn load_native_syscall_register_bits(
        &mut self,
        name: &str,
        bits: u16,
    ) -> Result<IntValue<'ctx>, Error> {
        let location = SemanticLocation::Register {
            name: name.to_string(),
            bits,
        };
        let key = render_location(&location);
        if let Some(slot) = self.slots.get(&key) {
            return self
                .builder
                .build_load(self.int_type(bits), *slot, "linux_syscall_arg")
                .map_err(|err| Error::other(err.to_string()))
                .map(|value| value.into_int_value());
        }
        Ok(self.int_type(bits).const_zero())
    }

    fn store_arm64_syscall_result(
        &mut self,
        x0_name: &str,
        w0_name: &str,
        result: IntValue<'ctx>,
    ) -> Result<(), Error> {
        let x0_location = SemanticLocation::Register {
            name: x0_name.to_string(),
            bits: 64,
        };
        let x0_slot = self.slot_for_location(&x0_location)?;
        self.builder
            .build_store(x0_slot, result)
            .map_err(|err| Error::other(err.to_string()))?;
        self.written_locations.insert(render_location(&x0_location));

        let w0_location = SemanticLocation::Register {
            name: w0_name.to_string(),
            bits: 32,
        };
        let w0_slot = self.slot_for_location(&w0_location)?;
        let truncated = self
            .builder
            .build_int_truncate(result, self.context.i32_type(), "linux_syscall_w0")
            .map_err(|err| Error::other(err.to_string()))?;
        self.builder
            .build_store(w0_slot, truncated)
            .map_err(|err| Error::other(err.to_string()))?;
        self.written_locations.insert(render_location(&w0_location));
        Ok(())
    }

    fn store_native_syscall_result(
        &mut self,
        name: &str,
        bits: u16,
        result: IntValue<'ctx>,
    ) -> Result<(), Error> {
        let location = SemanticLocation::Register {
            name: name.to_string(),
            bits,
        };
        let slot = self.slot_for_location(&location)?;
        let value = coerce_int_value_width(
            &self.builder,
            result,
            self.int_type(bits),
            "linux_syscall_result_zext",
            "linux_syscall_result_trunc",
        )?;
        self.builder
            .build_store(slot, value)
            .map_err(|err| Error::other(err.to_string()))?;
        self.written_locations.insert(render_location(&location));
        Ok(())
    }

    pub(super) fn const_return_adjust(expression: &SemanticExpression) -> Option<u16> {
        match expression {
            SemanticExpression::Const { value, .. } => u16::try_from(*value).ok(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lifters::llvm::Abi;
    use crate::lifters::llvm::Lifter;
    use crate::semantics::{
        Semantic, SemanticEffect, SemanticExpression, SemanticLocation, SemanticStatus,
        SemanticTerminator, SemanticTrapKind,
    };
    use crate::{Architecture, Configuration};

    #[test]
    fn arm64_linux_syscall_native_lowering_emits_svc_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::LinuxSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::arm64::linux_syscall::X0_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const { value: 1, bits: 64 },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::arm64::linux_syscall::X1_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x620000,
                        bits: 64,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::arm64::linux_syscall::X2_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 14,
                        bits: 64,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::arm64::linux_syscall::X8_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 64,
                        bits: 64,
                    },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::LinuxSyscall));

        let mut lifter = Lifter::new(Architecture::ARM64, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"svc #0\""));
        assert!(!text.contains("@binlex_trap_syscall"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn amd64_linux_syscall_native_lowering_emits_syscall_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::LinuxSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name:
                            crate::lifters::llvm::abi::x86::linux_syscall::amd64::RAX_SEMANTIC_NAME
                                .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const { value: 1, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::LinuxSyscall));

        let mut lifter = Lifter::new(Architecture::AMD64, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"syscall\""));
        assert!(!text.contains("@binlex_trap_syscall"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn amd64_windows_syscall_native_lowering_emits_syscall_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::WindowsSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::x86::windows_syscall::amd64::RAX_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const { value: 0x55, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::WindowsSyscall));

        let mut lifter = Lifter::new(Architecture::AMD64, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"syscall\""));
        assert!(!text.contains("@binlex_trap_syscall"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn amd64_windows_syscall_preserves_r10_from_rcx_prep_semantics() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::WindowsSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: "rcx".to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x1122_3344_5566_7788,
                        bits: 64,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::x86::windows_syscall::amd64::R10_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rcx".to_string(),
                            bits: 64,
                        },
                    )),
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::x86::windows_syscall::amd64::RAX_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const { value: 0x55, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::WindowsSyscall));

        let mut lifter = Lifter::new(Architecture::AMD64, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("store i64 1234605616436508552"));
        assert!(text.contains("%readtmp"));
        assert!(text.contains("store i64 %readtmp"));
        assert!(text.contains("asm sideeffect \"syscall\""));
        assert!(text.contains("{r10}"));
    }

    #[test]
    fn amd64_windows_syscall_uses_rcx_for_r10_when_prep_is_missing() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::WindowsSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::x86::windows_syscall::amd64::RCX_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x1122_3344_5566_7788,
                        bits: 64,
                    },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::x86::windows_syscall::amd64::RAX_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const { value: 0x55, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::WindowsSyscall));

        let mut lifter = Lifter::new(Architecture::AMD64, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"syscall\""));
        assert!(text.contains("{r10}"));
        assert!(text.contains("windows_syscall_rcx_as_r10"));
    }

    #[test]
    fn i386_linux_syscall_native_lowering_emits_int_0x80_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::LinuxSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name:
                            crate::lifters::llvm::abi::x86::linux_syscall::i386::EAX_SEMANTIC_NAME
                                .to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::Const { value: 4, bits: 32 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Interrupt,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::LinuxSyscall));

        let mut lifter = Lifter::new(Architecture::I386, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"int $$0x80\""));
        assert!(!text.contains("@binlex_trap_interrupt"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn i386_windows_syscall_native_lowering_emits_int_0x2e_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::WindowsSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name:
                            crate::lifters::llvm::abi::x86::windows_syscall::i386::EAX_SEMANTIC_NAME
                                .to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x55,
                        bits: 32,
                    },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Interrupt,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::WindowsSyscall));

        let mut lifter = Lifter::new(Architecture::I386, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"int $$0x2e\""));
        assert!(!text.contains("@binlex_trap_interrupt"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn i386_linux_sysenter_native_lowering_emits_sysenter_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::LinuxSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name:
                            crate::lifters::llvm::abi::x86::linux_syscall::i386::EAX_SEMANTIC_NAME
                                .to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::Const { value: 4, bits: 32 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::ArchSpecific {
                        name: "x86.sysenter".to_string(),
                    },
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::LinuxSyscall));

        let mut lifter = Lifter::new(Architecture::I386, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"sysenter\""));
        assert!(!text.contains("@binlex_trap_x86_sysenter"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn i386_windows_sysenter_native_lowering_emits_sysenter_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::WindowsSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name:
                            crate::lifters::llvm::abi::x86::windows_syscall::i386::EAX_SEMANTIC_NAME
                                .to_string(),
                        bits: 32,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x55,
                        bits: 32,
                    },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::ArchSpecific {
                        name: "x86.sysenter".to_string(),
                    },
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::WindowsSyscall));

        let mut lifter = Lifter::new(Architecture::I386, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"sysenter\""));
        assert!(!text.contains("@binlex_trap_x86_sysenter"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn arm64_windows_syscall_native_lowering_emits_svc_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(Abi::WindowsSyscall),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::arm64::windows_syscall::X0_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const { value: 1, bits: 64 },
                },
                SemanticEffect::Set {
                    dst: SemanticLocation::Register {
                        name: crate::lifters::llvm::abi::arm64::windows_syscall::X8_SEMANTIC_NAME
                            .to_string(),
                        bits: 64,
                    },
                    expression: SemanticExpression::Const {
                        value: 0x55,
                        bits: 64,
                    },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(Abi::WindowsSyscall));

        let mut lifter = Lifter::new(Architecture::ARM64, Configuration::default());
        lifter
            .lift_semantics(std::slice::from_ref(&semantics))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"svc #0\""));
        assert!(!text.contains("@binlex_trap_syscall"));
        assert!(!text.contains("@binlex_term_trap"));
    }
}
