use super::LoweringContext;
use super::helpers::{coerce_int_value_width, render_location, render_trap_kind};
use crate::semantics::{
    SemanticAbiTrap, SemanticCpuKind, SemanticExpression, SemanticLocation, SemanticTrapKind,
};
use crate::Architecture;
use inkwell::values::IntValue;
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn lower_native_trap(&mut self, kind: &SemanticTrapKind) -> Result<(), Error> {
        match (
            kind,
            self.current_semantics_abi.as_ref(),
            self.architecture,
        ) {
            (SemanticTrapKind::Syscall, Some(abi), Architecture::ARM64)
                if abi.is_linux_syscall() =>
            {
                self.emit_arm64_linux_syscall_native()
            }
            (SemanticTrapKind::Syscall, Some(abi), Architecture::ARM64)
                if abi.is_windows_syscall() =>
            {
                self.emit_arm64_windows_syscall_native()
            }
            (SemanticTrapKind::Syscall, Some(abi), Architecture::AMD64)
                if abi.is_linux_syscall() =>
            {
                self.emit_amd64_linux_syscall_native()
            }
            (SemanticTrapKind::Syscall, Some(abi), Architecture::AMD64)
                if abi.is_windows_syscall() =>
            {
                self.emit_amd64_windows_syscall_native()
            }
            (SemanticTrapKind::Interrupt, Some(abi), Architecture::I386)
                if abi.is_linux_syscall() =>
            {
                self.emit_i386_linux_syscall_native()
            }
            (SemanticTrapKind::Interrupt, Some(abi), Architecture::I386)
                if abi.is_windows_syscall() =>
            {
                self.emit_i386_windows_syscall_native()
            }
            (SemanticTrapKind::Named { name }, Some(abi), Architecture::I386)
                if name == "x86.sysenter" && abi.is_linux_syscall() =>
            {
                self.emit_i386_linux_sysenter_native()
            }
            (SemanticTrapKind::Named { name }, Some(abi), Architecture::I386)
                if name == "x86.sysenter" && abi.is_windows_syscall() =>
            {
                self.emit_i386_windows_sysenter_native()
            }
            _ => Err(Error::other(format!(
                "unsupported native trap lowering: kind={} abi={} architecture={}",
                render_trap_kind(kind),
                self.current_semantics_abi
                    .as_ref()
                    .map(|abi| abi.name.clone())
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
        let syscall_kind = SemanticTrapKind::Syscall;
        let (x0_name, _) = self.trap_argument_name(&syscall_kind, 0)?;
        let (x1_name, _) = self.trap_argument_name(&syscall_kind, 1)?;
        let (x2_name, _) = self.trap_argument_name(&syscall_kind, 2)?;
        let (x3_name, _) = self.trap_argument_name(&syscall_kind, 3)?;
        let (x4_name, _) = self.trap_argument_name(&syscall_kind, 4)?;
        let (x5_name, _) = self.trap_argument_name(&syscall_kind, 5)?;
        let (x8_name, _) = self.trap_number_name(&syscall_kind)?;
        let x0 = self.load_native_syscall_register(&x0_name)?.into();
        let x1 = self.load_native_syscall_register(&x1_name)?.into();
        let x2 = self.load_native_syscall_register(&x2_name)?.into();
        let x3 = self.load_native_syscall_register(&x3_name)?.into();
        let x4 = self.load_native_syscall_register(&x4_name)?.into();
        let x5 = self.load_native_syscall_register(&x5_name)?.into();
        let x8 = self.load_native_syscall_register(&x8_name)?.into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[x0, x1, x2, x3, x4, x5, x8], "linux_syscall")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected arm64 linux syscall return value"))?
            .into_int_value();
        let (result_x0, _) = self.trap_result_name(&syscall_kind, 0)?;
        let (result_w0, _) = self.trap_result_name(&syscall_kind, 1)?;
        self.store_arm64_syscall_result(&result_x0, &result_w0, result)
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
        let syscall_kind = SemanticTrapKind::Syscall;
        let (x0_name, _) = self.trap_argument_name(&syscall_kind, 0)?;
        let (x1_name, _) = self.trap_argument_name(&syscall_kind, 1)?;
        let (x2_name, _) = self.trap_argument_name(&syscall_kind, 2)?;
        let (x3_name, _) = self.trap_argument_name(&syscall_kind, 3)?;
        let (x4_name, _) = self.trap_argument_name(&syscall_kind, 4)?;
        let (x5_name, _) = self.trap_argument_name(&syscall_kind, 5)?;
        let (x6_name, _) = self.trap_argument_name(&syscall_kind, 6)?;
        let (x7_name, _) = self.trap_argument_name(&syscall_kind, 7)?;
        let (x8_name, _) = self.trap_number_name(&syscall_kind)?;
        let x0 = self.load_native_syscall_register(&x0_name)?.into();
        let x1 = self.load_native_syscall_register(&x1_name)?.into();
        let x2 = self.load_native_syscall_register(&x2_name)?.into();
        let x3 = self.load_native_syscall_register(&x3_name)?.into();
        let x4 = self.load_native_syscall_register(&x4_name)?.into();
        let x5 = self.load_native_syscall_register(&x5_name)?.into();
        let x6 = self.load_native_syscall_register(&x6_name)?.into();
        let x7 = self.load_native_syscall_register(&x7_name)?.into();
        let x8 = self.load_native_syscall_register(&x8_name)?.into();
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
        let (result_x0, _) = self.trap_result_name(&syscall_kind, 0)?;
        let (result_w0, _) = self.trap_result_name(&syscall_kind, 1)?;
        self.store_arm64_syscall_result(&result_x0, &result_w0, result)
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
        let syscall_kind = SemanticTrapKind::Syscall;
        let (rax_name, rax_bits) = self.trap_number_name(&syscall_kind)?;
        let (rdi_name, rdi_bits) = self.trap_argument_name(&syscall_kind, 0)?;
        let (rsi_name, rsi_bits) = self.trap_argument_name(&syscall_kind, 1)?;
        let (rdx_name, rdx_bits) = self.trap_argument_name(&syscall_kind, 2)?;
        let (r10_name, r10_bits) = self.trap_argument_name(&syscall_kind, 3)?;
        let (r8_name, r8_bits) = self.trap_argument_name(&syscall_kind, 4)?;
        let (r9_name, r9_bits) = self.trap_argument_name(&syscall_kind, 5)?;
        let rax = self.load_native_syscall_register_bits(&rax_name, rax_bits)?.into();
        let rdi = self.load_native_syscall_register_bits(&rdi_name, rdi_bits)?.into();
        let rsi = self.load_native_syscall_register_bits(&rsi_name, rsi_bits)?.into();
        let rdx = self.load_native_syscall_register_bits(&rdx_name, rdx_bits)?.into();
        let r10 = self.load_native_syscall_register_bits(&r10_name, r10_bits)?.into();
        let r8 = self.load_native_syscall_register_bits(&r8_name, r8_bits)?.into();
        let r9 = self.load_native_syscall_register_bits(&r9_name, r9_bits)?.into();
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
        self.store_native_syscall_result(&rax_name, rax_bits, result)
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
        let syscall_kind = SemanticTrapKind::Syscall;
        let (rax_name, rax_bits) = self.trap_number_name(&syscall_kind)?;
        let (_, rdx_bits) = self.trap_argument_name(&syscall_kind, 0)?;
        let (_, r8_bits) = self.trap_argument_name(&syscall_kind, 1)?;
        let (_, r9_bits) = self.trap_argument_name(&syscall_kind, 2)?;
        let rax = self
            .load_native_syscall_register_bits(&rax_name, rax_bits)?
            .into();
        let r10 = self.load_amd64_windows_syscall_r10()?.into();
        let rdx = self
            .load_native_syscall_register_bits("rdx", rdx_bits)?
            .into();
        let r8 = self
            .load_native_syscall_register_bits("r8", r8_bits)?
            .into();
        let r9 = self
            .load_native_syscall_register_bits("r9", r9_bits)?
            .into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[rax, r10, rdx, r8, r9], "windows_syscall")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected amd64 windows syscall return value"))?
            .into_int_value();
        self.store_native_syscall_result(&rax_name, rax_bits, result)
    }

    fn load_amd64_windows_syscall_r10(&mut self) -> Result<IntValue<'ctx>, Error> {
        let r10_name = self.semantic_register_name("r10")?;
        let r10_location = SemanticLocation::Register {
            name: r10_name.clone(),
            bits: 64,
        };
        let r10_key = render_location(&r10_location);
        if self.written_locations.contains(&r10_key) {
            return self.load_native_syscall_register_bits(&r10_name, 64);
        }

        let rcx_name = self.semantic_register_name("rcx")?;
        let rcx_location = SemanticLocation::Register {
            name: rcx_name,
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
        let interrupt_kind = SemanticTrapKind::Interrupt;
        let (eax_name, eax_bits) = self.trap_number_name(&interrupt_kind)?;
        let (ebx_name, ebx_bits) = self.trap_argument_name(&interrupt_kind, 0)?;
        let (ecx_name, ecx_bits) = self.trap_argument_name(&interrupt_kind, 1)?;
        let (edx_name, edx_bits) = self.trap_argument_name(&interrupt_kind, 2)?;
        let (esi_name, esi_bits) = self.trap_argument_name(&interrupt_kind, 3)?;
        let (edi_name, edi_bits) = self.trap_argument_name(&interrupt_kind, 4)?;
        let (ebp_name, ebp_bits) = self.trap_argument_name(&interrupt_kind, 5)?;
        let eax = self.load_native_syscall_register_bits(&eax_name, eax_bits)?.into();
        let ebx = self.load_native_syscall_register_bits(&ebx_name, ebx_bits)?.into();
        let ecx = self.load_native_syscall_register_bits(&ecx_name, ecx_bits)?.into();
        let edx = self.load_native_syscall_register_bits(&edx_name, edx_bits)?.into();
        let esi = self.load_native_syscall_register_bits(&esi_name, esi_bits)?.into();
        let edi = self.load_native_syscall_register_bits(&edi_name, edi_bits)?.into();
        let ebp = self.load_native_syscall_register_bits(&ebp_name, ebp_bits)?.into();
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
        self.store_native_syscall_result(&eax_name, eax_bits, result)
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
        let interrupt_kind = SemanticTrapKind::Interrupt;
        let (eax_name, eax_bits) = self.trap_number_name(&interrupt_kind)?;
        let (edx_name, edx_bits) = self.trap_argument_name(&interrupt_kind, 0)?;
        let eax = self.load_native_syscall_register_bits(&eax_name, eax_bits)?.into();
        let edx = self.load_native_syscall_register_bits(&edx_name, edx_bits)?.into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[eax, edx], "windows_syscall")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected i386 windows syscall return value"))?
            .into_int_value();
        self.store_native_syscall_result(&eax_name, eax_bits, result)
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
        let sysenter_kind = SemanticTrapKind::Named {
            name: "x86.sysenter".to_string(),
        };
        let (eax_name, eax_bits) = self.trap_number_name(&sysenter_kind)?;
        let (ebx_name, ebx_bits) = self.trap_argument_name(&sysenter_kind, 0)?;
        let (ecx_name, ecx_bits) = self.trap_argument_name(&sysenter_kind, 1)?;
        let (edx_name, edx_bits) = self.trap_argument_name(&sysenter_kind, 2)?;
        let (esi_name, esi_bits) = self.trap_argument_name(&sysenter_kind, 3)?;
        let (edi_name, edi_bits) = self.trap_argument_name(&sysenter_kind, 4)?;
        let (ebp_name, ebp_bits) = self.trap_argument_name(&sysenter_kind, 5)?;
        let eax = self.load_native_syscall_register_bits(&eax_name, eax_bits)?.into();
        let ebx = self.load_native_syscall_register_bits(&ebx_name, ebx_bits)?.into();
        let ecx = self.load_native_syscall_register_bits(&ecx_name, ecx_bits)?.into();
        let edx = self.load_native_syscall_register_bits(&edx_name, edx_bits)?.into();
        let esi = self.load_native_syscall_register_bits(&esi_name, esi_bits)?.into();
        let edi = self.load_native_syscall_register_bits(&edi_name, edi_bits)?.into();
        let ebp = self.load_native_syscall_register_bits(&ebp_name, ebp_bits)?.into();
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
        self.store_native_syscall_result(&eax_name, eax_bits, result)
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
        let sysenter_kind = SemanticTrapKind::Named {
            name: "x86.sysenter".to_string(),
        };
        let (eax_name, eax_bits) = self.trap_number_name(&sysenter_kind)?;
        let (ecx_name, ecx_bits) = self.trap_argument_name(&sysenter_kind, 0)?;
        let (edx_name, edx_bits) = self.trap_argument_name(&sysenter_kind, 1)?;
        let eax = self.load_native_syscall_register_bits(&eax_name, eax_bits)?.into();
        let ecx = self.load_native_syscall_register_bits(&ecx_name, ecx_bits)?.into();
        let edx = self.load_native_syscall_register_bits(&edx_name, edx_bits)?.into();
        let result = self
            .builder
            .build_indirect_call(fn_type, asm, &[eax, ecx, edx], "windows_sysenter")
            .map_err(|err| Error::other(err.to_string()))?
            .try_as_basic_value()
            .basic()
            .ok_or_else(|| Error::other("expected i386 windows sysenter return value"))?
            .into_int_value();
        self.store_native_syscall_result(&eax_name, eax_bits, result)
    }

    fn native_trap_abi(&self, kind: &SemanticTrapKind) -> Result<&SemanticAbiTrap, Error> {
        self.current_semantics_abi
            .as_ref()
            .and_then(|abi| abi.trap(kind))
            .ok_or_else(|| Error::other(format!("missing trap abi for {}", render_trap_kind(kind))))
    }

    fn semantic_register_name(&self, register_name: &str) -> Result<String, Error> {
        let cpu_kind = match self.architecture {
            Architecture::I386 => SemanticCpuKind::I386,
            Architecture::AMD64 => SemanticCpuKind::Amd64,
            Architecture::ARM64 => SemanticCpuKind::Arm64,
            Architecture::CIL => SemanticCpuKind::Cil,
            Architecture::UNKNOWN => {
                return Err(Error::other(
                    "cannot resolve semantic register names for unknown architecture",
                ))
            }
        };
        crate::semantics::cpus::semantic_register_name(cpu_kind, register_name)
            .ok_or_else(|| Error::other(format!("unknown semantic cpu register {register_name}")))
    }

    fn trap_argument_name(
        &self,
        kind: &SemanticTrapKind,
        index: usize,
    ) -> Result<(String, u16), Error> {
        let trap = self.native_trap_abi(kind)?;
        let Some(SemanticLocation::Register { name, bits }) = trap.argument_registers.get(index) else {
            return Err(Error::other(format!(
                "missing trap argument register {} for {}",
                index,
                render_trap_kind(kind)
            )));
        };
        Ok((self.semantic_register_name(name)?, *bits))
    }

    fn trap_number_name(&self, kind: &SemanticTrapKind) -> Result<(String, u16), Error> {
        let trap = self.native_trap_abi(kind)?;
        let Some(SemanticLocation::Register { name, bits }) = trap.number_register.as_ref() else {
            return Err(Error::other(format!(
                "missing trap number register for {}",
                render_trap_kind(kind)
            )));
        };
        Ok((self.semantic_register_name(name)?, *bits))
    }

    fn trap_result_name(
        &self,
        kind: &SemanticTrapKind,
        index: usize,
    ) -> Result<(String, u16), Error> {
        let trap = self.native_trap_abi(kind)?;
        let Some(SemanticLocation::Register { name, bits }) = trap.result_registers.get(index) else {
            return Err(Error::other(format!(
                "missing trap result register {} for {}",
                index,
                render_trap_kind(kind)
            )));
        };
        Ok((self.semantic_register_name(name)?, *bits))
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
    use crate::lifters::llvm::Lifter;
    use crate::semantics::{
        Semantic, SemanticAbi, SemanticAbiKind, SemanticCpu, SemanticCpuKind, SemanticEffect,
        SemanticExpression, SemanticLocation, SemanticStatus, SemanticTerminator,
        SemanticTrapKind,
    };
    use crate::{Architecture, Configuration};

    fn cpu_kind(architecture: Architecture) -> SemanticCpuKind {
        match architecture {
            Architecture::I386 => SemanticCpuKind::I386,
            Architecture::AMD64 => SemanticCpuKind::Amd64,
            Architecture::ARM64 => SemanticCpuKind::Arm64,
            Architecture::CIL => SemanticCpuKind::Cil,
            Architecture::UNKNOWN => panic!("unsupported test architecture"),
        }
    }

    fn builtin_abi(architecture: Architecture, kind: SemanticAbiKind) -> SemanticAbi {
        let cpu = SemanticCpu::from_kind(cpu_kind(architecture)).expect("cpu");
        SemanticAbi::from_kind(kind, &cpu).expect("abi")
    }

    fn semantic_register_location(
        architecture: Architecture,
        register_name: &str,
        bits: u16,
    ) -> SemanticLocation {
        let cpu = SemanticCpu::from_kind(cpu_kind(architecture)).expect("cpu");
        let name = cpu
            .semantic_register_name(register_name)
            .expect("semantic register name");
        SemanticLocation::Register { name, bits }
    }

    #[test]
    fn arm64_linux_syscall_native_lowering_emits_svc_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(builtin_abi(Architecture::ARM64, SemanticAbiKind::LinuxSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::ARM64, "x0", 64),
                    expression: SemanticExpression::Const { value: 1, bits: 64 },
                },
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::ARM64, "x1", 64),
                    expression: SemanticExpression::Const {
                        value: 0x620000,
                        bits: 64,
                    },
                },
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::ARM64, "x2", 64),
                    expression: SemanticExpression::Const {
                        value: 14,
                        bits: 64,
                    },
                },
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::ARM64, "x8", 64),
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
        semantics.set_abi(Some(builtin_abi(Architecture::ARM64, SemanticAbiKind::LinuxSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::ARM64, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::LinuxSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::AMD64, "rax", 64),
                    expression: SemanticExpression::Const { value: 1, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::LinuxSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::AMD64, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"syscall\""));
        assert!(!text.contains("@binlex_trap_syscall"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn explicit_function_abi_does_not_override_embedded_syscall_semantics() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::LinuxSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::AMD64, "rax", 64),
                    expression: SemanticExpression::Const { value: 60, bits: 64 },
                },
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::AMD64, "rdi", 64),
                    expression: SemanticExpression::Const { value: 0, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::LinuxSyscall)));
        let function_abi = builtin_abi(Architecture::AMD64, SemanticAbiKind::SysV);

        let mut lifter = Lifter::from_architecture(Architecture::AMD64, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), Some(&function_abi))
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("define i64 @semantic_function_0("));
        assert!(text.contains("asm sideeffect \"syscall\""));
        assert!(!text.contains("@binlex_trap_syscall"));
        assert!(!text.contains("@binlex_term_trap"));
    }

    #[test]
    fn amd64_windows_syscall_native_lowering_emits_syscall_inline_asm() {
        let mut semantics = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::WindowsSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::AMD64, "rax", 64),
                    expression: SemanticExpression::Const { value: 0x55, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::WindowsSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::AMD64, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::WindowsSyscall)),
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
                    dst: semantic_register_location(Architecture::AMD64, "r10", 64),
                    expression: SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "rcx".to_string(),
                            bits: 64,
                        },
                    )),
                },
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::AMD64, "rax", 64),
                    expression: SemanticExpression::Const { value: 0x55, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::WindowsSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::AMD64, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::WindowsSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::AMD64, "rcx", 64),
                    expression: SemanticExpression::Const {
                        value: 0x1122_3344_5566_7788,
                        bits: 64,
                    },
                },
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::AMD64, "rax", 64),
                    expression: SemanticExpression::Const { value: 0x55, bits: 64 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Syscall,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::AMD64, SemanticAbiKind::WindowsSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::AMD64, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::I386, SemanticAbiKind::LinuxSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::I386, "eax", 32),
                    expression: SemanticExpression::Const { value: 4, bits: 32 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Interrupt,
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::I386, SemanticAbiKind::LinuxSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::I386, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::I386, SemanticAbiKind::WindowsSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::I386, "eax", 32),
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
        semantics.set_abi(Some(builtin_abi(Architecture::I386, SemanticAbiKind::WindowsSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::I386, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::I386, SemanticAbiKind::LinuxSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::I386, "eax", 32),
                    expression: SemanticExpression::Const { value: 4, bits: 32 },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Named {
                        name: "x86.sysenter".to_string(),
                    },
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::I386, SemanticAbiKind::LinuxSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::I386, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::I386, SemanticAbiKind::WindowsSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::I386, "eax", 32),
                    expression: SemanticExpression::Const {
                        value: 0x55,
                        bits: 32,
                    },
                },
                SemanticEffect::Trap {
                    kind: SemanticTrapKind::Named {
                        name: "x86.sysenter".to_string(),
                    },
                },
            ],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        };
        semantics.set_abi(Some(builtin_abi(Architecture::I386, SemanticAbiKind::WindowsSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::I386, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
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
            abi: Some(builtin_abi(Architecture::ARM64, SemanticAbiKind::WindowsSyscall)),
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::ARM64, "x0", 64),
                    expression: SemanticExpression::Const { value: 1, bits: 64 },
                },
                SemanticEffect::Set {
                    dst: semantic_register_location(Architecture::ARM64, "x8", 64),
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
        semantics.set_abi(Some(builtin_abi(Architecture::ARM64, SemanticAbiKind::WindowsSyscall)));

        let mut lifter = Lifter::from_architecture(Architecture::ARM64, Configuration::default());
        lifter
            .lift_function_semantics(std::slice::from_ref(&semantics), None)
            .expect("lift semantics");
        lifter.verify().expect("verify");
        let text = lifter.text();

        assert!(text.contains("asm sideeffect \"svc #0\""));
        assert!(!text.contains("@binlex_trap_syscall"));
        assert!(!text.contains("@binlex_term_trap"));
    }
}
