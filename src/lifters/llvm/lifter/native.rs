use super::LoweringContext;
use super::helpers::coerce_int_value_width;
use super::helpers::render_location;
use crate::semantics::SemanticLocation;
use inkwell::attributes::AttributeLoc;
use inkwell::values::IntValue;
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    fn write_native_register(
        &self,
        register: &str,
        bits: u16,
        value: IntValue<'ctx>,
    ) -> Result<(), Error> {
        let ty = self.int_type(bits);
        let value =
            coerce_int_value_width(&self.builder, value, ty, "regwrite_zext", "regwrite_trunc")?;
        if bits == 128 && register.starts_with("xmm") {
            let slot = self.build_entry_alloca(ty, "regwrite_xmm_slot")?;
            self.builder
                .build_store(slot, value)
                .map_err(|err| Error::other(err.to_string()))?;
            let fn_ty = self.context.void_type().fn_type(
                &[self
                    .context
                    .ptr_type(inkwell::AddressSpace::default())
                    .into()],
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
            let fn_ty = self.context.void_type().fn_type(
                &[self
                    .context
                    .ptr_type(inkwell::AddressSpace::default())
                    .into()],
                false,
            );
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
        let fn_ty = self.context.void_type().fn_type(&[ty.into()], false);
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
        let fn_ty = self.context.void_type().fn_type(
            &[self
                .context
                .ptr_type(inkwell::AddressSpace::default())
                .into()],
            false,
        );
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

    pub(super) fn sync_slots_to_architecture(&self) -> Result<(), Error> {
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
            let Some(SemanticLocation::Register { name, bits }) = self.slot_locations.get(key)
            else {
                continue;
            };
            if self.uses_pure_callable_abi()
                && self.is_callable_abi_boundary_location(&SemanticLocation::Register {
                    name: name.clone(),
                    bits: *bits,
                })
            {
                continue;
            }
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
            && ["cf", "pf", "af", "zf", "sf", "if", "df", "of"]
                .iter()
                .any(|flag| {
                    self.written_locations
                        .contains(&render_location(&SemanticLocation::Flag {
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
            64 if name == "r8" => Some("r8"),
            64 if name == "r9" => Some("r9"),
            64 if name == "r10" => Some("r10"),
            64 if name == "rsp" => Some("rsp"),
            64 if name == "rbp" => Some("rbp"),
            128 if name == "xmm0" => Some("xmm0"),
            128 if name == "xmm1" => Some("xmm1"),
            128 if name == "xmm2" => Some("xmm2"),
            _ => None,
        }
    }

    pub(super) fn x86_parent_register_alias(
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
}
