use super::LoweringContext;
use super::helpers::render_location;
use crate::Abi;
use crate::semantics::SemanticLocation;
use inkwell::values::IntValue;
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn emit_body_marker_if_needed(&mut self, emit_marker: bool) -> Result<(), Error> {
        if !self.body_begin_emitted {
            if emit_marker {
                self.emit_body_marker("body_begin")?;
            }
            self.body_begin_emitted = true;
        }
        Ok(())
    }

    pub(super) fn emit_body_marker(&self, _suffix: &str) -> Result<(), Error> {
        let fn_ty = self.context.void_type().fn_type(&[], false);
        let asm = self.context.create_inline_asm(
            fn_ty,
            "nop".to_string(),
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

    pub(super) fn emit_native_return(&self, adjust: u16) -> Result<(), Error> {
        if adjust == 0 {
            self.emit_default_return()?;
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

    pub(super) fn emit_default_return(&self) -> Result<(), Error> {
        if self.function.get_type().get_return_type().is_some() {
            self.builder
                .build_return(Some(&self.context.i64_type().const_zero()))
                .map_err(|err| Error::other(err.to_string()))?;
        } else {
            self.builder
                .build_return(None)
                .map_err(|err| Error::other(err.to_string()))?;
        }
        Ok(())
    }

    pub(super) fn emit_abi_return(&mut self) -> Result<bool, Error> {
        match (self.abi, self.function.get_type().get_return_type()) {
            (Some(Abi::SysV), Some(_))
                if self.module.get_triple().as_str().to_str() == Ok("aarch64-unknown-unknown") =>
            {
                let value = self.arm64_sysv_return_value()?;
                self.builder
                    .build_return(Some(&value))
                    .map_err(|err| Error::other(err.to_string()))?;
                Ok(true)
            }
            (Some(Abi::Windows64), Some(_))
                if self.module.get_triple().as_str().to_str() == Ok("x86_64-unknown-unknown") =>
            {
                let value = self.amd64_windows64_return_value()?;
                self.builder
                    .build_return(Some(&value))
                    .map_err(|err| Error::other(err.to_string()))?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn arm64_sysv_return_value(&mut self) -> Result<IntValue<'ctx>, Error> {
        let x0_location = SemanticLocation::Register {
            name: crate::lifters::llvm::abi::arm64::sysv::X0_RETURN_SEMANTIC_NAME.to_string(),
            bits: 64,
        };
        let x0_key = render_location(&x0_location);
        if let Some(slot) = self.slots.get(&x0_key) {
            let value = self
                .builder
                .build_load(self.context.i64_type(), *slot, "abi_ret_x0")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value();
            return Ok(value);
        }

        let w0_location = SemanticLocation::Register {
            name: crate::lifters::llvm::abi::arm64::sysv::W0_RETURN_SEMANTIC_NAME.to_string(),
            bits: 32,
        };
        let w0_key = render_location(&w0_location);
        if let Some(slot) = self.slots.get(&w0_key) {
            let value = self
                .builder
                .build_load(self.context.i32_type(), *slot, "abi_ret_w0")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value();
            let widened = self
                .builder
                .build_int_z_extend(value, self.context.i64_type(), "abi_ret_w0_zext")
                .map_err(|err| Error::other(err.to_string()))?;
            return Ok(widened);
        }

        Ok(self.context.i64_type().const_zero())
    }

    fn amd64_windows64_return_value(&mut self) -> Result<IntValue<'ctx>, Error> {
        let rax_location = SemanticLocation::Register {
            name: crate::lifters::llvm::abi::x86::windows64::RAX_RETURN_SEMANTIC_NAME.to_string(),
            bits: 64,
        };
        let rax_key = render_location(&rax_location);
        if let Some(slot) = self.slots.get(&rax_key) {
            let value = self
                .builder
                .build_load(self.context.i64_type(), *slot, "abi_ret_rax")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value();
            return Ok(value);
        }

        let eax_location = SemanticLocation::Register {
            name: crate::lifters::llvm::abi::x86::windows64::EAX_RETURN_SEMANTIC_NAME.to_string(),
            bits: 32,
        };
        let eax_key = render_location(&eax_location);
        if let Some(slot) = self.slots.get(&eax_key) {
            let value = self
                .builder
                .build_load(self.context.i32_type(), *slot, "abi_ret_eax")
                .map_err(|err| Error::other(err.to_string()))?
                .into_int_value();
            let widened = self
                .builder
                .build_int_z_extend(value, self.context.i64_type(), "abi_ret_eax_zext")
                .map_err(|err| Error::other(err.to_string()))?;
            return Ok(widened);
        }

        Ok(self.context.i64_type().const_zero())
    }
}
