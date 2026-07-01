use super::LoweringContext;
use super::helpers::coerce_int_value_width;
use crate::Architecture;
use crate::irs::lir::LirLocation;
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
    pub(super) fn native_return_location(&self) -> Option<LirLocation> {
        match self.architecture {
            Architecture::I386 => Some(LirLocation::Register {
                name: "eax".to_string(),
                bits: 32,
            }),
            Architecture::AMD64 => Some(LirLocation::Register {
                name: "rax".to_string(),
                bits: 64,
            }),
            _ => None,
        }
    }

    pub(super) fn emit_native_value_return(&mut self) -> Result<bool, Error> {
        let Some(return_type) = self.function.get_type().get_return_type() else {
            return Ok(false);
        };
        let Some(location) = self.native_return_location() else {
            return Ok(false);
        };
        let slot = self.slot_for_location(&location)?;
        let value = self
            .builder
            .build_load(self.location_type(&location), slot, "native_retval")
            .map_err(|err| Error::other(err.to_string()))?
            .into_int_value();
        let value = coerce_int_value_width(
            &self.builder,
            value,
            return_type.into_int_type(),
            "native_ret_zext",
            "native_ret_trunc",
        )?;
        self.builder
            .build_return(Some(&value))
            .map_err(|err| Error::other(err.to_string()))?;
        Ok(true)
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
        if let Some(return_type) = self.function.get_type().get_return_type() {
            let return_type = return_type.into_int_type();
            self.builder
                .build_return(Some(&return_type.const_zero()))
                .map_err(|err| Error::other(err.to_string()))?;
        } else {
            self.builder
                .build_return(None)
                .map_err(|err| Error::other(err.to_string()))?;
        }
        Ok(())
    }
}
