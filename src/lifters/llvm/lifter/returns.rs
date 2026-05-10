use super::LoweringContext;
use super::helpers::render_location;
use crate::semantics::SemanticLocation;
use inkwell::values::IntValue;
use std::io::Error;

impl<'ctx, 'm> LoweringContext<'ctx, 'm> {
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

    pub(super) fn emit_abi_return(&mut self) -> Result<bool, Error> {
        if self.abi.is_some()
            && self.function.get_type().get_return_type().is_some()
            && self
                .abi
                .as_ref()
                .and_then(|abi| abi.function_return_bits)
                .is_some()
        {
            let value = self.abi_return_value()?;
            self.builder
                .build_return(Some(&value))
                .map_err(|err| Error::other(err.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn abi_return_value(&mut self) -> Result<IntValue<'ctx>, Error> {
        let return_bits = self
            .abi
            .as_ref()
            .and_then(|abi| abi.function_return_bits)
            .unwrap_or(64);
        let return_type = self.int_type(return_bits);
        if let Some(abi) = &self.abi {
            for location in &abi.return_locations {
                let SemanticLocation::Register { bits, .. } = location else {
                    continue;
                };
                let key = render_location(location);
                if let Some(slot) = self.slots.get(&key) {
                    let value = self
                        .builder
                        .build_load(self.int_type(*bits), *slot, "abi_ret")
                        .map_err(|err| Error::other(err.to_string()))?
                        .into_int_value();
                    if *bits == return_bits {
                        return Ok(value);
                    }
                    let coerced = if *bits < return_bits {
                        self.builder
                            .build_int_z_extend(value, return_type, "abi_ret_zext")
                            .map_err(|err| Error::other(err.to_string()))?
                    } else {
                        self.builder
                            .build_int_truncate(value, return_type, "abi_ret_trunc")
                            .map_err(|err| Error::other(err.to_string()))?
                    };
                    return Ok(coerced);
                }
            }
        }
        Ok(return_type.const_zero())
    }
}
