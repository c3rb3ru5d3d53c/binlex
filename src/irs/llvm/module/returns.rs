use super::LoweringContext;
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
}
