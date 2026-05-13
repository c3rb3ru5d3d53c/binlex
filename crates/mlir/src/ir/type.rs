use crate::ffi;
use crate::printer;
use crate::{Context, Result, string_ref};

#[derive(Copy, Clone)]
pub struct Type {
    raw: ffi::MlirType,
}

impl Type {
    pub(crate) fn from_raw(raw: ffi::MlirType) -> Self {
        Self { raw }
    }

    pub fn parse(context: &Context, text: &str) -> Option<Self> {
        let raw = unsafe { ffi::mlirTypeParseGet(context.raw(), string_ref::from_str(text)) };
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    pub fn integer(context: &Context, bitwidth: u32) -> Self {
        Self::from_raw(unsafe { ffi::mlirIntegerTypeGet(context.raw(), bitwidth) })
    }

    pub fn signed_integer(context: &Context, bitwidth: u32) -> Self {
        Self::from_raw(unsafe { ffi::mlirIntegerTypeSignedGet(context.raw(), bitwidth) })
    }

    pub fn unsigned_integer(context: &Context, bitwidth: u32) -> Self {
        Self::from_raw(unsafe { ffi::mlirIntegerTypeUnsignedGet(context.raw(), bitwidth) })
    }

    pub fn index(context: &Context) -> Self {
        Self::from_raw(unsafe { ffi::mlirIndexTypeGet(context.raw()) })
    }

    pub fn function(context: &Context, inputs: &[Type], results: &[Type]) -> Self {
        let inputs = inputs.iter().map(|ty| ty.raw).collect::<Vec<_>>();
        let results = results.iter().map(|ty| ty.raw).collect::<Vec<_>>();
        Self::from_raw(unsafe {
            ffi::mlirFunctionTypeGet(
                context.raw(),
                inputs.len() as isize,
                inputs.as_ptr(),
                results.len() as isize,
                results.as_ptr(),
            )
        })
    }

    pub fn to_string(&self) -> Result<String> {
        printer::collect_string(|callback, user_data| unsafe {
            ffi::mlirTypePrint(self.raw, callback, user_data);
        })
    }

    pub(crate) fn raw(&self) -> ffi::MlirType {
        self.raw
    }
}
