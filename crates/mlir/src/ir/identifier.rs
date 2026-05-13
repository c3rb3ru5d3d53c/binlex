use crate::{Context, ffi, string_ref};

#[derive(Copy, Clone)]
pub struct Identifier {
    raw: ffi::MlirIdentifier,
}

impl Identifier {
    pub fn new(context: &Context, value: &str) -> Self {
        let raw = unsafe { ffi::mlirIdentifierGet(context.raw(), string_ref::from_str(value)) };
        Self { raw }
    }

    pub(crate) fn from_raw(raw: ffi::MlirIdentifier) -> Self {
        Self { raw }
    }

    pub fn as_string(&self) -> String {
        string_ref::to_string(unsafe { ffi::mlirIdentifierStr(self.raw) })
    }

    pub(crate) fn raw(&self) -> ffi::MlirIdentifier {
        self.raw
    }
}
