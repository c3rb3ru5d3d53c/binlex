use crate::Context;
use crate::dialect_registry::DialectRegistry;
use crate::ffi;
use crate::string_ref;

#[derive(Copy, Clone)]
pub struct DialectHandle {
    raw: ffi::MlirDialectHandle,
}

impl DialectHandle {
    pub(crate) fn from_raw(raw: ffi::MlirDialectHandle) -> Self {
        Self { raw }
    }

    pub fn namespace(&self) -> String {
        string_ref::to_string(unsafe { ffi::mlirDialectHandleGetNamespace(self.raw) })
    }

    pub fn insert_dialect(&self, registry: &DialectRegistry) {
        unsafe { ffi::mlirDialectHandleInsertDialect(self.raw, registry.raw()) };
    }

    pub fn register_dialect(&self, context: &Context) {
        unsafe { ffi::mlirDialectHandleRegisterDialect(self.raw, context.raw()) };
    }

    pub fn load_dialect(&self, context: &Context) {
        unsafe {
            ffi::mlirDialectHandleLoadDialect(self.raw, context.raw());
        }
    }
}
