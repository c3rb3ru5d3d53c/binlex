use crate::ffi;

pub struct DialectRegistry {
    raw: ffi::MlirDialectRegistry,
}

impl DialectRegistry {
    pub fn new() -> Self {
        let raw = unsafe { ffi::mlirDialectRegistryCreate() };
        Self { raw }
    }

    pub fn register_all_dialects(&self) {
        unsafe { ffi::mlirRegisterAllDialects(self.raw) };
    }

    pub(crate) fn raw(&self) -> ffi::MlirDialectRegistry {
        self.raw
    }
}

impl Default for DialectRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DialectRegistry {
    fn drop(&mut self) {
        unsafe { ffi::mlirDialectRegistryDestroy(self.raw) };
    }
}
