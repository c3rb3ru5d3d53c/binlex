use crate::dialect_registry::DialectRegistry;
use crate::ffi;
use crate::string_ref;

pub struct Context {
    raw: ffi::MlirContext,
}

impl Context {
    pub fn new() -> Self {
        let raw = unsafe { ffi::mlirContextCreate() };
        Self { raw }
    }

    pub fn new_with_threading(threading_enabled: bool) -> Self {
        let raw = unsafe { ffi::mlirContextCreateWithThreading(threading_enabled) };
        Self { raw }
    }

    pub fn new_with_registry(registry: &DialectRegistry, threading_enabled: bool) -> Self {
        let raw = unsafe { ffi::mlirContextCreateWithRegistry(registry.raw(), threading_enabled) };
        Self { raw }
    }

    pub fn append_dialect_registry(&self, registry: &DialectRegistry) {
        unsafe { ffi::mlirContextAppendDialectRegistry(self.raw, registry.raw()) };
    }

    pub fn load_all_available_dialects(&self) {
        unsafe { ffi::mlirContextLoadAllAvailableDialects(self.raw) };
    }

    pub fn set_allow_unregistered_dialects(&self, allow: bool) {
        unsafe { ffi::mlirContextSetAllowUnregisteredDialects(self.raw, allow) };
    }

    pub fn allow_unregistered_dialects(&self) -> bool {
        unsafe { ffi::mlirContextGetAllowUnregisteredDialects(self.raw) }
    }

    pub fn num_registered_dialects(&self) -> usize {
        unsafe { ffi::mlirContextGetNumRegisteredDialects(self.raw) as usize }
    }

    pub fn num_loaded_dialects(&self) -> usize {
        unsafe { ffi::mlirContextGetNumLoadedDialects(self.raw) as usize }
    }

    pub fn is_registered_operation(&self, name: &str) -> bool {
        unsafe { ffi::mlirContextIsRegisteredOperation(self.raw, string_ref::from_str(name)) }
    }

    pub fn new_with_all_dialects() -> Self {
        let registry = DialectRegistry::new();
        registry.register_all_dialects();
        let context = Self::new_with_registry(&registry, true);
        context.load_all_available_dialects();
        context
    }

    pub(crate) fn raw(&self) -> ffi::MlirContext {
        self.raw
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new_with_all_dialects()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ffi::mlirContextDestroy(self.raw) };
    }
}
