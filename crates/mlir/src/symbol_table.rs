use crate::string_ref;
use crate::{ffi, ir::attribute::Attribute, ir::operation::Operation};

pub struct SymbolTable {
    raw: ffi::MlirSymbolTable,
}

impl SymbolTable {
    pub fn new(operation: &Operation) -> Option<Self> {
        let raw = unsafe { ffi::mlirSymbolTableCreate(operation.raw()) };
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    pub fn symbol_attribute_name() -> String {
        string_ref::to_string(unsafe { ffi::mlirSymbolTableGetSymbolAttributeName() })
    }

    pub fn visibility_attribute_name() -> String {
        string_ref::to_string(unsafe { ffi::mlirSymbolTableGetVisibilityAttributeName() })
    }

    pub fn lookup(&self, name: &str) -> Option<Operation> {
        let raw = unsafe { ffi::mlirSymbolTableLookup(self.raw, string_ref::from_str(name)) };
        Operation::from_borrowed_raw(raw)
    }

    pub fn insert(&self, operation: &Operation) -> Attribute {
        Attribute::from_raw(unsafe { ffi::mlirSymbolTableInsert(self.raw, operation.raw()) })
    }

    pub fn erase(&self, operation: &Operation) {
        unsafe { ffi::mlirSymbolTableErase(self.raw, operation.raw()) };
    }
}

impl Drop for SymbolTable {
    fn drop(&mut self) {
        unsafe { ffi::mlirSymbolTableDestroy(self.raw) };
    }
}
