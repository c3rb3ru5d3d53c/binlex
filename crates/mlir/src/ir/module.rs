use crate::Context;
use crate::error::{Error, Result};
use crate::ffi;
use crate::string_ref;

use super::{Block, Location, Operation};

pub struct Module {
    raw: ffi::MlirModule,
}

impl Module {
    pub fn new(location: Location) -> Result<Self> {
        let raw = unsafe { ffi::mlirModuleCreateEmpty(location.raw()) };
        if raw.ptr.is_null() {
            return Err(Error::NullHandle("module"));
        }
        Ok(Self { raw })
    }

    pub fn parse(context: &Context, source: &str) -> Result<Self> {
        let raw =
            unsafe { ffi::mlirModuleCreateParse(context.raw(), string_ref::from_str(source)) };
        if raw.ptr.is_null() {
            return Err(Error::ParseFailed);
        }
        Ok(Self { raw })
    }

    pub fn parse_from_file(context: &Context, file_name: &str) -> Result<Self> {
        let raw = unsafe {
            ffi::mlirModuleCreateParseFromFile(context.raw(), string_ref::from_str(file_name))
        };
        if raw.ptr.is_null() {
            return Err(Error::ParseFailed);
        }
        Ok(Self { raw })
    }

    pub fn from_operation(operation: &Operation) -> Option<Self> {
        let raw = unsafe { ffi::mlirModuleFromOperation(operation.raw()) };
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    pub fn body(&self) -> Option<Block> {
        Block::from_borrowed_raw(unsafe { ffi::mlirModuleGetBody(self.raw) })
    }

    pub fn operation(&self) -> Operation {
        Operation::from_borrowed_raw(unsafe { ffi::mlirModuleGetOperation(self.raw) })
            .expect("module operation should never be null")
    }

    pub fn verify(&self) -> Result<()> {
        self.operation().verify()
    }

    pub fn to_string(&self) -> Result<String> {
        self.operation().to_string()
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        unsafe { ffi::mlirModuleDestroy(self.raw) };
    }
}
