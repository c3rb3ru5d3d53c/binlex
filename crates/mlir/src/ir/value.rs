use crate::Result;
use crate::ffi;
use crate::printer;

use super::{Block, Location, Operation, Type};

#[derive(Copy, Clone)]
pub struct Value {
    raw: ffi::MlirValue,
}

impl Value {
    pub(crate) fn from_raw(raw: ffi::MlirValue) -> Option<Self> {
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    pub fn is_block_argument(&self) -> bool {
        unsafe { ffi::mlirValueIsABlockArgument(self.raw) }
    }

    pub fn is_op_result(&self) -> bool {
        unsafe { ffi::mlirValueIsAOpResult(self.raw) }
    }

    pub fn block_argument_owner(&self) -> Option<Block> {
        let raw = unsafe { ffi::mlirBlockArgumentGetOwner(self.raw) };
        Block::from_borrowed_raw(raw)
    }

    pub fn op_result_owner(&self) -> Option<Operation> {
        let raw = unsafe { ffi::mlirOpResultGetOwner(self.raw) };
        Operation::from_borrowed_raw(raw)
    }

    pub fn arg_number(&self) -> isize {
        unsafe { ffi::mlirBlockArgumentGetArgNumber(self.raw) }
    }

    pub fn result_number(&self) -> isize {
        unsafe { ffi::mlirOpResultGetResultNumber(self.raw) }
    }

    pub fn ty(&self) -> Type {
        Type::from_raw(unsafe { ffi::mlirValueGetType(self.raw) })
    }

    pub fn set_type(&self, ty: Type) {
        unsafe { ffi::mlirValueSetType(self.raw, ty.raw()) };
    }

    pub fn location(&self) -> Location {
        Location::from_raw(unsafe { ffi::mlirValueGetLocation(self.raw) })
    }

    pub fn replace_all_uses_with(&self, replacement: Value) {
        unsafe { ffi::mlirValueReplaceAllUsesOfWith(self.raw, replacement.raw) };
    }

    pub fn to_string(&self) -> Result<String> {
        printer::collect_string(|callback, user_data| unsafe {
            ffi::mlirValuePrint(self.raw, callback, user_data);
        })
    }

    pub(crate) fn raw(&self) -> ffi::MlirValue {
        self.raw
    }
}
