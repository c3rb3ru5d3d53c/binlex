use crate::Result;
use crate::ffi;
use crate::printer;

use super::{Location, Operation, Type, Value};

pub struct Block {
    pub(crate) raw: ffi::MlirBlock,
    owned: bool,
}

impl Block {
    pub fn new(arguments: &[(Type, Location)]) -> Self {
        let types = arguments.iter().map(|(ty, _)| ty.raw()).collect::<Vec<_>>();
        let locations = arguments
            .iter()
            .map(|(_, loc)| loc.raw())
            .collect::<Vec<_>>();
        let raw = unsafe {
            ffi::mlirBlockCreate(types.len() as isize, types.as_ptr(), locations.as_ptr())
        };
        Self { raw, owned: true }
    }

    pub(crate) fn from_borrowed_raw(raw: ffi::MlirBlock) -> Option<Self> {
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw, owned: false })
        }
    }

    pub fn parent_operation(&self) -> Option<Operation> {
        Operation::from_borrowed_raw(unsafe { ffi::mlirBlockGetParentOperation(self.raw) })
    }

    pub fn parent_region(&self) -> Option<super::Region> {
        super::Region::from_borrowed_raw(unsafe { ffi::mlirBlockGetParentRegion(self.raw) })
    }

    pub fn next_in_region(&self) -> Option<Self> {
        Self::from_borrowed_raw(unsafe { ffi::mlirBlockGetNextInRegion(self.raw) })
    }

    pub fn first_operation(&self) -> Option<Operation> {
        Operation::from_borrowed_raw(unsafe { ffi::mlirBlockGetFirstOperation(self.raw) })
    }

    pub fn terminator(&self) -> Option<Operation> {
        Operation::from_borrowed_raw(unsafe { ffi::mlirBlockGetTerminator(self.raw) })
    }

    pub fn append_owned_operation(&self, operation: Operation) {
        unsafe { ffi::mlirBlockAppendOwnedOperation(self.raw, operation.into_raw()) };
    }

    pub fn insert_owned_operation_before(
        &self,
        reference: Option<&Operation>,
        operation: Operation,
    ) {
        unsafe {
            ffi::mlirBlockInsertOwnedOperationBefore(
                self.raw,
                reference.map_or(
                    ffi::MlirOperation {
                        ptr: std::ptr::null_mut(),
                    },
                    |op| op.raw(),
                ),
                operation.into_raw(),
            )
        };
    }

    pub fn insert_owned_operation_after(
        &self,
        reference: Option<&Operation>,
        operation: Operation,
    ) {
        unsafe {
            ffi::mlirBlockInsertOwnedOperationAfter(
                self.raw,
                reference.map_or(
                    ffi::MlirOperation {
                        ptr: std::ptr::null_mut(),
                    },
                    |op| op.raw(),
                ),
                operation.into_raw(),
            )
        };
    }

    pub fn num_arguments(&self) -> usize {
        unsafe { ffi::mlirBlockGetNumArguments(self.raw) as usize }
    }

    pub fn add_argument(&self, ty: Type, location: Location) -> Value {
        Value::from_raw(unsafe { ffi::mlirBlockAddArgument(self.raw, ty.raw(), location.raw()) })
            .expect("mlirBlockAddArgument returned a null value")
    }

    pub fn argument(&self, index: usize) -> Option<Value> {
        Value::from_raw(unsafe { ffi::mlirBlockGetArgument(self.raw, index as isize) })
    }

    pub fn to_string(&self) -> Result<String> {
        printer::collect_string(|callback, user_data| unsafe {
            ffi::mlirBlockPrint(self.raw, callback, user_data);
        })
    }

    pub(crate) fn into_raw(self) -> ffi::MlirBlock {
        let raw = self.raw;
        std::mem::forget(self);
        raw
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        if self.owned {
            unsafe { ffi::mlirBlockDestroy(self.raw) };
        }
    }
}
