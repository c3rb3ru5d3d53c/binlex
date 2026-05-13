use crate::Context;
use crate::error::{Error, Result};
use crate::ffi;
use crate::printer;
use crate::string_ref;
use crate::verifier;

use super::{Attribute, Identifier, Location, OperationState, Region, Value, block::Block};

pub struct Operation {
    raw: ffi::MlirOperation,
    owned: bool,
}

impl Operation {
    pub fn create(state: &mut OperationState) -> Result<Self> {
        let raw = unsafe { ffi::mlirOperationCreate(state.raw_mut()) };
        if raw.ptr.is_null() {
            return Err(Error::NullHandle("operation"));
        }
        Ok(Self { raw, owned: true })
    }

    pub fn parse(context: &Context, source: &str, source_name: &str) -> Result<Self> {
        let raw = unsafe {
            ffi::mlirOperationCreateParse(
                context.raw(),
                string_ref::from_str(source),
                string_ref::from_str(source_name),
            )
        };
        if raw.ptr.is_null() {
            return Err(Error::ParseFailed);
        }
        Ok(Self { raw, owned: true })
    }

    pub fn clone(&self) -> Self {
        let raw = unsafe { ffi::mlirOperationClone(self.raw) };
        Self { raw, owned: true }
    }

    pub(crate) fn from_borrowed_raw(raw: ffi::MlirOperation) -> Option<Self> {
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw, owned: false })
        }
    }

    pub fn verify(&self) -> Result<()> {
        verifier::logical_result(unsafe { ffi::mlirOperationVerify(self.raw) })
    }

    pub fn location(&self) -> Location {
        Location::from_raw(unsafe { ffi::mlirOperationGetLocation(self.raw) })
    }

    pub fn set_location(&self, location: Location) {
        unsafe { ffi::mlirOperationSetLocation(self.raw, location.raw()) };
    }

    pub fn name(&self) -> Identifier {
        Identifier::from_raw(unsafe { ffi::mlirOperationGetName(self.raw) })
    }

    pub fn block(&self) -> Option<Block> {
        Block::from_borrowed_raw(unsafe { ffi::mlirOperationGetBlock(self.raw) })
    }

    pub fn parent_operation(&self) -> Option<Self> {
        Self::from_borrowed_raw(unsafe { ffi::mlirOperationGetParentOperation(self.raw) })
    }

    pub fn num_regions(&self) -> usize {
        unsafe { ffi::mlirOperationGetNumRegions(self.raw) as usize }
    }

    pub fn region(&self, index: usize) -> Option<Region> {
        Region::from_borrowed_raw(unsafe { ffi::mlirOperationGetRegion(self.raw, index as isize) })
    }

    pub fn num_operands(&self) -> usize {
        unsafe { ffi::mlirOperationGetNumOperands(self.raw) as usize }
    }

    pub fn operand(&self, index: usize) -> Option<Value> {
        Value::from_raw(unsafe { ffi::mlirOperationGetOperand(self.raw, index as isize) })
    }

    pub fn set_operand(&self, index: usize, value: Value) {
        unsafe { ffi::mlirOperationSetOperand(self.raw, index as isize, value.raw()) };
    }

    pub fn num_results(&self) -> usize {
        unsafe { ffi::mlirOperationGetNumResults(self.raw) as usize }
    }

    pub fn result(&self, index: usize) -> Option<Value> {
        Value::from_raw(unsafe { ffi::mlirOperationGetResult(self.raw, index as isize) })
    }

    pub fn num_successors(&self) -> usize {
        unsafe { ffi::mlirOperationGetNumSuccessors(self.raw) as usize }
    }

    pub fn successor(&self, index: usize) -> Option<Block> {
        Block::from_borrowed_raw(unsafe {
            ffi::mlirOperationGetSuccessor(self.raw, index as isize)
        })
    }

    pub fn set_successor(&self, index: usize, block: &Block) {
        unsafe { ffi::mlirOperationSetSuccessor(self.raw, index as isize, block.raw) };
    }

    pub fn discardable_attribute(&self, name: &str) -> Option<Attribute> {
        let raw = unsafe {
            ffi::mlirOperationGetDiscardableAttributeByName(self.raw, string_ref::from_str(name))
        };
        if raw.ptr.is_null() {
            None
        } else {
            Some(Attribute::from_raw(raw))
        }
    }

    pub fn set_discardable_attribute(&self, name: &str, attribute: Attribute) {
        unsafe {
            ffi::mlirOperationSetDiscardableAttributeByName(
                self.raw,
                string_ref::from_str(name),
                attribute.raw(),
            )
        };
    }

    pub fn remove_discardable_attribute(&self, name: &str) -> bool {
        unsafe {
            ffi::mlirOperationRemoveDiscardableAttributeByName(self.raw, string_ref::from_str(name))
        }
    }

    pub fn to_string(&self) -> Result<String> {
        printer::collect_string(|callback, user_data| unsafe {
            ffi::mlirOperationPrint(self.raw, callback, user_data);
        })
    }

    pub(crate) fn raw(&self) -> ffi::MlirOperation {
        self.raw
    }

    pub(crate) fn into_raw(self) -> ffi::MlirOperation {
        let raw = self.raw;
        std::mem::forget(self);
        raw
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if self.owned {
            unsafe { ffi::mlirOperationDestroy(self.raw) };
        }
    }
}
