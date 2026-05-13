use crate::ffi;
use crate::string_ref;

use super::{NamedAttribute, Region, Type, Value, block::Block, location::Location};

pub struct OperationState {
    name: String,
    raw: ffi::MlirOperationState,
}

impl OperationState {
    pub fn new(name: &str, location: Location) -> Self {
        let name_owned = name.to_string();
        let raw = unsafe {
            ffi::mlirOperationStateGet(string_ref::from_str(&name_owned), location.raw())
        };
        Self {
            name: name_owned,
            raw,
        }
    }

    pub fn add_results(&mut self, results: &[Type]) {
        let results = results
            .iter()
            .map(|result| result.raw())
            .collect::<Vec<_>>();
        unsafe {
            ffi::mlirOperationStateAddResults(
                &mut self.raw,
                results.len() as isize,
                results.as_ptr(),
            )
        };
    }

    pub fn add_operands(&mut self, operands: &[Value]) {
        let operands = operands
            .iter()
            .map(|operand| operand.raw())
            .collect::<Vec<_>>();
        unsafe {
            ffi::mlirOperationStateAddOperands(
                &mut self.raw,
                operands.len() as isize,
                operands.as_ptr(),
            )
        };
    }

    pub fn add_owned_regions(&mut self, regions: Vec<Region>) {
        let regions = regions
            .into_iter()
            .map(Region::into_raw)
            .collect::<Vec<_>>();
        unsafe {
            ffi::mlirOperationStateAddOwnedRegions(
                &mut self.raw,
                regions.len() as isize,
                regions.as_ptr(),
            )
        };
    }

    pub fn add_successors(&mut self, successors: &[Block]) {
        let successors = successors
            .iter()
            .map(|successor| successor.raw)
            .collect::<Vec<_>>();
        unsafe {
            ffi::mlirOperationStateAddSuccessors(
                &mut self.raw,
                successors.len() as isize,
                successors.as_ptr(),
            )
        };
    }

    pub fn add_attributes(&mut self, attributes: &[NamedAttribute]) {
        let attributes = attributes
            .iter()
            .map(|attribute| attribute.raw())
            .collect::<Vec<_>>();
        unsafe {
            ffi::mlirOperationStateAddAttributes(
                &mut self.raw,
                attributes.len() as isize,
                attributes.as_ptr(),
            )
        };
    }

    pub fn enable_result_type_inference(&mut self) {
        unsafe { ffi::mlirOperationStateEnableResultTypeInference(&mut self.raw) };
    }

    pub(crate) fn raw_mut(&mut self) -> &mut ffi::MlirOperationState {
        let _ = &self.name;
        &mut self.raw
    }
}
