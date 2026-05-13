use crate::error::Result;
use crate::ffi;
use crate::printer;
use crate::string_ref;
use crate::verifier;
use crate::{Context, ir::operation::Operation};
use std::ffi::c_void;

pub struct PassManager {
    raw: ffi::MlirPassManager,
}

#[derive(Copy, Clone)]
pub struct OpPassManager {
    raw: ffi::MlirOpPassManager,
}

impl PassManager {
    pub fn new(context: &Context) -> Self {
        let raw = unsafe { ffi::mlirPassManagerCreate(context.raw()) };
        Self { raw }
    }

    pub fn new_on_operation(context: &Context, anchor_op: &str) -> Self {
        let raw = unsafe {
            ffi::mlirPassManagerCreateOnOperation(context.raw(), string_ref::from_str(anchor_op))
        };
        Self { raw }
    }

    pub fn as_op_pass_manager(&self) -> OpPassManager {
        let raw = unsafe { ffi::mlirPassManagerGetAsOpPassManager(self.raw) };
        OpPassManager { raw }
    }

    pub fn enable_verifier(&self, enable: bool) {
        unsafe { ffi::mlirPassManagerEnableVerifier(self.raw, enable) };
    }

    pub fn enable_timing(&self) {
        unsafe { ffi::mlirPassManagerEnableTiming(self.raw) };
    }

    pub fn run_on_operation(&self, operation: &Operation) -> Result<()> {
        verifier::logical_result(unsafe { ffi::mlirPassManagerRunOnOp(self.raw, operation.raw()) })
    }
}

impl Drop for PassManager {
    fn drop(&mut self) {
        unsafe { ffi::mlirPassManagerDestroy(self.raw) };
    }
}

impl OpPassManager {
    pub fn add_pipeline(&self, pipeline: &str) -> Result<()> {
        unsafe extern "C" fn ignore(_string: ffi::MlirStringRef, _user_data: *mut c_void) {}

        verifier::logical_result(unsafe {
            ffi::mlirOpPassManagerAddPipeline(
                self.raw,
                string_ref::from_str(pipeline),
                Some(ignore),
                std::ptr::null_mut(),
            )
        })
    }

    pub fn to_string(&self) -> Result<String> {
        printer::collect_string(|callback, user_data| unsafe {
            ffi::mlirPrintPassPipeline(self.raw, callback, user_data);
        })
    }
}
