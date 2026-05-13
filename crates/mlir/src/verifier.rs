use crate::error::{Error, Result};
use crate::ffi;

pub fn logical_result(result: ffi::MlirLogicalResult) -> Result<()> {
    if ffi::logical_result_is_success(result) {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}
