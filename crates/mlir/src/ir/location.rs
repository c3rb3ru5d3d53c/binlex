use crate::ffi;
use crate::printer;
use crate::{Context, Result};

#[derive(Copy, Clone)]
pub struct Location {
    raw: ffi::MlirLocation,
}

impl Location {
    pub(crate) fn from_raw(raw: ffi::MlirLocation) -> Self {
        Self { raw }
    }

    pub fn unknown(context: &Context) -> Self {
        Self::from_raw(unsafe { ffi::mlirLocationUnknownGet(context.raw()) })
    }

    pub fn file_line_col(context: &Context, filename: &str, line: u32, column: u32) -> Self {
        Self::from_raw(unsafe {
            ffi::mlirLocationFileLineColGet(
                context.raw(),
                crate::string_ref::from_str(filename),
                line,
                column,
            )
        })
    }

    pub fn to_string(&self) -> Result<String> {
        printer::collect_string(|callback, user_data| unsafe {
            ffi::mlirLocationPrint(self.raw, callback, user_data);
        })
    }

    pub(crate) fn raw(&self) -> ffi::MlirLocation {
        self.raw
    }
}
