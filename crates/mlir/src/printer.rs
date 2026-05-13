use crate::error::Result;
use crate::ffi;
use std::ffi::c_void;

pub fn collect_string(print: impl FnOnce(ffi::MlirStringCallback, *mut c_void)) -> Result<String> {
    unsafe extern "C" fn callback(string: ffi::MlirStringRef, user_data: *mut c_void) {
        let output = unsafe { &mut *(user_data as *mut Vec<u8>) };
        if string.data.is_null() || string.length == 0 {
            return;
        }
        let bytes = unsafe { std::slice::from_raw_parts(string.data.cast::<u8>(), string.length) };
        output.extend_from_slice(bytes);
    }

    let mut output = Vec::new();
    print(Some(callback), &mut output as *mut _ as *mut c_void);
    Ok(std::str::from_utf8(&output)?.to_string())
}
