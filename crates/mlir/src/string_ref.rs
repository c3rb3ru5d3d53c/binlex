use crate::ffi::MlirStringRef;

pub fn from_str(value: &str) -> MlirStringRef {
    MlirStringRef {
        data: value.as_ptr().cast(),
        length: value.len(),
    }
}

pub fn from_bytes(value: &[u8]) -> MlirStringRef {
    MlirStringRef {
        data: value.as_ptr().cast(),
        length: value.len(),
    }
}

pub fn to_string(value: MlirStringRef) -> String {
    if value.data.is_null() || value.length == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(value.data.cast::<u8>(), value.length) };
    String::from_utf8_lossy(bytes).into_owned()
}
