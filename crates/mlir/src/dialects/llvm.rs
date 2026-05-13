use crate::{DialectHandle, ffi};

pub fn dialect_handle() -> DialectHandle {
    DialectHandle::from_raw(unsafe { ffi::mlirGetDialectHandle__llvm__() })
}
