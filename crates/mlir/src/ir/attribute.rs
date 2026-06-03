use crate::ffi;
use crate::printer;
use crate::{Context, Result, string_ref};

use super::r#type::Type;

#[derive(Copy, Clone)]
pub struct Attribute {
    raw: ffi::MlirAttribute,
}

impl Attribute {
    pub(crate) fn from_raw(raw: ffi::MlirAttribute) -> Self {
        Self { raw }
    }

    pub fn null() -> Self {
        Self::from_raw(unsafe { ffi::mlirAttributeGetNull() })
    }

    pub fn parse(context: &Context, text: &str) -> Option<Self> {
        let raw = unsafe { ffi::mlirAttributeParseGet(context.raw(), string_ref::from_str(text)) };
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    pub fn bool(context: &Context, value: bool) -> Self {
        Self::from_raw(unsafe { ffi::mlirBoolAttrGet(context.raw(), i32::from(value)) })
    }

    pub fn is_bool(&self) -> bool {
        unsafe { ffi::mlirAttributeIsABool(self.raw) }
    }

    pub fn as_bool(&self) -> Option<bool> {
        self.is_bool()
            .then(|| unsafe { ffi::mlirBoolAttrGetValue(self.raw) })
    }

    pub fn integer(ty: Type, value: i64) -> Self {
        Self::from_raw(unsafe { ffi::mlirIntegerAttrGet(ty.raw(), value) })
    }

    pub fn is_integer(&self) -> bool {
        unsafe { ffi::mlirAttributeIsAInteger(self.raw) }
    }

    pub fn as_integer(&self) -> Option<i64> {
        self.is_integer()
            .then(|| unsafe { ffi::mlirIntegerAttrGetValueInt(self.raw) })
    }

    pub fn as_signed_integer(&self) -> Option<i64> {
        self.is_integer()
            .then(|| unsafe { ffi::mlirIntegerAttrGetValueSInt(self.raw) })
    }

    pub fn as_unsigned_integer(&self) -> Option<u64> {
        self.is_integer()
            .then(|| unsafe { ffi::mlirIntegerAttrGetValueUInt(self.raw) })
    }

    pub fn string(context: &Context, value: &str) -> Self {
        Self::from_raw(unsafe {
            ffi::mlirStringAttrGet(context.raw(), string_ref::from_str(value))
        })
    }

    pub fn is_string(&self) -> bool {
        unsafe { ffi::mlirAttributeIsAString(self.raw) }
    }

    pub fn as_string(&self) -> Option<String> {
        self.is_string()
            .then(|| string_ref::to_string(unsafe { ffi::mlirStringAttrGetValue(self.raw) }))
    }

    pub fn ty(&self) -> Type {
        Type::from_raw(unsafe { ffi::mlirAttributeGetType(self.raw) })
    }

    pub fn to_string(&self) -> Result<String> {
        printer::collect_string(|callback, user_data| unsafe {
            ffi::mlirAttributePrint(self.raw, callback, user_data);
        })
    }

    pub(crate) fn raw(&self) -> ffi::MlirAttribute {
        self.raw
    }
}
