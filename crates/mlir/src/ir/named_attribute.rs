use crate::ffi;
use crate::ir::{Attribute, Identifier};

#[derive(Copy, Clone)]
pub struct NamedAttribute {
    raw: ffi::MlirNamedAttribute,
}

impl NamedAttribute {
    pub fn new(name: Identifier, attribute: Attribute) -> Self {
        let raw = unsafe { ffi::mlirNamedAttributeGet(name.raw(), attribute.raw()) };
        Self { raw }
    }
    pub fn name(&self) -> Identifier {
        Identifier::from_raw(self.raw.name)
    }

    pub fn attribute(&self) -> Attribute {
        Attribute::from_raw(self.raw.attribute)
    }

    pub(crate) fn raw(&self) -> ffi::MlirNamedAttribute {
        self.raw
    }
}
