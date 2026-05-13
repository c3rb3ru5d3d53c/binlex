use crate::ffi;

use super::Block;

pub struct Region {
    raw: ffi::MlirRegion,
    owned: bool,
}

impl Region {
    pub fn new() -> Self {
        let raw = unsafe { ffi::mlirRegionCreate() };
        Self { raw, owned: true }
    }

    pub(crate) fn from_borrowed_raw(raw: ffi::MlirRegion) -> Option<Self> {
        if raw.ptr.is_null() {
            None
        } else {
            Some(Self { raw, owned: false })
        }
    }

    pub fn first_block(&self) -> Option<Block> {
        Block::from_borrowed_raw(unsafe { ffi::mlirRegionGetFirstBlock(self.raw) })
    }

    pub fn next_in_operation(&self) -> Option<Self> {
        Self::from_borrowed_raw(unsafe { ffi::mlirRegionGetNextInOperation(self.raw) })
    }

    pub fn append_owned_block(&self, block: Block) {
        unsafe { ffi::mlirRegionAppendOwnedBlock(self.raw, block.into_raw()) };
    }

    pub fn insert_owned_block_after(&self, reference: Option<&Block>, block: Block) {
        unsafe {
            ffi::mlirRegionInsertOwnedBlockAfter(
                self.raw,
                reference.map_or(
                    ffi::MlirBlock {
                        ptr: std::ptr::null_mut(),
                    },
                    |b| b.raw,
                ),
                block.into_raw(),
            )
        };
    }

    pub fn insert_owned_block_before(&self, reference: Option<&Block>, block: Block) {
        unsafe {
            ffi::mlirRegionInsertOwnedBlockBefore(
                self.raw,
                reference.map_or(
                    ffi::MlirBlock {
                        ptr: std::ptr::null_mut(),
                    },
                    |b| b.raw,
                ),
                block.into_raw(),
            )
        };
    }

    pub fn take_body(&self, source: Region) {
        unsafe { ffi::mlirRegionTakeBody(self.raw, source.into_raw()) };
    }

    pub(crate) fn into_raw(self) -> ffi::MlirRegion {
        let raw = self.raw;
        std::mem::forget(self);
        raw
    }
}

impl Default for Region {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        if self.owned {
            unsafe { ffi::mlirRegionDestroy(self.raw) };
        }
    }
}
