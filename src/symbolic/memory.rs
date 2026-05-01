use crate::symbolic::Error;
use crate::symbolic::backend::z3::Z3Backend;
use z3::ast::{Array, BV};

#[derive(Clone)]
pub(crate) struct FlatMemory {
    array: Array,
    mapped_ranges: Vec<(u64, u64)>,
    address_bits: u32,
}

impl FlatMemory {
    pub(crate) fn new(backend: &Z3Backend, address_bits: u32) -> Self {
        Self {
            array: backend.new_memory(address_bits),
            mapped_ranges: Vec::new(),
            address_bits,
        }
    }

    pub(crate) fn map(&mut self, address: u64, size: u64) {
        self.mapped_ranges.push((address, size));
    }

    pub(crate) fn store_bytes(
        &mut self,
        backend: &Z3Backend,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        for (offset, byte) in bytes.iter().enumerate() {
            let index =
                backend.const_bv((address + offset as u64) as u128, self.address_bits as u16)?;
            let value = backend.const_bv(*byte as u128, 8)?;
            self.array = self.array.store(&index, &value);
        }
        Ok(())
    }

    pub(crate) fn symbolize_bytes(
        &mut self,
        backend: &Z3Backend,
        address: u64,
        size: usize,
        mut symbol_name: impl FnMut(usize) -> String,
    ) -> Result<Vec<BV>, Error> {
        let mut values = Vec::with_capacity(size);
        for offset in 0..size {
            let index =
                backend.const_bv((address + offset as u64) as u128, self.address_bits as u16)?;
            let value = backend.fresh_bv(&symbol_name(offset), 8)?;
            self.array = self.array.store(&index, &value);
            values.push(value);
        }
        Ok(values)
    }

    pub(crate) fn load(&self, backend: &Z3Backend, address: &BV, bits: u16) -> Result<BV, Error> {
        if bits == 0 || !bits.is_multiple_of(8) {
            return Err(Error::UnsupportedExpression(
                "memory loads currently require a byte-aligned width",
            ));
        }
        let byte_count = (bits / 8) as usize;
        let mut bytes = Vec::with_capacity(byte_count);
        for offset in 0..byte_count {
            let byte_address = if offset == 0 {
                address.clone()
            } else {
                let increment = backend.const_bv(offset as u128, address.get_size() as u16)?;
                address.bvadd(&increment)
            };
            bytes.push(backend.memory_select(&self.array, &byte_address)?);
        }
        let mut value = bytes
            .pop()
            .ok_or_else(|| Error::solver("memory load assembled no bytes"))?;
        while let Some(next) = bytes.pop() {
            value = value.concat(&next);
        }
        Ok(value)
    }

    pub(crate) fn store(
        &mut self,
        backend: &Z3Backend,
        address: &BV,
        value: &BV,
        bits: u16,
    ) -> Result<(), Error> {
        if bits == 0 || !bits.is_multiple_of(8) {
            return Err(Error::UnsupportedEffect(
                "memory stores currently require a byte-aligned width",
            ));
        }
        let byte_count = (bits / 8) as usize;
        let coerced = backend.coerce_bv_width(value, bits)?;
        for offset in 0..byte_count {
            let low = (offset * 8) as u32;
            let high = low + 7;
            let byte = coerced.extract(high, low);
            let byte_address = if offset == 0 {
                address.clone()
            } else {
                let increment = backend.const_bv(offset as u128, address.get_size() as u16)?;
                address.bvadd(&increment)
            };
            self.array = self.array.store(&byte_address, &byte);
        }
        Ok(())
    }
}
