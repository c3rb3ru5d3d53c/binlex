use crate::symbolic::Error;
use crate::symbolic::backend::z3::Z3Backend;
use std::collections::{BTreeSet, HashMap};
use z3::ast::{Array, BV};

#[derive(Clone)]
pub(crate) struct FlatMemory {
    array: Array,
    provenance: HashMap<u64, u64>,
    mapped_ranges: Vec<(u64, u64)>,
    address_bits: u32,
}

impl FlatMemory {
    pub(crate) fn new(backend: &Z3Backend, address_bits: u32) -> Self {
        Self {
            array: backend.new_memory(address_bits),
            provenance: HashMap::new(),
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
            self.provenance.remove(&(address + offset as u64));
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
        Ok(self.load_with_provenance(backend, address, bits)?.0)
    }

    pub(crate) fn load_with_provenance(
        &self,
        backend: &Z3Backend,
        address: &BV,
        bits: u16,
    ) -> Result<(BV, BTreeSet<u64>), Error> {
        if bits == 0 || !bits.is_multiple_of(8) {
            return Err(Error::UnsupportedExpression(
                "memory loads currently require a byte-aligned width",
            ));
        }
        let byte_count = (bits / 8) as usize;
        let mut bytes = Vec::with_capacity(byte_count);
        let mut parents = BTreeSet::new();
        let concrete_address = address.as_u64();
        for offset in 0..byte_count {
            let byte_address = if offset == 0 {
                address.clone()
            } else {
                let increment = backend.const_bv(offset as u128, address.get_size() as u16)?;
                address.bvadd(&increment)
            };
            bytes.push(backend.memory_select(&self.array, &byte_address)?);
            if let Some(base) = concrete_address {
                if let Some(def_id) = self.provenance.get(&(base + offset as u64)) {
                    parents.insert(*def_id);
                }
            }
        }
        let mut value = bytes
            .pop()
            .ok_or_else(|| Error::solver("memory load assembled no bytes"))?;
        while let Some(next) = bytes.pop() {
            value = value.concat(&next);
        }
        Ok((value, parents))
    }

    pub(crate) fn store_with_provenance(
        &mut self,
        backend: &Z3Backend,
        address: &BV,
        value: &BV,
        bits: u16,
        def_id: Option<u64>,
    ) -> Result<(), Error> {
        if bits == 0 || !bits.is_multiple_of(8) {
            return Err(Error::UnsupportedEffect(
                "memory stores currently require a byte-aligned width",
            ));
        }
        let byte_count = (bits / 8) as usize;
        let coerced = backend.coerce_bv_width(value, bits)?;
        let concrete_address = address.as_u64();
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
            if let Some(base) = concrete_address {
                let current = base + offset as u64;
                if let Some(def_id) = def_id {
                    self.provenance.insert(current, def_id);
                } else {
                    self.provenance.remove(&current);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn set_byte_provenance(&mut self, address: u64, def_id: Option<u64>) {
        if let Some(def_id) = def_id {
            self.provenance.insert(address, def_id);
        } else {
            self.provenance.remove(&address);
        }
    }

    pub(crate) fn provenance_for_range(&self, address: u64, size: usize) -> BTreeSet<u64> {
        let mut parents = BTreeSet::new();
        for offset in 0..size {
            if let Some(def_id) = self.provenance.get(&(address + offset as u64)) {
                parents.insert(*def_id);
            }
        }
        parents
    }
}
