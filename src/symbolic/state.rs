use crate::Architecture;
use crate::symbolic::Error;
use crate::symbolic::backend::z3::{TrackedAst, Z3Backend};
use crate::symbolic::memory::FlatMemory;
use std::collections::HashMap;
use z3::ast::{BV, Bool};

#[derive(Clone)]
pub struct State {
    architecture: Architecture,
    address_bits: u16,
    backend: Z3Backend,
    registers: HashMap<String, BV>,
    flags: HashMap<String, BV>,
    temporaries: HashMap<u32, BV>,
    program_counter: Option<BV>,
    memory: FlatMemory,
    constraints: Vec<Bool>,
    tracked: HashMap<String, TrackedAst>,
    next_fresh_id: u64,
}

impl State {
    fn instruction_pointer_register_name(&self, bits: u16) -> Option<&'static str> {
        match (self.architecture, bits) {
            (Architecture::I386, 16) => Some("ip"),
            (Architecture::I386, 32) => Some("eip"),
            (Architecture::AMD64, 16) => Some("ip"),
            (Architecture::AMD64, 32) => Some("eip"),
            (Architecture::AMD64, 64) => Some("rip"),
            (Architecture::ARM64, 64) => Some("pc"),
            _ => None,
        }
    }

    pub(crate) fn new(architecture: Architecture, address_bits: u16) -> Self {
        let backend = Z3Backend::new();
        Self {
            architecture,
            address_bits,
            registers: HashMap::new(),
            flags: HashMap::new(),
            temporaries: HashMap::new(),
            program_counter: None,
            memory: FlatMemory::new(&backend, address_bits as u32),
            constraints: Vec::new(),
            tracked: HashMap::new(),
            next_fresh_id: 0,
            backend,
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn address_bits(&self) -> u16 {
        self.address_bits
    }

    pub fn symbolize_register(
        &mut self,
        name: &str,
        bits: u16,
        symbol: Option<&str>,
    ) -> Result<(), Error> {
        let symbol = symbol
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("register:{name}"));
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        self.registers.insert(name.to_string(), value);
        Ok(())
    }

    pub fn set_register(&mut self, name: &str, bits: u16, value: u64) -> Result<(), Error> {
        let value = self.backend.const_bv(value as u128, bits)?;
        self.registers.insert(name.to_string(), value);
        Ok(())
    }

    pub fn symbolic_register(&self, name: &str, bits: u16) -> Result<Option<String>, Error> {
        let Some(value) = self.registers.get(name) else {
            return Ok(None);
        };
        let value = self.backend.coerce_bv_width(value, bits)?;
        Ok(Some(value.to_string()))
    }

    pub fn evaluate_register(&self, name: &str, bits: u16) -> Result<Option<u64>, Error> {
        let Some(value) = self.registers.get(name) else {
            return Ok(None);
        };
        let value = self.backend.coerce_bv_width(value, bits)?;
        self.backend.eval_bv_u64(&self.constraints, &value)
    }

    pub fn map_memory(&mut self, address: u64, size: u64) {
        self.memory.map(address, size);
    }

    pub fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<(), Error> {
        self.memory.store_bytes(&self.backend, address, data)
    }

    pub fn symbolize_memory(
        &mut self,
        address: u64,
        size: usize,
        name: Option<&str>,
    ) -> Result<(), Error> {
        let prefix = name.unwrap_or("memory");
        let bytes = self
            .memory
            .symbolize_bytes(&self.backend, address, size, |offset| {
                format!("{prefix}[0x{:x}]", address + offset as u64)
            })?;
        for (offset, value) in bytes.into_iter().enumerate() {
            self.tracked.insert(
                format!("{prefix}[0x{:x}]", address + offset as u64),
                TrackedAst::BitVector(value),
            );
        }
        Ok(())
    }

    pub fn symbolic_memory(&self, address: u64, size: usize) -> Result<String, Error> {
        let address = self.backend.const_bv(address as u128, self.address_bits)?;
        let value = self
            .memory
            .load(&self.backend, &address, (size * 8) as u16)?;
        Ok(value.to_string())
    }

    pub fn constraints(&self) -> Vec<String> {
        self.constraints.iter().map(ToString::to_string).collect()
    }

    #[cfg(test)]
    pub(crate) fn eval_program_counter_u64(&self) -> Result<Option<u64>, Error> {
        match self.program_counter.as_ref() {
            Some(value) => self.backend.eval_bv_u64(&self.constraints, value),
            None => Ok(None),
        }
    }

    pub fn evaluate_memory(&self, address: u64, size: usize) -> Result<Option<u64>, Error> {
        let address = self.backend.const_bv(address as u128, self.address_bits)?;
        let value = self
            .memory
            .load(&self.backend, &address, (size * 8) as u16)?;
        self.backend.eval_bv_u64(&self.constraints, &value)
    }

    pub fn satisfiable(&self) -> Result<bool, Error> {
        self.backend.is_sat(&self.constraints)
    }

    pub fn model(&self) -> Result<HashMap<String, String>, Error> {
        self.backend.model(&self.constraints, &self.tracked)
    }

    pub(crate) fn add_constraint(&mut self, constraint: Bool) {
        self.constraints.push(constraint);
    }

    pub(crate) fn backend(&self) -> &Z3Backend {
        &self.backend
    }

    pub(crate) fn memory(&self) -> &FlatMemory {
        &self.memory
    }

    pub(crate) fn memory_mut(&mut self) -> &mut FlatMemory {
        &mut self.memory
    }

    pub(crate) fn set_program_counter(&mut self, value: BV) {
        if let Some(name) = self.instruction_pointer_register_name(value.get_size() as u16) {
            self.registers.insert(name.to_string(), value.clone());
        }
        self.program_counter = Some(value);
    }

    pub(crate) fn get_or_create_register(&mut self, name: &str, bits: u16) -> Result<BV, Error> {
        if let Some(value) = self.registers.get(name) {
            return self.backend.coerce_bv_width(value, bits);
        }
        let symbol = format!("register:{name}");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol, TrackedAst::BitVector(value.clone()));
        self.registers.insert(name.to_string(), value.clone());
        Ok(value)
    }

    pub(crate) fn set_register_value(&mut self, name: &str, value: BV) {
        if self
            .instruction_pointer_register_name(value.get_size() as u16)
            .is_some_and(|ip_name| ip_name == name)
        {
            self.program_counter = Some(value.clone());
        }
        self.registers.insert(name.to_string(), value);
    }

    pub(crate) fn get_or_create_flag(&mut self, name: &str, bits: u16) -> Result<BV, Error> {
        if let Some(value) = self.flags.get(name) {
            return self.backend.coerce_bv_width(value, bits);
        }
        let symbol = format!("flag:{name}");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol, TrackedAst::BitVector(value.clone()));
        self.flags.insert(name.to_string(), value.clone());
        Ok(value)
    }

    pub(crate) fn set_flag_value(&mut self, name: &str, value: BV) {
        self.flags.insert(name.to_string(), value);
    }

    pub(crate) fn get_or_create_temporary(&mut self, id: u32, bits: u16) -> Result<BV, Error> {
        if let Some(value) = self.temporaries.get(&id) {
            return self.backend.coerce_bv_width(value, bits);
        }
        let symbol = format!("temporary:{id}");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol, TrackedAst::BitVector(value.clone()));
        self.temporaries.insert(id, value.clone());
        Ok(value)
    }

    pub(crate) fn set_temporary_value(&mut self, id: u32, value: BV) {
        self.temporaries.insert(id, value);
    }

    pub(crate) fn get_or_create_program_counter(&mut self, bits: u16) -> Result<BV, Error> {
        if let Some(value) = self.program_counter.as_ref() {
            return self.backend.coerce_bv_width(value, bits);
        }
        if let Some(name) = self.instruction_pointer_register_name(bits) {
            if let Some(value) = self.registers.get(name) {
                let value = self.backend.coerce_bv_width(value, bits)?;
                self.program_counter = Some(value.clone());
                return Ok(value);
            }
        }
        let symbol = "program_counter".to_string();
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol, TrackedAst::BitVector(value.clone()));
        if let Some(name) = self.instruction_pointer_register_name(bits) {
            self.registers.insert(name.to_string(), value.clone());
        }
        self.program_counter = Some(value.clone());
        Ok(value)
    }

    pub(crate) fn fresh_value(&mut self, prefix: &str, bits: u16) -> Result<BV, Error> {
        let name = format!("{prefix}#{}", self.next_fresh_id);
        self.next_fresh_id += 1;
        let value = self.backend.fresh_bv(&name, bits)?;
        self.tracked
            .insert(name, TrackedAst::BitVector(value.clone()));
        Ok(value)
    }
}
