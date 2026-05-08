use crate::semantics::{SemanticCpu, SemanticEncoding};
use crate::symbolic::Error;
use crate::symbolic::backend::z3::{TrackedAst, Z3Backend};
use crate::symbolic::memory::FlatMemory;
use crate::symbolic::slice::{Slice, SliceInstruction, SliceNode};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use z3::ast::{BV, Bool};

#[derive(Clone)]
pub(crate) struct SymbolicCell {
    pub(crate) value: BV,
    pub(crate) def_id: Option<u64>,
}

#[derive(Clone)]
struct DefinitionNode {
    id: u64,
    instruction: Option<SliceInstruction>,
    location: String,
    value: String,
    parents: Vec<u64>,
}

#[derive(Clone)]
pub struct SymbolicCpuState {
    cpu: Arc<SemanticCpu>,
    address_bits: u16,
    backend: Z3Backend,
    registers: HashMap<String, SymbolicCell>,
    flags: HashMap<String, SymbolicCell>,
    temporaries: HashMap<u32, SymbolicCell>,
    program_counter: Option<SymbolicCell>,
    memory: FlatMemory,
    indexed_memory: HashMap<String, HashMap<String, SymbolicCell>>,
    stack_memory: HashMap<String, HashMap<u32, SymbolicCell>>,
    reference_properties: HashMap<String, HashMap<String, SymbolicCell>>,
    reference_elements: HashMap<String, HashMap<String, SymbolicCell>>,
    constraints: Vec<Bool>,
    tracked: HashMap<String, TrackedAst>,
    definitions: HashMap<u64, DefinitionNode>,
    next_definition_id: u64,
    next_fresh_id: u64,
    next_reference_id: u64,
}

impl SymbolicCpuState {
    fn extract_register_alias(&self, value: &BV, alias_bits: u16, lsb: u16) -> Result<BV, Error> {
        let full_bits = value.get_size() as u16;
        if alias_bits == full_bits && lsb == 0 {
            return Ok(value.clone());
        }
        Ok(value.extract((lsb + alias_bits - 1) as u32, lsb as u32))
    }

    fn merge_register_alias(
        &self,
        current: Option<&SymbolicCell>,
        alias_value: &BV,
        full_bits: u16,
        alias_bits: u16,
        lsb: u16,
        zero_extend_on_write: bool,
    ) -> Result<BV, Error> {
        if alias_bits == full_bits && lsb == 0 {
            return self.backend.coerce_bv_width(alias_value, full_bits);
        }
        if zero_extend_on_write {
            return Ok(alias_value.zero_ext((full_bits - alias_bits) as u32));
        }

        let current = match current {
            Some(cell) => self.backend.coerce_bv_width(&cell.value, full_bits)?,
            None => self.backend.zero_bv(full_bits)?,
        };
        let alias_value = self.backend.coerce_bv_width(alias_value, alias_bits)?;
        let low_bits = lsb;
        let high_bits = full_bits - (lsb + alias_bits);

        let mut parts = Vec::new();
        if high_bits > 0 {
            parts.push(current.extract((full_bits - 1) as u32, (lsb + alias_bits) as u32));
        }
        parts.push(alias_value);
        if low_bits > 0 {
            parts.push(current.extract((lsb - 1) as u32, 0));
        }

        let mut merged = parts[0].clone();
        for part in parts.iter().skip(1) {
            merged = merged.concat(part);
        }
        Ok(merged)
    }

    fn instruction_pointer_register_name(&self, bits: u16) -> Option<&str> {
        self.cpu.program_counter_name(bits)
    }

    pub fn new(cpu: SemanticCpu) -> Self {
        Self::from_shared_cpu(Arc::new(cpu))
    }

    pub(crate) fn from_shared_cpu(cpu: Arc<SemanticCpu>) -> Self {
        let address_bits = cpu.address_bits();
        let backend = Z3Backend::new();
        Self {
            cpu,
            address_bits,
            registers: HashMap::new(),
            flags: HashMap::new(),
            temporaries: HashMap::new(),
            program_counter: None,
            memory: FlatMemory::new(&backend, address_bits as u32),
            indexed_memory: HashMap::new(),
            stack_memory: HashMap::new(),
            reference_properties: HashMap::new(),
            reference_elements: HashMap::new(),
            constraints: Vec::new(),
            tracked: HashMap::new(),
            definitions: HashMap::new(),
            next_definition_id: 0,
            next_fresh_id: 0,
            next_reference_id: 1,
            backend,
        }
    }

    pub fn cpu(&self) -> &SemanticCpu {
        &self.cpu
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
        let def_id = self.create_root_definition(format!("register:{name}"), &value, Some(symbol));
        self.set_register_value(name, value, Some(def_id));
        Ok(())
    }

    pub fn set_register(&mut self, name: &str, bits: u16, value: u64) -> Result<(), Error> {
        let value = self.backend.const_bv(value as u128, bits)?;
        self.set_register_value(name, value, None);
        Ok(())
    }

    pub fn symbolic_register(&self, name: &str, bits: u16) -> Result<Option<String>, Error> {
        let Some(value) = self.get_register_cell(name, bits)? else {
            return Ok(None);
        };
        Ok(Some(value.value.to_string()))
    }

    pub fn evaluate_register(&self, name: &str, bits: u16) -> Result<Option<u64>, Error> {
        let Some(value) = self.get_register_cell(name, bits)? else {
            return Ok(None);
        };
        self.backend.eval_bv_u64(&self.constraints, &value.value)
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
            let byte_name = format!("{prefix}[0x{:x}]", address + offset as u64);
            self.tracked
                .insert(byte_name.clone(), TrackedAst::BitVector(value.clone()));
            let def_id = self.create_root_definition(
                format!("memory[0x{:x}]", address + offset as u64),
                &value,
                Some(byte_name),
            );
            self.memory
                .set_byte_provenance(address + offset as u64, Some(def_id));
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

    pub fn program_counter(&self) -> Result<Option<u64>, Error> {
        match self.program_counter.as_ref() {
            Some(value) => self.backend.eval_bv_u64(&self.constraints, &value.value),
            None => Ok(None),
        }
    }

    pub(crate) fn eval_program_counter_u64(&self) -> Result<Option<u64>, Error> {
        self.program_counter()
    }

    pub fn evaluate_memory(&self, address: u64, size: usize) -> Result<Option<u64>, Error> {
        let address = self.backend.const_bv(address as u128, self.address_bits)?;
        let value = self
            .memory
            .load(&self.backend, &address, (size * 8) as u16)?;
        self.backend.eval_bv_u64(&self.constraints, &value)
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Result<Option<Vec<u8>>, Error> {
        let mut bytes = Vec::with_capacity(size);
        for offset in 0..size {
            let byte_address = self
                .backend
                .const_bv((address + offset as u64) as u128, self.address_bits)?;
            let byte = self.memory.load(&self.backend, &byte_address, 8)?;
            let Some(value) = self.backend.eval_bv_u64(&self.constraints, &byte)? else {
                return Ok(None);
            };
            bytes.push(value as u8);
        }
        Ok(Some(bytes))
    }

    pub fn satisfiable(&self) -> Result<bool, Error> {
        self.backend.is_sat(&self.constraints)
    }

    pub fn model(&self) -> Result<HashMap<String, String>, Error> {
        self.backend.model(&self.constraints, &self.tracked)
    }

    pub fn slice_from_register(&self, name: &str, bits: u16) -> Result<Slice, Error> {
        let Some(cell) = self.get_register_cell(name, bits)? else {
            return Ok(Slice::default());
        };
        Ok(self.slice_from_def_ids(cell.def_id.into_iter().collect()))
    }

    pub fn slice_from_memory(&self, address: u64, size: usize) -> Result<Slice, Error> {
        Ok(self.slice_from_def_ids(self.memory.provenance_for_range(address, size)))
    }

    pub(crate) fn add_constraint(&mut self, constraint: Bool) {
        self.constraints.push(constraint);
    }

    pub(crate) fn backend(&self) -> &Z3Backend {
        &self.backend
    }

    pub(crate) fn solver_constraints(&self) -> &[Bool] {
        &self.constraints
    }

    pub(crate) fn memory(&self) -> &FlatMemory {
        &self.memory
    }

    pub(crate) fn memory_mut(&mut self) -> &mut FlatMemory {
        &mut self.memory
    }

    pub(crate) fn set_program_counter(&mut self, value: BV, def_id: Option<u64>) {
        if let Some(name) = self
            .instruction_pointer_register_name(value.get_size() as u16)
            .map(str::to_string)
        {
            self.set_register_value(&name, value.clone(), def_id);
        }
        self.program_counter = Some(SymbolicCell { value, def_id });
    }

    pub(crate) fn get_or_create_register(
        &mut self,
        name: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(resolution) = self.cpu.resolve_register(name) {
            let canonical = resolution.storage_name;
            let base = if let Some(value) = self.registers.get(&canonical) {
                value.clone()
            } else {
                let symbol = format!("register:{canonical}");
                let value = self.backend.fresh_bv(&symbol, resolution.storage_bits)?;
                self.tracked
                    .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
                let def_id = self.create_root_definition(
                    format!("register:{canonical}"),
                    &value,
                    Some(symbol),
                );
                let cell = SymbolicCell {
                    value: value.clone(),
                    def_id: Some(def_id),
                };
                self.registers.insert(canonical.to_string(), cell.clone());
                cell
            };
            return Ok(SymbolicCell {
                value: self.extract_register_alias(
                    &base.value,
                    resolution.bits.min(bits),
                    resolution.offset,
                )?,
                def_id: base.def_id,
            });
        }
        if let Some(value) = self.registers.get(name) {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        let symbol = format!("register:{name}");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(format!("register:{name}"), &value, Some(symbol));
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        self.registers.insert(name.to_string(), cell.clone());
        Ok(cell)
    }

    pub(crate) fn set_register_value(&mut self, name: &str, value: BV, def_id: Option<u64>) {
        if let Some(resolution) = self.cpu.resolve_register(name) {
            let canonical = resolution.storage_name;
            let current = self.registers.get(&canonical);
            let merged = self
                .merge_register_alias(
                    current,
                    &value,
                    resolution.storage_bits,
                    resolution.bits,
                    resolution.offset,
                    resolution.zero_extend_on_write,
                )
                .expect("merge register alias");
            if self
                .instruction_pointer_register_name(merged.get_size() as u16)
                .is_some_and(|ip_name| ip_name == canonical.as_str())
            {
                self.program_counter = Some(SymbolicCell {
                    value: merged.clone(),
                    def_id,
                });
            }
            self.registers.insert(
                canonical,
                SymbolicCell {
                    value: merged,
                    def_id,
                },
            );
            return;
        }
        if self
            .instruction_pointer_register_name(value.get_size() as u16)
            .is_some_and(|ip_name| ip_name == name)
        {
            self.program_counter = Some(SymbolicCell {
                value: value.clone(),
                def_id,
            });
        }
        self.registers
            .insert(name.to_string(), SymbolicCell { value, def_id });
    }

    fn get_register_cell(&self, name: &str, bits: u16) -> Result<Option<SymbolicCell>, Error> {
        if let Some(resolution) = self.cpu.resolve_register(name) {
            let Some(base) = self.registers.get(&resolution.storage_name) else {
                return Ok(None);
            };
            return Ok(Some(SymbolicCell {
                value: self.extract_register_alias(
                    &base.value,
                    resolution.bits.min(bits),
                    resolution.offset,
                )?,
                def_id: base.def_id,
            }));
        }
        let Some(value) = self.registers.get(name) else {
            return Ok(None);
        };
        Ok(Some(SymbolicCell {
            value: self.backend.coerce_bv_width(&value.value, bits)?,
            def_id: value.def_id,
        }))
    }

    pub(crate) fn get_or_create_flag(
        &mut self,
        name: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(value) = self.flags.get(name) {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        let symbol = format!("flag:{name}");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(format!("flag:{name}"), &value, Some(symbol));
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        self.flags.insert(name.to_string(), cell.clone());
        Ok(cell)
    }

    pub(crate) fn set_flag_value(&mut self, name: &str, value: BV, def_id: Option<u64>) {
        self.flags
            .insert(name.to_string(), SymbolicCell { value, def_id });
    }

    pub(crate) fn get_or_create_temporary(
        &mut self,
        id: u32,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(value) = self.temporaries.get(&id) {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        let symbol = format!("temporary:{id}");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(format!("temporary:{id}"), &value, Some(symbol));
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        self.temporaries.insert(id, cell.clone());
        Ok(cell)
    }

    pub(crate) fn set_temporary_value(&mut self, id: u32, value: BV, def_id: Option<u64>) {
        self.temporaries.insert(id, SymbolicCell { value, def_id });
    }

    pub(crate) fn get_or_create_indexed_memory(
        &mut self,
        name: &str,
        index: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(value) = self
            .indexed_memory
            .get(name)
            .and_then(|slots| slots.get(index))
        {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        let symbol = format!("indexed_memory:{name}[{index}]");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(
            format!("indexed_memory:{name}[{index}]"),
            &value,
            Some(symbol),
        );
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        self.indexed_memory
            .entry(name.to_string())
            .or_default()
            .insert(index.to_string(), cell.clone());
        Ok(cell)
    }

    pub(crate) fn set_indexed_memory_value(
        &mut self,
        name: &str,
        index: String,
        value: BV,
        def_id: Option<u64>,
    ) {
        self.indexed_memory
            .entry(name.to_string())
            .or_default()
            .insert(index, SymbolicCell { value, def_id });
    }

    pub(crate) fn get_or_create_stack_memory(
        &mut self,
        name: &str,
        offset: u32,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(value) = self
            .stack_memory
            .get(name)
            .and_then(|slots| slots.get(&offset))
        {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        let symbol = format!("stack_memory:{name}[{offset}]");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(
            format!("stack_memory:{name}[{offset}]"),
            &value,
            Some(symbol),
        );
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        self.stack_memory
            .entry(name.to_string())
            .or_default()
            .insert(offset, cell.clone());
        Ok(cell)
    }

    pub(crate) fn set_stack_memory_value(
        &mut self,
        name: &str,
        offset: u32,
        value: BV,
        def_id: Option<u64>,
    ) {
        self.stack_memory
            .entry(name.to_string())
            .or_default()
            .insert(offset, SymbolicCell { value, def_id });
    }

    pub(crate) fn push_stack_memory_value(&mut self, name: &str, value: BV, def_id: Option<u64>) {
        let stack = self.stack_memory.entry(name.to_string()).or_default();
        let mut shifted = stack
            .iter()
            .map(|(offset, cell)| (offset.saturating_add(1), cell.clone()))
            .collect::<HashMap<_, _>>();
        shifted.insert(0, SymbolicCell { value, def_id });
        *stack = shifted;
    }

    pub(crate) fn pop_stack_memory_value(
        &mut self,
        name: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        let cell = self.get_or_create_stack_memory(name, 0, bits)?;
        let stack = self.stack_memory.entry(name.to_string()).or_default();
        let shifted = stack
            .iter()
            .filter_map(|(offset, cell)| {
                if *offset == 0 {
                    None
                } else {
                    Some((offset - 1, cell.clone()))
                }
            })
            .collect::<HashMap<_, _>>();
        *stack = shifted;
        Ok(cell)
    }

    pub(crate) fn get_or_create_program_counter(
        &mut self,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(value) = self.program_counter.as_ref() {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        if let Some(name) = self.instruction_pointer_register_name(bits) {
            if let Some(value) = self.registers.get(name) {
                let value = SymbolicCell {
                    value: self.backend.coerce_bv_width(&value.value, bits)?,
                    def_id: value.def_id,
                };
                self.program_counter = Some(value.clone());
                return Ok(value);
            }
        }
        let symbol = "program_counter".to_string();
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id =
            self.create_root_definition("program_counter".to_string(), &value, Some(symbol));
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        if let Some(name) = self.instruction_pointer_register_name(bits) {
            self.registers.insert(name.to_string(), cell.clone());
        }
        self.program_counter = Some(cell.clone());
        Ok(cell)
    }

    pub(crate) fn fresh_value(&mut self, prefix: &str, bits: u16) -> Result<SymbolicCell, Error> {
        let name = format!("{prefix}#{}", self.next_fresh_id);
        self.next_fresh_id += 1;
        let value = self.backend.fresh_bv(&name, bits)?;
        self.tracked
            .insert(name.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(name.clone(), &value, Some(name));
        Ok(SymbolicCell {
            value,
            def_id: Some(def_id),
        })
    }

    pub(crate) fn allocate_reference(
        &mut self,
        kind: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        let id = self.next_reference_id;
        self.next_reference_id = self.next_reference_id.saturating_add(1);
        let value = self.backend.const_bv(id as u128, bits)?;
        let def_id = self.create_root_definition(
            format!("reference:{kind}#{id}"),
            &value,
            Some(format!("reference:{kind}#{id}")),
        );
        Ok(SymbolicCell {
            value,
            def_id: Some(def_id),
        })
    }

    pub(crate) fn get_or_create_reference_property(
        &mut self,
        reference: &str,
        name: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(value) = self
            .reference_properties
            .get(reference)
            .and_then(|properties| properties.get(name))
        {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        let symbol = format!("reference:{reference}.{name}");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(
            format!("reference:{reference}.{name}"),
            &value,
            Some(symbol),
        );
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        self.reference_properties
            .entry(reference.to_string())
            .or_default()
            .insert(name.to_string(), cell.clone());
        Ok(cell)
    }

    pub(crate) fn set_reference_property_value(
        &mut self,
        reference: String,
        name: String,
        value: BV,
        def_id: Option<u64>,
    ) {
        self.reference_properties
            .entry(reference)
            .or_default()
            .insert(name, SymbolicCell { value, def_id });
    }

    pub(crate) fn get_or_create_reference_element(
        &mut self,
        reference: &str,
        index: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some(value) = self
            .reference_elements
            .get(reference)
            .and_then(|elements| elements.get(index))
        {
            return Ok(SymbolicCell {
                value: self.backend.coerce_bv_width(&value.value, bits)?,
                def_id: value.def_id,
            });
        }
        let symbol = format!("reference:{reference}[{index}]");
        let value = self.backend.fresh_bv(&symbol, bits)?;
        self.tracked
            .insert(symbol.clone(), TrackedAst::BitVector(value.clone()));
        let def_id = self.create_root_definition(
            format!("reference:{reference}[{index}]"),
            &value,
            Some(symbol),
        );
        let cell = SymbolicCell {
            value: value.clone(),
            def_id: Some(def_id),
        };
        self.reference_elements
            .entry(reference.to_string())
            .or_default()
            .insert(index.to_string(), cell.clone());
        Ok(cell)
    }

    pub(crate) fn set_reference_element_value(
        &mut self,
        reference: String,
        index: String,
        value: BV,
        def_id: Option<u64>,
    ) {
        self.reference_elements
            .entry(reference)
            .or_default()
            .insert(index, SymbolicCell { value, def_id });
    }

    pub(crate) fn define_location(
        &mut self,
        instruction: Option<&SemanticEncoding>,
        location: String,
        value: &BV,
        parents: &BTreeSet<u64>,
    ) -> Option<u64> {
        if parents.is_empty() {
            return None;
        }
        let id = self.next_definition_id;
        self.next_definition_id += 1;
        self.definitions.insert(
            id,
            DefinitionNode {
                id,
                instruction: instruction.map(SliceInstruction::from_encoding),
                location,
                value: value.to_string(),
                parents: parents.iter().copied().collect(),
            },
        );
        Some(id)
    }

    fn create_root_definition(
        &mut self,
        location: String,
        value: &BV,
        tracked_name: Option<String>,
    ) -> u64 {
        let id = self.next_definition_id;
        self.next_definition_id += 1;
        self.definitions.insert(
            id,
            DefinitionNode {
                id,
                instruction: None,
                location,
                value: tracked_name.unwrap_or_else(|| value.to_string()),
                parents: Vec::new(),
            },
        );
        id
    }

    fn slice_from_def_ids(&self, roots: BTreeSet<u64>) -> Slice {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        for root in roots {
            if visited.insert(root) {
                queue.push_back(root);
            }
        }

        while let Some(id) = queue.pop_front() {
            if let Some(node) = self.definitions.get(&id) {
                for parent in &node.parents {
                    if visited.insert(*parent) {
                        queue.push_back(*parent);
                    }
                }
            }
        }

        let mut items = visited
            .into_iter()
            .filter_map(|id| self.definitions.get(&id))
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by_key(|item| item.id);
        Slice::new(
            items
                .into_iter()
                .map(|item| SliceNode {
                    id: item.id,
                    instruction: item.instruction,
                    location: item.location,
                    value: item.value,
                    parents: item.parents,
                })
                .collect(),
        )
    }
}
