use crate::Architecture;
use crate::semantics::InstructionEncoding;
use crate::symbolic::Error;
use crate::symbolic::backend::z3::{TrackedAst, Z3Backend};
use crate::symbolic::memory::FlatMemory;
use crate::symbolic::slice::{Slice, SliceInstruction, SliceNode};
use std::collections::{BTreeSet, HashMap, VecDeque};
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
pub struct State {
    architecture: Architecture,
    address_bits: u16,
    backend: Z3Backend,
    registers: HashMap<String, SymbolicCell>,
    flags: HashMap<String, SymbolicCell>,
    temporaries: HashMap<u32, SymbolicCell>,
    program_counter: Option<SymbolicCell>,
    memory: FlatMemory,
    constraints: Vec<Bool>,
    tracked: HashMap<String, TrackedAst>,
    definitions: HashMap<u64, DefinitionNode>,
    next_definition_id: u64,
    next_fresh_id: u64,
}

impl State {
    fn x86_register_alias(&self, name: &str) -> Option<(&'static str, u16, u16, u16, bool)> {
        match self.architecture {
            Architecture::AMD64 => match name {
                "al" => Some(("rax", 64, 0, 8, false)),
                "ah" => Some(("rax", 64, 8, 8, false)),
                "ax" => Some(("rax", 64, 0, 16, false)),
                "eax" => Some(("rax", 64, 0, 32, true)),
                "rax" => Some(("rax", 64, 0, 64, false)),
                "bl" => Some(("rbx", 64, 0, 8, false)),
                "bh" => Some(("rbx", 64, 8, 8, false)),
                "bx" => Some(("rbx", 64, 0, 16, false)),
                "ebx" => Some(("rbx", 64, 0, 32, true)),
                "rbx" => Some(("rbx", 64, 0, 64, false)),
                "cl" => Some(("rcx", 64, 0, 8, false)),
                "ch" => Some(("rcx", 64, 8, 8, false)),
                "cx" => Some(("rcx", 64, 0, 16, false)),
                "ecx" => Some(("rcx", 64, 0, 32, true)),
                "rcx" => Some(("rcx", 64, 0, 64, false)),
                "dl" => Some(("rdx", 64, 0, 8, false)),
                "dh" => Some(("rdx", 64, 8, 8, false)),
                "dx" => Some(("rdx", 64, 0, 16, false)),
                "edx" => Some(("rdx", 64, 0, 32, true)),
                "rdx" => Some(("rdx", 64, 0, 64, false)),
                "sil" => Some(("rsi", 64, 0, 8, false)),
                "si" => Some(("rsi", 64, 0, 16, false)),
                "esi" => Some(("rsi", 64, 0, 32, true)),
                "rsi" => Some(("rsi", 64, 0, 64, false)),
                "dil" => Some(("rdi", 64, 0, 8, false)),
                "di" => Some(("rdi", 64, 0, 16, false)),
                "edi" => Some(("rdi", 64, 0, 32, true)),
                "rdi" => Some(("rdi", 64, 0, 64, false)),
                "bpl" => Some(("rbp", 64, 0, 8, false)),
                "bp" => Some(("rbp", 64, 0, 16, false)),
                "ebp" => Some(("rbp", 64, 0, 32, true)),
                "rbp" => Some(("rbp", 64, 0, 64, false)),
                "spl" => Some(("rsp", 64, 0, 8, false)),
                "sp" => Some(("rsp", 64, 0, 16, false)),
                "esp" => Some(("rsp", 64, 0, 32, true)),
                "rsp" => Some(("rsp", 64, 0, 64, false)),
                "r8b" => Some(("r8", 64, 0, 8, false)),
                "r8w" => Some(("r8", 64, 0, 16, false)),
                "r8d" => Some(("r8", 64, 0, 32, true)),
                "r8" => Some(("r8", 64, 0, 64, false)),
                "r9b" => Some(("r9", 64, 0, 8, false)),
                "r9w" => Some(("r9", 64, 0, 16, false)),
                "r9d" => Some(("r9", 64, 0, 32, true)),
                "r9" => Some(("r9", 64, 0, 64, false)),
                "r10b" => Some(("r10", 64, 0, 8, false)),
                "r10w" => Some(("r10", 64, 0, 16, false)),
                "r10d" => Some(("r10", 64, 0, 32, true)),
                "r10" => Some(("r10", 64, 0, 64, false)),
                "r11b" => Some(("r11", 64, 0, 8, false)),
                "r11w" => Some(("r11", 64, 0, 16, false)),
                "r11d" => Some(("r11", 64, 0, 32, true)),
                "r11" => Some(("r11", 64, 0, 64, false)),
                "r12b" => Some(("r12", 64, 0, 8, false)),
                "r12w" => Some(("r12", 64, 0, 16, false)),
                "r12d" => Some(("r12", 64, 0, 32, true)),
                "r12" => Some(("r12", 64, 0, 64, false)),
                "r13b" => Some(("r13", 64, 0, 8, false)),
                "r13w" => Some(("r13", 64, 0, 16, false)),
                "r13d" => Some(("r13", 64, 0, 32, true)),
                "r13" => Some(("r13", 64, 0, 64, false)),
                "r14b" => Some(("r14", 64, 0, 8, false)),
                "r14w" => Some(("r14", 64, 0, 16, false)),
                "r14d" => Some(("r14", 64, 0, 32, true)),
                "r14" => Some(("r14", 64, 0, 64, false)),
                "r15b" => Some(("r15", 64, 0, 8, false)),
                "r15w" => Some(("r15", 64, 0, 16, false)),
                "r15d" => Some(("r15", 64, 0, 32, true)),
                "r15" => Some(("r15", 64, 0, 64, false)),
                _ => None,
            },
            Architecture::I386 => match name {
                "al" => Some(("eax", 32, 0, 8, false)),
                "ah" => Some(("eax", 32, 8, 8, false)),
                "ax" => Some(("eax", 32, 0, 16, false)),
                "eax" => Some(("eax", 32, 0, 32, false)),
                "bl" => Some(("ebx", 32, 0, 8, false)),
                "bh" => Some(("ebx", 32, 8, 8, false)),
                "bx" => Some(("ebx", 32, 0, 16, false)),
                "ebx" => Some(("ebx", 32, 0, 32, false)),
                "cl" => Some(("ecx", 32, 0, 8, false)),
                "ch" => Some(("ecx", 32, 8, 8, false)),
                "cx" => Some(("ecx", 32, 0, 16, false)),
                "ecx" => Some(("ecx", 32, 0, 32, false)),
                "dl" => Some(("edx", 32, 0, 8, false)),
                "dh" => Some(("edx", 32, 8, 8, false)),
                "dx" => Some(("edx", 32, 0, 16, false)),
                "edx" => Some(("edx", 32, 0, 32, false)),
                "si" => Some(("esi", 32, 0, 16, false)),
                "esi" => Some(("esi", 32, 0, 32, false)),
                "di" => Some(("edi", 32, 0, 16, false)),
                "edi" => Some(("edi", 32, 0, 32, false)),
                "bp" => Some(("ebp", 32, 0, 16, false)),
                "ebp" => Some(("ebp", 32, 0, 32, false)),
                "sp" => Some(("esp", 32, 0, 16, false)),
                "esp" => Some(("esp", 32, 0, 32, false)),
                _ => None,
            },
            _ => None,
        }
    }

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
            definitions: HashMap::new(),
            next_definition_id: 0,
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

    #[cfg(test)]
    pub(crate) fn eval_program_counter_u64(&self) -> Result<Option<u64>, Error> {
        match self.program_counter.as_ref() {
            Some(value) => self.backend.eval_bv_u64(&self.constraints, &value.value),
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
        if let Some(name) = self.instruction_pointer_register_name(value.get_size() as u16) {
            self.registers.insert(
                name.to_string(),
                SymbolicCell {
                    value: value.clone(),
                    def_id,
                },
            );
        }
        self.program_counter = Some(SymbolicCell { value, def_id });
    }

    pub(crate) fn get_or_create_register(
        &mut self,
        name: &str,
        bits: u16,
    ) -> Result<SymbolicCell, Error> {
        if let Some((canonical, full_bits, lsb, alias_bits, _)) = self.x86_register_alias(name) {
            let base = if let Some(value) = self.registers.get(canonical) {
                value.clone()
            } else {
                let symbol = format!("register:{canonical}");
                let value = self.backend.fresh_bv(&symbol, full_bits)?;
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
                value: self.extract_register_alias(&base.value, alias_bits, lsb)?,
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
        if let Some((canonical, full_bits, lsb, alias_bits, zero_extend_on_write)) =
            self.x86_register_alias(name)
        {
            let current = self.registers.get(canonical);
            let merged = self
                .merge_register_alias(
                    current,
                    &value,
                    full_bits,
                    alias_bits,
                    lsb,
                    zero_extend_on_write,
                )
                .expect("merge register alias");
            if self
                .instruction_pointer_register_name(merged.get_size() as u16)
                .is_some_and(|ip_name| ip_name == canonical)
            {
                self.program_counter = Some(SymbolicCell {
                    value: merged.clone(),
                    def_id,
                });
            }
            self.registers.insert(
                canonical.to_string(),
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
        if let Some((canonical, _, lsb, alias_bits, _)) = self.x86_register_alias(name) {
            let Some(base) = self.registers.get(canonical) else {
                return Ok(None);
            };
            return Ok(Some(SymbolicCell {
                value: self.extract_register_alias(&base.value, alias_bits, lsb)?,
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

    pub(crate) fn define_location(
        &mut self,
        instruction: Option<&InstructionEncoding>,
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
