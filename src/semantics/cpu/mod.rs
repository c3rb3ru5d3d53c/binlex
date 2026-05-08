use crate::Architecture;
use crate::symbolic::Error;
use std::collections::BTreeMap;

pub mod builtins;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticCpuEndian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticCpuAliasWritePolicy {
    Preserve,
    ZeroExtend,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticCpuRegister {
    pub name: String,
    pub bits: u16,
}

impl SemanticCpuRegister {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticCpuAlias {
    pub name: String,
    pub parent: String,
    pub offset: u16,
    pub bits: u16,
    pub write_policy: SemanticCpuAliasWritePolicy,
}

impl SemanticCpuAlias {
    pub fn new(name: impl Into<String>, parent: impl Into<String>, offset: u16, bits: u16) -> Self {
        Self {
            name: name.into(),
            parent: parent.into(),
            offset,
            bits,
            write_policy: SemanticCpuAliasWritePolicy::Preserve,
        }
    }

    pub fn zero_extend(
        name: impl Into<String>,
        parent: impl Into<String>,
        offset: u16,
        bits: u16,
    ) -> Self {
        Self {
            name: name.into(),
            parent: parent.into(),
            offset,
            bits,
            write_policy: SemanticCpuAliasWritePolicy::ZeroExtend,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticCpuProgramCounter {
    pub name: String,
    pub bits: u16,
}

impl SemanticCpuProgramCounter {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticMemory {
    Indexed(SemanticMemoryIndexed),
    Stack(SemanticMemoryStack),
    Addressed(SemanticMemoryAddressed),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticMemoryIndexed {
    pub name: String,
}

impl SemanticMemoryIndexed {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticMemoryStack {
    pub name: String,
}

impl SemanticMemoryStack {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticMemoryAddressed {
    pub name: String,
    pub address_bits: u16,
    pub endian: SemanticCpuEndian,
}

impl SemanticMemoryAddressed {
    pub fn new(name: impl Into<String>, address_bits: u16, endian: SemanticCpuEndian) -> Self {
        Self {
            name: name.into(),
            address_bits,
            endian,
        }
    }
}

impl SemanticMemory {
    pub fn indexed(name: impl Into<String>) -> Self {
        Self::Indexed(SemanticMemoryIndexed::new(name))
    }

    pub fn stack(name: impl Into<String>) -> Self {
        Self::Stack(SemanticMemoryStack::new(name))
    }

    pub fn addressed(
        name: impl Into<String>,
        address_bits: u16,
        endian: SemanticCpuEndian,
    ) -> Self {
        Self::Addressed(SemanticMemoryAddressed::new(name, address_bits, endian))
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Indexed(memory) => &memory.name,
            Self::Stack(memory) => &memory.name,
            Self::Addressed(memory) => &memory.name,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SemanticCpu {
    name: String,
    address_bits: u16,
    endian: SemanticCpuEndian,
    registers: BTreeMap<String, SemanticCpuRegister>,
    aliases: BTreeMap<String, SemanticCpuAlias>,
    program_counter: Option<SemanticCpuProgramCounter>,
    memory: BTreeMap<String, SemanticMemory>,
}

#[derive(Clone, Debug)]
pub(crate) struct SemanticCpuRegisterResolution {
    pub(crate) storage_name: String,
    pub(crate) storage_bits: u16,
    pub(crate) offset: u16,
    pub(crate) bits: u16,
    pub(crate) zero_extend_on_write: bool,
}

impl SemanticCpu {
    pub fn new(
        name: impl Into<String>,
        address_bits: u16,
        endian: SemanticCpuEndian,
        registers: Vec<SemanticCpuRegister>,
        aliases: Vec<SemanticCpuAlias>,
        program_counter: Option<SemanticCpuProgramCounter>,
        memory: Vec<SemanticMemory>,
    ) -> Result<Self, Error> {
        let cpu = Self {
            name: name.into(),
            address_bits,
            endian,
            registers: registers
                .into_iter()
                .map(|register| (register.name.clone(), register))
                .collect(),
            aliases: aliases
                .into_iter()
                .map(|alias| (alias.name.clone(), alias))
                .collect(),
            program_counter,
            memory: memory
                .into_iter()
                .map(|memory| (memory.name().to_string(), memory))
                .collect(),
        };
        cpu.validate()?;
        Ok(cpu)
    }

    pub fn from_architecture(architecture: Architecture) -> Result<Self, Error> {
        match architecture {
            Architecture::I386 => Self::i386(),
            Architecture::AMD64 => Self::amd64(),
            Architecture::ARM64 => Self::arm64(),
            Architecture::CIL => Self::cil(),
            Architecture::UNKNOWN => Err(Error::UnsupportedCpu("unknown".to_string())),
        }
    }

    pub fn i386() -> Result<Self, Error> {
        builtins::i386()
    }

    pub fn amd64() -> Result<Self, Error> {
        builtins::amd64()
    }

    pub fn arm64() -> Result<Self, Error> {
        builtins::arm64()
    }

    pub fn cil() -> Result<Self, Error> {
        builtins::cil()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address_bits(&self) -> u16 {
        self.address_bits
    }

    pub fn endian(&self) -> SemanticCpuEndian {
        self.endian
    }

    pub fn registers(&self) -> Vec<SemanticCpuRegister> {
        self.registers.values().cloned().collect()
    }

    pub fn aliases(&self) -> Vec<SemanticCpuAlias> {
        self.aliases.values().cloned().collect()
    }

    pub fn program_counter(&self) -> Option<&SemanticCpuProgramCounter> {
        self.program_counter.as_ref()
    }

    pub fn memory(&self) -> Vec<SemanticMemory> {
        self.memory.values().cloned().collect()
    }

    pub(crate) fn resolve_register(&self, name: &str) -> Option<SemanticCpuRegisterResolution> {
        if let Some(register) = self.registers.get(name) {
            return Some(SemanticCpuRegisterResolution {
                storage_name: register.name.clone(),
                storage_bits: register.bits,
                offset: 0,
                bits: register.bits,
                zero_extend_on_write: false,
            });
        }
        let alias = self.aliases.get(name)?;
        let parent = self.registers.get(&alias.parent)?;
        Some(SemanticCpuRegisterResolution {
            storage_name: parent.name.clone(),
            storage_bits: parent.bits,
            offset: alias.offset,
            bits: alias.bits,
            zero_extend_on_write: matches!(
                alias.write_policy,
                SemanticCpuAliasWritePolicy::ZeroExtend
            ),
        })
    }

    pub(crate) fn program_counter_name(&self, bits: u16) -> Option<&str> {
        self.program_counter
            .as_ref()
            .filter(|program_counter| program_counter.bits == bits)
            .map(|program_counter| program_counter.name.as_str())
    }

    fn validate(&self) -> Result<(), Error> {
        validate_bits(self.address_bits, "address width")?;
        if self.name.trim().is_empty() {
            return Err(Error::InvalidCpu("CPU name must not be empty".to_string()));
        }
        for register in self.registers.values() {
            validate_name(&register.name, "register")?;
            validate_bits(register.bits, &format!("register {}", register.name))?;
        }
        for alias in self.aliases.values() {
            validate_name(&alias.name, "alias")?;
            validate_bits(alias.bits, &format!("alias {}", alias.name))?;
            if self.registers.contains_key(&alias.name) {
                return Err(Error::InvalidCpu(format!(
                    "alias {} conflicts with a register",
                    alias.name
                )));
            }
            let Some(parent) = self.registers.get(&alias.parent) else {
                return Err(Error::InvalidCpu(format!(
                    "alias {} references missing parent register {}",
                    alias.name, alias.parent
                )));
            };
            if alias.offset.saturating_add(alias.bits) > parent.bits {
                return Err(Error::InvalidCpu(format!(
                    "alias {} exceeds parent register {}",
                    alias.name, parent.name
                )));
            }
            if matches!(alias.write_policy, SemanticCpuAliasWritePolicy::ZeroExtend)
                && alias.offset != 0
            {
                return Err(Error::InvalidCpu(format!(
                    "zero-extend alias {} must start at bit 0",
                    alias.name
                )));
            }
        }
        for memory in self.memory.values() {
            validate_name(memory.name(), "memory")?;
            if let SemanticMemory::Addressed(memory) = memory {
                validate_bits(memory.address_bits, &format!("memory {}", memory.name))?;
            }
        }
        if let Some(program_counter) = &self.program_counter {
            validate_name(&program_counter.name, "program counter")?;
            validate_bits(program_counter.bits, "program counter")?;
            let Some(resolution) = self.resolve_register(&program_counter.name) else {
                return Err(Error::InvalidCpu(format!(
                    "program counter {} is not a register or alias",
                    program_counter.name
                )));
            };
            if resolution.bits != program_counter.bits {
                return Err(Error::InvalidCpu(format!(
                    "program counter {} declares {} bits but resolves to {} bits",
                    program_counter.name, program_counter.bits, resolution.bits
                )));
            }
        }
        Ok(())
    }
}

fn validate_name(name: &str, kind: &str) -> Result<(), Error> {
    if name.trim().is_empty() {
        return Err(Error::InvalidCpu(format!("{kind} name must not be empty")));
    }
    Ok(())
}

fn validate_bits(bits: u16, label: &str) -> Result<(), Error> {
    if bits == 0 {
        return Err(Error::InvalidCpu(format!(
            "{label} must have non-zero bits"
        )));
    }
    Ok(())
}
