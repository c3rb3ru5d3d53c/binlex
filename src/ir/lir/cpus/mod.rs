use crate::Architecture;
use crate::symbolic::Error;
use ::capstone::{RegId, arch::arm64::Arm64Reg};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod amd64;
pub mod arm64;
pub mod cil;
pub mod i386;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirCpuKind {
    I386,
    Amd64,
    Arm64,
    Cil,
}

impl LirCpuKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::I386 => "i386",
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
            Self::Cil => "cil",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirCpuEndian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirCpuAliasWritePolicy {
    Preserve,
    ZeroExtend,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirCpuRegister {
    pub name: String,
    pub bits: u16,
}

impl LirCpuRegister {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirCpuAlias {
    pub name: String,
    pub parent: String,
    pub offset: u16,
    pub bits: u16,
    pub write_policy: LirCpuAliasWritePolicy,
}

impl LirCpuAlias {
    pub fn new(name: impl Into<String>, parent: impl Into<String>, offset: u16, bits: u16) -> Self {
        Self {
            name: name.into(),
            parent: parent.into(),
            offset,
            bits,
            write_policy: LirCpuAliasWritePolicy::Preserve,
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
            write_policy: LirCpuAliasWritePolicy::ZeroExtend,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirCpuProgramCounter {
    pub name: String,
    pub bits: u16,
}

impl LirCpuProgramCounter {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirMemory {
    Indexed(LirMemoryIndexed),
    Stack(LirMemoryStack),
    Addressed(LirMemoryAddressed),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirMemoryIndexed {
    pub name: String,
}

impl LirMemoryIndexed {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirMemoryStack {
    pub name: String,
}

impl LirMemoryStack {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirMemoryAddressed {
    pub name: String,
    pub address_bits: u16,
    pub endian: LirCpuEndian,
}

impl LirMemoryAddressed {
    pub fn new(name: impl Into<String>, address_bits: u16, endian: LirCpuEndian) -> Self {
        Self {
            name: name.into(),
            address_bits,
            endian,
        }
    }
}

impl LirMemory {
    pub fn indexed(name: impl Into<String>) -> Self {
        Self::Indexed(LirMemoryIndexed::new(name))
    }

    pub fn stack(name: impl Into<String>) -> Self {
        Self::Stack(LirMemoryStack::new(name))
    }

    pub fn addressed(name: impl Into<String>, address_bits: u16, endian: LirCpuEndian) -> Self {
        Self::Addressed(LirMemoryAddressed::new(name, address_bits, endian))
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Indexed(memory) => &memory.name,
            Self::Stack(memory) => &memory.name,
            Self::Addressed(memory) => &memory.name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirCpu {
    kind: Option<LirCpuKind>,
    name: String,
    address_bits: u16,
    endian: LirCpuEndian,
    registers: BTreeMap<String, LirCpuRegister>,
    aliases: BTreeMap<String, LirCpuAlias>,
    program_counter: Option<LirCpuProgramCounter>,
    memory: BTreeMap<String, LirMemory>,
}

#[derive(Clone, Debug)]
pub(crate) struct LirCpuRegisterResolution {
    pub(crate) storage_name: String,
    pub(crate) storage_bits: u16,
    pub(crate) offset: u16,
    pub(crate) bits: u16,
    pub(crate) zero_extend_on_write: bool,
}

impl LirCpu {
    pub fn new(
        name: impl Into<String>,
        address_bits: u16,
        endian: LirCpuEndian,
        registers: Vec<LirCpuRegister>,
        aliases: Vec<LirCpuAlias>,
        program_counter: Option<LirCpuProgramCounter>,
        memory: Vec<LirMemory>,
    ) -> Result<Self, Error> {
        Self::build(
            None,
            name.into(),
            address_bits,
            endian,
            registers,
            aliases,
            program_counter,
            memory,
        )
    }

    pub(crate) fn builtin(
        kind: LirCpuKind,
        name: impl Into<String>,
        address_bits: u16,
        endian: LirCpuEndian,
        registers: Vec<LirCpuRegister>,
        aliases: Vec<LirCpuAlias>,
        program_counter: Option<LirCpuProgramCounter>,
        memory: Vec<LirMemory>,
    ) -> Result<Self, Error> {
        Self::build(
            Some(kind),
            name.into(),
            address_bits,
            endian,
            registers,
            aliases,
            program_counter,
            memory,
        )
    }

    fn build(
        kind: Option<LirCpuKind>,
        name: String,
        address_bits: u16,
        endian: LirCpuEndian,
        registers: Vec<LirCpuRegister>,
        aliases: Vec<LirCpuAlias>,
        program_counter: Option<LirCpuProgramCounter>,
        memory: Vec<LirMemory>,
    ) -> Result<Self, Error> {
        let cpu = Self {
            kind,
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

    pub fn from_kind(kind: LirCpuKind) -> Result<Self, Error> {
        match kind {
            LirCpuKind::I386 => i386::build(),
            LirCpuKind::Amd64 => amd64::build(),
            LirCpuKind::Arm64 => arm64::build(),
            LirCpuKind::Cil => cil::build(),
        }
    }

    pub fn i386() -> Result<Self, Error> {
        Self::from_kind(LirCpuKind::I386)
    }

    pub fn amd64() -> Result<Self, Error> {
        Self::from_kind(LirCpuKind::Amd64)
    }

    pub fn arm64() -> Result<Self, Error> {
        Self::from_kind(LirCpuKind::Arm64)
    }

    pub fn cil() -> Result<Self, Error> {
        Self::from_kind(LirCpuKind::Cil)
    }

    pub fn from_architecture(architecture: Architecture) -> Result<Self, Error> {
        match architecture {
            Architecture::I386 => Self::from_kind(LirCpuKind::I386),
            Architecture::AMD64 => Self::from_kind(LirCpuKind::Amd64),
            Architecture::ARM64 => Self::from_kind(LirCpuKind::Arm64),
            Architecture::CIL => Self::from_kind(LirCpuKind::Cil),
            Architecture::UNKNOWN => Err(Error::UnsupportedCpu("unknown".to_string())),
        }
    }

    pub fn kind(&self) -> Option<LirCpuKind> {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address_bits(&self) -> u16 {
        self.address_bits
    }

    pub fn endian(&self) -> LirCpuEndian {
        self.endian
    }

    pub fn registers(&self) -> Vec<LirCpuRegister> {
        self.registers.values().cloned().collect()
    }

    pub fn aliases(&self) -> Vec<LirCpuAlias> {
        self.aliases.values().cloned().collect()
    }

    pub fn program_counter(&self) -> Option<&LirCpuProgramCounter> {
        self.program_counter.as_ref()
    }

    pub fn memory(&self) -> Vec<LirMemory> {
        self.memory.values().cloned().collect()
    }

    pub fn semantic_register_name(&self, register_name: &str) -> Option<String> {
        match self.kind {
            Some(kind) => semantic_register_name(kind, register_name),
            None => self
                .resolve_register(register_name)
                .map(|_| register_name.trim().to_ascii_lowercase()),
        }
    }

    pub(crate) fn resolve_register(&self, name: &str) -> Option<LirCpuRegisterResolution> {
        if let Some(register) = self.registers.get(name) {
            return Some(LirCpuRegisterResolution {
                storage_name: register.name.clone(),
                storage_bits: register.bits,
                offset: 0,
                bits: register.bits,
                zero_extend_on_write: false,
            });
        }
        let alias = self.aliases.get(name)?;
        let parent = self.registers.get(&alias.parent)?;
        Some(LirCpuRegisterResolution {
            storage_name: parent.name.clone(),
            storage_bits: parent.bits,
            offset: alias.offset,
            bits: alias.bits,
            zero_extend_on_write: matches!(alias.write_policy, LirCpuAliasWritePolicy::ZeroExtend),
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
            if matches!(alias.write_policy, LirCpuAliasWritePolicy::ZeroExtend) && alias.offset != 0
            {
                return Err(Error::InvalidCpu(format!(
                    "zero-extend alias {} must start at bit 0",
                    alias.name
                )));
            }
        }
        for memory in self.memory.values() {
            validate_name(memory.name(), "memory")?;
            if let LirMemory::Addressed(memory) = memory {
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

pub fn semantic_register_name(kind: LirCpuKind, register_name: &str) -> Option<String> {
    match kind {
        LirCpuKind::Arm64 => arm64_semantic_register_name(register_name),
        _ => Some(register_name.trim().to_ascii_lowercase()),
    }
}

fn arm64_semantic_register_name(register_name: &str) -> Option<String> {
    Some(format!(
        "reg_{}",
        arm64_semantic_register_id_from_text(register_name)?
    ))
}

fn arm64_semantic_register_id_from_text(token: &str) -> Option<u16> {
    let normalized = token.trim().to_ascii_lowercase();
    let reg_id = match normalized.as_str() {
        "sp" => Arm64Reg::ARM64_REG_SP as u16,
        "wsp" => Arm64Reg::ARM64_REG_SP as u16,
        "fp" => Arm64Reg::ARM64_REG_X29 as u16,
        "lr" => Arm64Reg::ARM64_REG_X30 as u16,
        "xzr" => Arm64Reg::ARM64_REG_XZR as u16,
        "wzr" => Arm64Reg::ARM64_REG_WZR as u16,
        _ => {
            let (prefix, number) = arm64_parse_indexed_register(&normalized)?;
            (match prefix {
                'x' if number <= 28 => Arm64Reg::ARM64_REG_X0 as u32 + number as u32,
                'x' if number == 29 => Arm64Reg::ARM64_REG_X29 as u32,
                'x' if number == 30 => Arm64Reg::ARM64_REG_X30 as u32,
                'w' if number <= 30 => Arm64Reg::ARM64_REG_W0 as u32 + number as u32,
                'v' if number <= 31 => Arm64Reg::ARM64_REG_V0 as u32 + number as u32,
                'q' if number <= 31 => Arm64Reg::ARM64_REG_Q0 as u32 + number as u32,
                'd' if number <= 31 => Arm64Reg::ARM64_REG_D0 as u32 + number as u32,
                's' if number <= 31 => Arm64Reg::ARM64_REG_S0 as u32 + number as u32,
                'h' if number <= 31 => Arm64Reg::ARM64_REG_H0 as u32 + number as u32,
                'b' if number <= 31 => Arm64Reg::ARM64_REG_B0 as u32 + number as u32,
                _ => return None,
            }) as u16
        }
    };
    Some(arm64_canonical_semantic_register_id(reg_id))
}

fn arm64_parse_indexed_register(token: &str) -> Option<(char, u16)> {
    let normalized = token.trim().to_ascii_lowercase();
    let mut chars = normalized.chars();
    let prefix = chars.next()?;
    let number = chars.as_str().parse::<u16>().ok()?;
    Some((prefix, number))
}

fn arm64_canonical_semantic_register_id(reg_id: u16) -> u16 {
    match RegId(reg_id).0 as u32 {
        id if id == Arm64Reg::ARM64_REG_FP => Arm64Reg::ARM64_REG_X29 as u16,
        id if id == Arm64Reg::ARM64_REG_LR => Arm64Reg::ARM64_REG_X30 as u16,
        id if id == Arm64Reg::ARM64_REG_WSP => Arm64Reg::ARM64_REG_SP as u16,
        _ => reg_id,
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
