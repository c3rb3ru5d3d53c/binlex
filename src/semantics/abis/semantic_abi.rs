use crate::semantics::{SemanticCpu, SemanticLocation, SemanticTrapKind};
use crate::Architecture;
use crate::symbolic::Error;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticAbiKind {
    SysV,
    Windows64,
    Cdecl,
    Stdcall,
    Fastcall,
    LinuxSyscall,
    WindowsSyscall,
}

impl SemanticAbiKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::SysV => "sysv",
            Self::Windows64 => "windows64",
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Fastcall => "fastcall",
            Self::LinuxSyscall => "linux_syscall",
            Self::WindowsSyscall => "windows_syscall",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticAbi {
    pub name: String,
    pub cpu: SemanticCpu,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub function_arguments: Vec<SemanticLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub return_locations: Vec<SemanticLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_return_bits: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub traps: Vec<SemanticAbiTrap>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticAbiTrap {
    pub kind: SemanticTrapKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argument_registers: Vec<SemanticLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_register: Option<SemanticLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_registers: Vec<SemanticLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shadow_registers: Vec<SemanticLocation>,
}

impl SemanticAbi {
    pub fn new(
        name: String,
        cpu: SemanticCpu,
        function_arguments: Vec<SemanticLocation>,
        return_locations: Vec<SemanticLocation>,
        function_return_bits: Option<u16>,
        traps: Vec<SemanticAbiTrap>,
    ) -> Self {
        Self {
            name,
            cpu,
            function_arguments,
            return_locations,
            function_return_bits,
            traps,
        }
    }

    pub fn from_kind(kind: SemanticAbiKind, cpu: &SemanticCpu) -> Result<Self, Error> {
        super::build_builtin(kind, cpu)
    }

    pub fn sysv(cpu: &SemanticCpu) -> Result<Self, Error> {
        Self::from_kind(SemanticAbiKind::SysV, cpu)
    }

    pub fn windows64(cpu: &SemanticCpu) -> Result<Self, Error> {
        Self::from_kind(SemanticAbiKind::Windows64, cpu)
    }

    pub fn cdecl(cpu: &SemanticCpu) -> Result<Self, Error> {
        Self::from_kind(SemanticAbiKind::Cdecl, cpu)
    }

    pub fn stdcall(cpu: &SemanticCpu) -> Result<Self, Error> {
        Self::from_kind(SemanticAbiKind::Stdcall, cpu)
    }

    pub fn fastcall(cpu: &SemanticCpu) -> Result<Self, Error> {
        Self::from_kind(SemanticAbiKind::Fastcall, cpu)
    }

    pub fn linux_syscall(cpu: &SemanticCpu) -> Result<Self, Error> {
        Self::from_kind(SemanticAbiKind::LinuxSyscall, cpu)
    }

    pub fn windows_syscall(cpu: &SemanticCpu) -> Result<Self, Error> {
        Self::from_kind(SemanticAbiKind::WindowsSyscall, cpu)
    }

    pub fn custom(name: impl Into<String>, cpu: SemanticCpu) -> Self {
        Self::new(name.into(), cpu, Vec::new(), Vec::new(), None, Vec::new())
    }

    pub fn supports_cpu(&self, cpu: &SemanticCpu) -> bool {
        &self.cpu == cpu
    }

    pub fn supports_architecture(&self, architecture: Architecture) -> bool {
        matches!(
            (self.cpu.kind(), architecture),
            (Some(crate::semantics::SemanticCpuKind::I386), Architecture::I386)
                | (Some(crate::semantics::SemanticCpuKind::Amd64), Architecture::AMD64)
                | (Some(crate::semantics::SemanticCpuKind::Arm64), Architecture::ARM64)
                | (Some(crate::semantics::SemanticCpuKind::Cil), Architecture::CIL)
        )
    }

    pub fn is_named(&self, name: &str) -> bool {
        self.name == name
    }

    pub fn is_linux_syscall(&self) -> bool {
        self.is_named("linux_syscall")
    }

    pub fn is_windows_syscall(&self) -> bool {
        self.is_named("windows_syscall")
    }

    pub fn is_native_syscall(&self) -> bool {
        self.is_linux_syscall() || self.is_windows_syscall()
    }

    pub fn trap(&self, kind: &SemanticTrapKind) -> Option<&SemanticAbiTrap> {
        self.traps.iter().find(|trap| &trap.kind == kind)
    }
}

impl fmt::Display for SemanticAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.cpu.name())
    }
}
