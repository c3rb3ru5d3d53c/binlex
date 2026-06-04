use crate::Architecture;
use crate::irs::lir::executor::LirExecutorError;
use crate::irs::lir::{LirCpu, LirLocation, LirTrapKind};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirAbiKind {
    SysV,
    Windows64,
    Cdecl,
    Stdcall,
    Fastcall,
    LinuxSyscall,
    WindowsSyscall,
}

impl LirAbiKind {
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
pub struct LirAbi {
    pub name: String,
    pub cpu: LirCpu,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub function_arguments: Vec<LirLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub return_locations: Vec<LirLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_return_bits: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub traps: Vec<LirAbiTrap>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiTrap {
    pub kind: LirTrapKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argument_registers: Vec<LirLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_register: Option<LirLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_registers: Vec<LirLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shadow_registers: Vec<LirLocation>,
}

impl LirAbi {
    pub fn new(
        name: String,
        cpu: LirCpu,
        function_arguments: Vec<LirLocation>,
        return_locations: Vec<LirLocation>,
        function_return_bits: Option<u16>,
        traps: Vec<LirAbiTrap>,
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

    pub fn from_kind(kind: LirAbiKind, cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        super::build_builtin(kind, cpu)
    }

    pub fn sysv(cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        Self::from_kind(LirAbiKind::SysV, cpu)
    }

    pub fn windows64(cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        Self::from_kind(LirAbiKind::Windows64, cpu)
    }

    pub fn cdecl(cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        Self::from_kind(LirAbiKind::Cdecl, cpu)
    }

    pub fn stdcall(cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        Self::from_kind(LirAbiKind::Stdcall, cpu)
    }

    pub fn fastcall(cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        Self::from_kind(LirAbiKind::Fastcall, cpu)
    }

    pub fn linux_syscall(cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        Self::from_kind(LirAbiKind::LinuxSyscall, cpu)
    }

    pub fn windows_syscall(cpu: &LirCpu) -> Result<Self, LirExecutorError> {
        Self::from_kind(LirAbiKind::WindowsSyscall, cpu)
    }

    pub fn custom(name: impl Into<String>, cpu: LirCpu) -> Self {
        Self::new(name.into(), cpu, Vec::new(), Vec::new(), None, Vec::new())
    }

    pub fn supports_cpu(&self, cpu: &LirCpu) -> bool {
        &self.cpu == cpu
    }

    pub fn supports_architecture(&self, architecture: Architecture) -> bool {
        matches!(
            (self.cpu.kind(), architecture),
            (Some(crate::irs::lir::LirCpuKind::I386), Architecture::I386)
                | (
                    Some(crate::irs::lir::LirCpuKind::Amd64),
                    Architecture::AMD64
                )
                | (
                    Some(crate::irs::lir::LirCpuKind::Arm64),
                    Architecture::ARM64
                )
                | (Some(crate::irs::lir::LirCpuKind::Cil), Architecture::CIL)
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

    pub fn trap(&self, kind: &LirTrapKind) -> Option<&LirAbiTrap> {
        self.traps.iter().find(|trap| &trap.kind == kind)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiSysv;

impl LirAbiSysv {
    pub fn new(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
        LirAbi::from_kind(LirAbiKind::SysV, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiWindows64;

impl LirAbiWindows64 {
    pub fn new(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
        LirAbi::from_kind(LirAbiKind::Windows64, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiCdecl;

impl LirAbiCdecl {
    pub fn new(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
        LirAbi::from_kind(LirAbiKind::Cdecl, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiStdcall;

impl LirAbiStdcall {
    pub fn new(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
        LirAbi::from_kind(LirAbiKind::Stdcall, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiFastcall;

impl LirAbiFastcall {
    pub fn new(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
        LirAbi::from_kind(LirAbiKind::Fastcall, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiLinuxSyscall;

impl LirAbiLinuxSyscall {
    pub fn new(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
        LirAbi::from_kind(LirAbiKind::LinuxSyscall, cpu)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirAbiWindowsSyscall;

impl LirAbiWindowsSyscall {
    pub fn new(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
        LirAbi::from_kind(LirAbiKind::WindowsSyscall, cpu)
    }
}

impl fmt::Display for LirAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.cpu.name())
    }
}
