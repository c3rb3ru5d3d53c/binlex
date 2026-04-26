use crate::Architecture;
use crate::lifters::llvm::abi::{arm64, x86};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Abi {
    SysV,
    Windows64,
    Cdecl,
    Stdcall,
    Fastcall,
    LinuxSyscall,
    WindowsSyscall,
}

impl Abi {
    pub fn supports(self, architecture: Architecture) -> bool {
        match self {
            Abi::SysV => arm64::sysv::supports(architecture) || x86::sysv::supports(architecture),
            Abi::Windows64 => x86::windows64::supports(architecture),
            Abi::Cdecl => x86::cdecl::supports(architecture),
            Abi::Stdcall => x86::stdcall::supports(architecture),
            Abi::Fastcall => x86::fastcall::supports(architecture),
            Abi::LinuxSyscall => matches!(
                architecture,
                Architecture::ARM64 | Architecture::AMD64 | Architecture::I386
            ),
            Abi::WindowsSyscall => matches!(
                architecture,
                Architecture::ARM64 | Architecture::AMD64 | Architecture::I386
            ),
        }
    }
}

impl fmt::Display for Abi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Abi::SysV => "sysv",
            Abi::Windows64 => "windows64",
            Abi::Cdecl => "cdecl",
            Abi::Stdcall => "stdcall",
            Abi::Fastcall => "fastcall",
            Abi::LinuxSyscall => "linux_syscall",
            Abi::WindowsSyscall => "windows_syscall",
        };
        write!(f, "{}", value)
    }
}
