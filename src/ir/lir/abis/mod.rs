pub mod cdecl;
pub mod fastcall;
pub mod linux_syscall;
pub mod semantic_abi;
pub mod stdcall;
pub mod sysv;
pub mod windows64;
pub mod windows_syscall;

pub use semantic_abi::{LirAbi, LirAbiKind, LirAbiTrap};

use crate::ir::lir::executor::LirExecutorError;
use crate::ir::lir::{LirCpu, LirCpuKind};

pub(crate) fn reg(name: &str, bits: u16) -> crate::ir::lir::LirLocation {
    crate::ir::lir::LirLocation::Register {
        name: name.to_string(),
        bits,
    }
}

pub(crate) fn build_builtin(kind: LirAbiKind, cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
    match (kind, cpu.kind()) {
        (LirAbiKind::SysV, Some(LirCpuKind::Arm64)) => sysv::arm64(cpu),
        (LirAbiKind::SysV, Some(LirCpuKind::Amd64)) => sysv::amd64(cpu),
        (LirAbiKind::Windows64, Some(LirCpuKind::Amd64)) => windows64::amd64(cpu),
        (LirAbiKind::Cdecl, Some(LirCpuKind::I386)) => cdecl::i386(cpu),
        (LirAbiKind::Stdcall, Some(LirCpuKind::I386)) => stdcall::i386(cpu),
        (LirAbiKind::Fastcall, Some(LirCpuKind::I386)) => fastcall::i386(cpu),
        (LirAbiKind::LinuxSyscall, Some(LirCpuKind::Arm64)) => linux_syscall::arm64(cpu),
        (LirAbiKind::LinuxSyscall, Some(LirCpuKind::Amd64)) => linux_syscall::amd64(cpu),
        (LirAbiKind::LinuxSyscall, Some(LirCpuKind::I386)) => linux_syscall::i386(cpu),
        (LirAbiKind::WindowsSyscall, Some(LirCpuKind::Arm64)) => windows_syscall::arm64(cpu),
        (LirAbiKind::WindowsSyscall, Some(LirCpuKind::Amd64)) => windows_syscall::amd64(cpu),
        (LirAbiKind::WindowsSyscall, Some(LirCpuKind::I386)) => windows_syscall::i386(cpu),
        (kind, Some(cpu_kind)) => Err(LirExecutorError::UnsupportedCpu(format!(
            "{} ABI is not available for {}",
            kind.name(),
            cpu_kind.name()
        ))),
        (kind, None) => Err(LirExecutorError::UnsupportedCpu(format!(
            "{} ABI requires a built-in semantic CPU kind",
            kind.name()
        ))),
    }
}
