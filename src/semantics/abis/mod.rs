pub mod cdecl;
pub mod fastcall;
pub mod linux_syscall;
pub mod semantic_abi;
pub mod stdcall;
pub mod sysv;
pub mod windows64;
pub mod windows_syscall;

pub use semantic_abi::{SemanticAbi, SemanticAbiKind, SemanticAbiTrap};

use crate::semantics::{SemanticCpu, SemanticCpuKind};
use crate::symbolic::Error;

pub(crate) fn reg(name: &str, bits: u16) -> crate::semantics::SemanticLocation {
    crate::semantics::SemanticLocation::Register {
        name: name.to_string(),
        bits,
    }
}

pub(crate) fn build_builtin(
    kind: SemanticAbiKind,
    cpu: &SemanticCpu,
) -> Result<SemanticAbi, Error> {
    match (kind, cpu.kind()) {
        (SemanticAbiKind::SysV, Some(SemanticCpuKind::Arm64)) => sysv::arm64(cpu),
        (SemanticAbiKind::SysV, Some(SemanticCpuKind::Amd64)) => sysv::amd64(cpu),
        (SemanticAbiKind::Windows64, Some(SemanticCpuKind::Amd64)) => windows64::amd64(cpu),
        (SemanticAbiKind::Cdecl, Some(SemanticCpuKind::I386)) => cdecl::i386(cpu),
        (SemanticAbiKind::Stdcall, Some(SemanticCpuKind::I386)) => stdcall::i386(cpu),
        (SemanticAbiKind::Fastcall, Some(SemanticCpuKind::I386)) => fastcall::i386(cpu),
        (SemanticAbiKind::LinuxSyscall, Some(SemanticCpuKind::Arm64)) => linux_syscall::arm64(cpu),
        (SemanticAbiKind::LinuxSyscall, Some(SemanticCpuKind::Amd64)) => linux_syscall::amd64(cpu),
        (SemanticAbiKind::LinuxSyscall, Some(SemanticCpuKind::I386)) => linux_syscall::i386(cpu),
        (SemanticAbiKind::WindowsSyscall, Some(SemanticCpuKind::Arm64)) => {
            windows_syscall::arm64(cpu)
        }
        (SemanticAbiKind::WindowsSyscall, Some(SemanticCpuKind::Amd64)) => {
            windows_syscall::amd64(cpu)
        }
        (SemanticAbiKind::WindowsSyscall, Some(SemanticCpuKind::I386)) => {
            windows_syscall::i386(cpu)
        }
        (kind, Some(cpu_kind)) => Err(Error::UnsupportedCpu(format!(
            "{} ABI is not available for {}",
            kind.name(),
            cpu_kind.name()
        ))),
        (kind, None) => Err(Error::UnsupportedCpu(format!(
            "{} ABI requires a built-in semantic CPU kind",
            kind.name()
        ))),
    }
}
