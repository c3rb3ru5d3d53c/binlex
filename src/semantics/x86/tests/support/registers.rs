use std::collections::BTreeMap;

use num_bigint::BigUint;
use num_traits::Zero;
use unicorn_engine_sys::RegisterX86;

use crate::Architecture;

use super::common::{I386Register, mask_to_bits, mask_to_bits_wide};

const EAX: &str = "eax";
const RAX: &str = "rax";
const EBX: &str = "ebx";
const RBX: &str = "rbx";
const ECX: &str = "ecx";
const RCX: &str = "rcx";
const EDX: &str = "edx";
const RDX: &str = "rdx";
const ESI: &str = "esi";
const RSI: &str = "rsi";
const EDI: &str = "edi";
const RDI: &str = "rdi";
const EBP: &str = "ebp";
const RBP: &str = "rbp";
const ESP: &str = "esp";
const RSP: &str = "rsp";
const AX: &str = "ax";
const AH: &str = "ah";
const AL: &str = "al";
const CX: &str = "cx";
const CH: &str = "ch";
const CL: &str = "cl";

fn register_aliases(register: I386Register) -> &'static [&'static str] {
    match register {
        I386Register::Eax => &[EAX, AX, AH, AL],
        I386Register::Rax => &[RAX, EAX, AX, AH, AL],
        I386Register::Ebx => &[EBX, "bx", "bh", "bl"],
        I386Register::Rbx => &[RBX, EBX, "bx", "bh", "bl"],
        I386Register::Ecx => &[ECX, CX, CH, CL],
        I386Register::Rcx => &[RCX, ECX, CX, CH, CL],
        I386Register::Edx => &[EDX, "dx", "dh", "dl"],
        I386Register::Rdx => &[RDX, EDX, "dx", "dh", "dl"],
        I386Register::Esi => &[ESI, "si"],
        I386Register::Rsi => &[RSI, ESI, "si", "sil"],
        I386Register::Edi => &[EDI, "di"],
        I386Register::Rdi => &[RDI, EDI, "di", "dil"],
        I386Register::Ebp => &[EBP, "bp"],
        I386Register::Rbp => &[RBP, EBP, "bp", "bpl"],
        I386Register::Esp => &[ESP, "sp"],
        I386Register::Rsp => &[RSP, ESP, "sp", "spl"],
        I386Register::Xmm0 => &["xmm0"],
        I386Register::Xmm1 => &["xmm1"],
        I386Register::Xmm2 => &["xmm2"],
        I386Register::Ymm0 => &["ymm0"],
        I386Register::Ymm1 => &["ymm1"],
        I386Register::Ymm2 => &["ymm2"],
    }
}

fn is_alias(name: &str, aliases: &[&str]) -> bool {
    aliases.contains(&name)
}

pub(crate) fn read_register_value(
    registers: &BTreeMap<String, u128>,
    name: &str,
    bits: u16,
) -> u128 {
    if let Some(value) = registers.get(name) {
        return mask_to_bits(*value, bits);
    }

    let eax_value = registers.get(EAX).copied().unwrap_or_default();

    if name == AX {
        return mask_to_bits(eax_value, 16);
    }
    if name == AH {
        return mask_to_bits(eax_value >> 8, 8);
    }
    if name == AL {
        return mask_to_bits(eax_value, 8);
    }
    if name == CX {
        return mask_to_bits(registers.get(ECX).copied().unwrap_or_default(), 16);
    }
    if name == CH {
        return mask_to_bits(registers.get(ECX).copied().unwrap_or_default() >> 8, 8);
    }
    if name == CL {
        return mask_to_bits(registers.get(ECX).copied().unwrap_or_default(), 8);
    }
    if name == RAX {
        return mask_to_bits(registers.get(RAX).copied().unwrap_or_default(), bits);
    }
    if name == EAX {
        return mask_to_bits(registers.get(RAX).copied().unwrap_or_default(), bits);
    }
    for (wide, narrow) in [
        (RBX, EBX),
        (RCX, ECX),
        (RDX, EDX),
        (RSI, ESI),
        (RDI, EDI),
        (RBP, EBP),
    ] {
        if name == wide {
            return mask_to_bits(registers.get(narrow).copied().unwrap_or_default(), bits);
        }
        if name == narrow {
            return mask_to_bits(registers.get(wide).copied().unwrap_or_default(), bits);
        }
    }
    if name == RSP {
        return mask_to_bits(registers.get(RSP).copied().unwrap_or_default(), bits);
    }
    if name == ESP {
        return mask_to_bits(registers.get(RSP).copied().unwrap_or_default(), bits);
    }

    panic!("unknown register read: {name}");
}

pub(crate) fn write_register_value(
    registers: &mut BTreeMap<String, u128>,
    name: &str,
    value: u128,
) {
    if name == AX {
        let current = registers.get(EAX).copied().unwrap_or_default();
        let next = (current & !0xffff) | mask_to_bits(value, 16);
        registers.insert(EAX.to_string(), next);
        return;
    }
    if name == AL {
        let current = registers.get(EAX).copied().unwrap_or_default();
        let next = (current & !0xff) | mask_to_bits(value, 8);
        registers.insert(EAX.to_string(), next);
        return;
    }
    if name == AH {
        let current = registers.get(EAX).copied().unwrap_or_default();
        let next = (current & !(0xff << 8)) | (mask_to_bits(value, 8) << 8);
        registers.insert(EAX.to_string(), next);
        return;
    }
    if name == EAX {
        let masked = mask_to_bits(value, 32);
        registers.insert(EAX.to_string(), masked);
        if registers.contains_key(RAX) {
            registers.insert(RAX.to_string(), masked);
        }
        return;
    }
    if name == RAX {
        let masked = mask_to_bits(value, 64);
        registers.insert(RAX.to_string(), masked);
        if registers.contains_key(EAX) {
            registers.insert(EAX.to_string(), mask_to_bits(masked, 32));
        }
        return;
    }
    for (wide, narrow) in [
        (RBX, EBX),
        (RCX, ECX),
        (RDX, EDX),
        (RSI, ESI),
        (RDI, EDI),
        (RBP, EBP),
    ] {
        if name == narrow {
            let masked = mask_to_bits(value, 32);
            registers.insert(narrow.to_string(), masked);
            if registers.contains_key(wide) {
                registers.insert(wide.to_string(), masked);
            }
            return;
        }
        if name == wide {
            let masked = mask_to_bits(value, 64);
            registers.insert(wide.to_string(), masked);
            if registers.contains_key(narrow) {
                registers.insert(narrow.to_string(), mask_to_bits(masked, 32));
            }
            return;
        }
    }
    if name == ESP {
        let masked = mask_to_bits(value, 32);
        registers.insert(ESP.to_string(), masked);
        if registers.contains_key(RSP) {
            registers.insert(RSP.to_string(), masked);
        }
        return;
    }
    if name == RSP {
        let masked = mask_to_bits(value, 64);
        registers.insert(RSP.to_string(), masked);
        if registers.contains_key(ESP) {
            registers.insert(ESP.to_string(), mask_to_bits(masked, 32));
        }
        return;
    }

    registers.insert(name.to_string(), value);
}

pub(crate) fn normalize_register_name(name: &str) -> String {
    if matches!(name, AX | AH | AL)
    {
        return EAX.to_string();
    }
    for register in [
        I386Register::Eax,
        I386Register::Rax,
        I386Register::Ebx,
        I386Register::Rbx,
        I386Register::Ecx,
        I386Register::Rcx,
        I386Register::Edx,
        I386Register::Rdx,
        I386Register::Esi,
        I386Register::Rsi,
        I386Register::Edi,
        I386Register::Rdi,
        I386Register::Ebp,
        I386Register::Rbp,
        I386Register::Esp,
        I386Register::Rsp,
        I386Register::Xmm0,
        I386Register::Xmm1,
        I386Register::Xmm2,
        I386Register::Ymm0,
        I386Register::Ymm1,
        I386Register::Ymm2,
    ] {
        if is_alias(name, register_aliases(register)) {
            return stable_register_name(register).to_string();
        }
    }
    name.to_string()
}

pub(crate) fn stable_register_name(register: I386Register) -> &'static str {
    match register {
        I386Register::Eax => "eax",
        I386Register::Rax => "rax",
        I386Register::Ebx => "ebx",
        I386Register::Rbx => "rbx",
        I386Register::Ecx => "ecx",
        I386Register::Rcx => "rcx",
        I386Register::Edx => "edx",
        I386Register::Rdx => "rdx",
        I386Register::Esi => "esi",
        I386Register::Rsi => "rsi",
        I386Register::Edi => "edi",
        I386Register::Rdi => "rdi",
        I386Register::Ebp => "ebp",
        I386Register::Rbp => "rbp",
        I386Register::Esp => "esp",
        I386Register::Rsp => "rsp",
        I386Register::Xmm0 => "xmm0",
        I386Register::Xmm1 => "xmm1",
        I386Register::Xmm2 => "xmm2",
        I386Register::Ymm0 => "ymm0",
        I386Register::Ymm1 => "ymm1",
        I386Register::Ymm2 => "ymm2",
    }
}

pub(crate) fn register_by_name(name: &str) -> Option<I386Register> {
    [
        I386Register::Eax,
        I386Register::Rax,
        I386Register::Ebx,
        I386Register::Rbx,
        I386Register::Ecx,
        I386Register::Rcx,
        I386Register::Edx,
        I386Register::Rdx,
        I386Register::Esi,
        I386Register::Rsi,
        I386Register::Edi,
        I386Register::Rdi,
        I386Register::Ebp,
        I386Register::Rbp,
        I386Register::Esp,
        I386Register::Rsp,
        I386Register::Xmm0,
        I386Register::Xmm1,
        I386Register::Xmm2,
        I386Register::Ymm0,
        I386Register::Ymm1,
        I386Register::Ymm2,
    ]
    .into_iter()
    .find(|register| {
        stable_register_name(*register) == name || is_alias(name, register_aliases(*register))
    })
}

pub(crate) fn read_register_value_wide(
    registers: &BTreeMap<String, BigUint>,
    name: &str,
    bits: u16,
) -> BigUint {
    let normalized = if name.starts_with("reg_") {
        normalize_register_name(name)
    } else {
        name.to_string()
    };
    let name = normalized.as_str();
    if let Some(value) = registers.get(name) {
        return mask_to_bits_wide(value.clone(), bits);
    }

    let eax_value = registers.get(EAX).cloned().unwrap_or_else(BigUint::zero);

    if name == AX {
        return mask_to_bits_wide(eax_value, 16);
    }
    if name == AH {
        return mask_to_bits_wide(eax_value >> 8usize, 8);
    }
    if name == AL {
        return mask_to_bits_wide(eax_value, 8);
    }
    if name == RAX {
        return mask_to_bits_wide(
            registers.get(RAX).cloned().unwrap_or_else(BigUint::zero),
            bits,
        );
    }
    if name == EAX {
        return mask_to_bits_wide(
            registers.get(RAX).cloned().unwrap_or_else(BigUint::zero),
            bits,
        );
    }
    if name == RSP {
        return mask_to_bits_wide(
            registers.get(RSP).cloned().unwrap_or_else(BigUint::zero),
            bits,
        );
    }
    if name == ESP {
        return mask_to_bits_wide(
            registers.get(RSP).cloned().unwrap_or_else(BigUint::zero),
            bits,
        );
    }
    registers.get(name).cloned().unwrap_or_else(BigUint::zero)
}

pub(crate) fn write_register_value_wide(
    registers: &mut BTreeMap<String, BigUint>,
    name: &str,
    value: BigUint,
) {
    let normalized = if name.starts_with("reg_") {
        normalize_register_name(name)
    } else {
        name.to_string()
    };
    let name = normalized.as_str();
    if name == AX {
        let current = registers.get(EAX).cloned().unwrap_or_else(BigUint::zero);
        let next = ((&current >> 16usize) << 16usize) | mask_to_bits_wide(value, 16);
        registers.insert(EAX.to_string(), next);
        return;
    }
    if name == AL {
        let current = registers.get(EAX).cloned().unwrap_or_else(BigUint::zero);
        let next = ((&current >> 8usize) << 8usize) | mask_to_bits_wide(value, 8);
        registers.insert(EAX.to_string(), next);
        return;
    }
    if name == AH {
        let current = registers.get(EAX).cloned().unwrap_or_else(BigUint::zero);
        let low = mask_to_bits_wide(current.clone(), 8);
        let high = (&current >> 16usize) << 16usize;
        registers.insert(
            EAX.to_string(),
            high | (mask_to_bits_wide(value, 8) << 8usize) | low,
        );
        return;
    }
    if name == EAX {
        let masked = mask_to_bits_wide(value, 32);
        registers.insert(EAX.to_string(), masked.clone());
        if registers.contains_key(RAX) {
            registers.insert(RAX.to_string(), masked);
        }
        return;
    }
    if name == RAX {
        let masked = mask_to_bits_wide(value, 64);
        registers.insert(RAX.to_string(), masked.clone());
        if registers.contains_key(EAX) {
            registers.insert(EAX.to_string(), mask_to_bits_wide(masked, 32));
        }
        return;
    }
    if name == ESP {
        let masked = mask_to_bits_wide(value, 32);
        registers.insert(ESP.to_string(), masked.clone());
        if registers.contains_key(RSP) {
            registers.insert(RSP.to_string(), masked);
        }
        return;
    }
    if name == RSP {
        let masked = mask_to_bits_wide(value, 64);
        registers.insert(RSP.to_string(), masked.clone());
        if registers.contains_key(ESP) {
            registers.insert(ESP.to_string(), mask_to_bits_wide(masked, 32));
        }
        return;
    }
    registers.insert(name.to_string(), value);
}

impl I386Register {
    pub(crate) fn all_for_arch(architecture: Architecture) -> Vec<Self> {
        let mut registers = vec![
            Self::Eax,
            Self::Ebx,
            Self::Ecx,
            Self::Edx,
            Self::Esi,
            Self::Edi,
            Self::Ebp,
            Self::Esp,
            Self::Xmm0,
            Self::Xmm1,
            Self::Xmm2,
        ];
        if matches!(architecture, Architecture::AMD64) {
            registers.push(Self::Rax);
            registers.push(Self::Rbx);
            registers.push(Self::Rcx);
            registers.push(Self::Rdx);
            registers.push(Self::Rsi);
            registers.push(Self::Rdi);
            registers.push(Self::Rbp);
            registers.push(Self::Rsp);
        }
        registers
    }
    pub(crate) fn unicorn_register(self) -> RegisterX86 {
        match self {
            Self::Eax => RegisterX86::EAX,
            Self::Rax => RegisterX86::RAX,
            Self::Ebx => RegisterX86::EBX,
            Self::Rbx => RegisterX86::RBX,
            Self::Ecx => RegisterX86::ECX,
            Self::Rcx => RegisterX86::RCX,
            Self::Edx => RegisterX86::EDX,
            Self::Rdx => RegisterX86::RDX,
            Self::Esi => RegisterX86::ESI,
            Self::Rsi => RegisterX86::RSI,
            Self::Edi => RegisterX86::EDI,
            Self::Rdi => RegisterX86::RDI,
            Self::Ebp => RegisterX86::EBP,
            Self::Rbp => RegisterX86::RBP,
            Self::Esp => RegisterX86::ESP,
            Self::Rsp => RegisterX86::RSP,
            Self::Xmm0 => RegisterX86::XMM0,
            Self::Xmm1 => RegisterX86::XMM1,
            Self::Xmm2 => RegisterX86::XMM2,
            Self::Ymm0 => RegisterX86::YMM0,
            Self::Ymm1 => RegisterX86::YMM1,
            Self::Ymm2 => RegisterX86::YMM2,
        }
    }

    pub(crate) fn bit_width(self) -> u16 {
        match self {
            Self::Rax
            | Self::Rbx
            | Self::Rcx
            | Self::Rdx
            | Self::Rsi
            | Self::Rdi
            | Self::Rbp
            | Self::Rsp => 64,
            Self::Xmm0 | Self::Xmm1 | Self::Xmm2 => 128,
            Self::Ymm0 | Self::Ymm1 | Self::Ymm2 => 256,
            _ => 32,
        }
    }
}
