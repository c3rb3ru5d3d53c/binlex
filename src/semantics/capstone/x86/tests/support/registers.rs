use std::collections::BTreeMap;

use capstone::arch::x86::X86Reg;
use num_bigint::BigUint;
use num_traits::Zero;
use unicorn_engine_sys::RegisterX86;

use crate::Architecture;
use crate::semantics::capstone::x86::common as x86_common;

use super::common::{I386Register, mask_to_bits, mask_to_bits_wide};

pub(crate) fn read_register_value(
    registers: &BTreeMap<String, u128>,
    name: &str,
    bits: u16,
) -> u128 {
    if let Some(value) = registers.get(name) {
        return mask_to_bits(*value, bits);
    }

    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let eax_value = registers.get(&eax_name).copied().unwrap_or_default();
    let ebx_name = x86_common::reg_id_name(X86Reg::X86_REG_EBX as u16);
    let rbx_name = x86_common::reg_id_name(X86Reg::X86_REG_RBX as u16);
    let ecx_name = x86_common::reg_id_name(X86Reg::X86_REG_ECX as u16);
    let rcx_name = x86_common::reg_id_name(X86Reg::X86_REG_RCX as u16);
    let edx_name = x86_common::reg_id_name(X86Reg::X86_REG_EDX as u16);
    let rdx_name = x86_common::reg_id_name(X86Reg::X86_REG_RDX as u16);
    let esi_name = x86_common::reg_id_name(X86Reg::X86_REG_ESI as u16);
    let rsi_name = x86_common::reg_id_name(X86Reg::X86_REG_RSI as u16);
    let edi_name = x86_common::reg_id_name(X86Reg::X86_REG_EDI as u16);
    let rdi_name = x86_common::reg_id_name(X86Reg::X86_REG_RDI as u16);
    let ebp_name = x86_common::reg_id_name(X86Reg::X86_REG_EBP as u16);
    let rbp_name = x86_common::reg_id_name(X86Reg::X86_REG_RBP as u16);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);

    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        return mask_to_bits(eax_value, 16);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        return mask_to_bits(eax_value >> 8, 8);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        return mask_to_bits(eax_value, 8);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_CX as u16) {
        return mask_to_bits(registers.get(&ecx_name).copied().unwrap_or_default(), 16);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_CH as u16) {
        return mask_to_bits(
            registers.get(&ecx_name).copied().unwrap_or_default() >> 8,
            8,
        );
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_CL as u16) {
        return mask_to_bits(registers.get(&ecx_name).copied().unwrap_or_default(), 8);
    }
    if name == rax_name {
        return mask_to_bits(registers.get(&rax_name).copied().unwrap_or_default(), bits);
    }
    if name == eax_name {
        return mask_to_bits(registers.get(&rax_name).copied().unwrap_or_default(), bits);
    }
    for (wide, narrow) in [
        (&rbx_name, &ebx_name),
        (&rcx_name, &ecx_name),
        (&rdx_name, &edx_name),
        (&rsi_name, &esi_name),
        (&rdi_name, &edi_name),
        (&rbp_name, &ebp_name),
    ] {
        if name == *wide {
            return mask_to_bits(registers.get(narrow).copied().unwrap_or_default(), bits);
        }
        if name == *narrow {
            return mask_to_bits(registers.get(wide).copied().unwrap_or_default(), bits);
        }
    }
    if name == rsp_name {
        return mask_to_bits(registers.get(&rsp_name).copied().unwrap_or_default(), bits);
    }
    if name == esp_name {
        return mask_to_bits(registers.get(&rsp_name).copied().unwrap_or_default(), bits);
    }

    panic!("unknown register read: {name}");
}

pub(crate) fn write_register_value(
    registers: &mut BTreeMap<String, u128>,
    name: &str,
    value: u128,
) {
    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let ebx_name = x86_common::reg_id_name(X86Reg::X86_REG_EBX as u16);
    let rbx_name = x86_common::reg_id_name(X86Reg::X86_REG_RBX as u16);
    let ecx_name = x86_common::reg_id_name(X86Reg::X86_REG_ECX as u16);
    let rcx_name = x86_common::reg_id_name(X86Reg::X86_REG_RCX as u16);
    let edx_name = x86_common::reg_id_name(X86Reg::X86_REG_EDX as u16);
    let rdx_name = x86_common::reg_id_name(X86Reg::X86_REG_RDX as u16);
    let esi_name = x86_common::reg_id_name(X86Reg::X86_REG_ESI as u16);
    let rsi_name = x86_common::reg_id_name(X86Reg::X86_REG_RSI as u16);
    let edi_name = x86_common::reg_id_name(X86Reg::X86_REG_EDI as u16);
    let rdi_name = x86_common::reg_id_name(X86Reg::X86_REG_RDI as u16);
    let ebp_name = x86_common::reg_id_name(X86Reg::X86_REG_EBP as u16);
    let rbp_name = x86_common::reg_id_name(X86Reg::X86_REG_RBP as u16);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        let current = registers.get(&eax_name).copied().unwrap_or_default();
        let next = (current & !0xffff) | mask_to_bits(value, 16);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        let current = registers.get(&eax_name).copied().unwrap_or_default();
        let next = (current & !0xff) | mask_to_bits(value, 8);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        let current = registers.get(&eax_name).copied().unwrap_or_default();
        let next = (current & !(0xff << 8)) | (mask_to_bits(value, 8) << 8);
        registers.insert(eax_name, next);
        return;
    }
    if name == eax_name {
        let masked = mask_to_bits(value, 32);
        registers.insert(eax_name, masked);
        if registers.contains_key(&rax_name) {
            registers.insert(rax_name, masked);
        }
        return;
    }
    if name == rax_name {
        let masked = mask_to_bits(value, 64);
        registers.insert(rax_name, masked);
        if registers.contains_key(&eax_name) {
            registers.insert(eax_name, mask_to_bits(masked, 32));
        }
        return;
    }
    for (wide, narrow) in [
        (&rbx_name, &ebx_name),
        (&rcx_name, &ecx_name),
        (&rdx_name, &edx_name),
        (&rsi_name, &esi_name),
        (&rdi_name, &edi_name),
        (&rbp_name, &ebp_name),
    ] {
        if name == *narrow {
            let masked = mask_to_bits(value, 32);
            registers.insert((*narrow).clone(), masked);
            if registers.contains_key(wide) {
                registers.insert((*wide).clone(), masked);
            }
            return;
        }
        if name == *wide {
            let masked = mask_to_bits(value, 64);
            registers.insert((*wide).clone(), masked);
            if registers.contains_key(narrow) {
                registers.insert((*narrow).clone(), mask_to_bits(masked, 32));
            }
            return;
        }
    }
    if name == esp_name {
        let masked = mask_to_bits(value, 32);
        registers.insert(esp_name, masked);
        if registers.contains_key(&rsp_name) {
            registers.insert(rsp_name, masked);
        }
        return;
    }
    if name == rsp_name {
        let masked = mask_to_bits(value, 64);
        registers.insert(rsp_name, masked);
        if registers.contains_key(&esp_name) {
            registers.insert(esp_name, mask_to_bits(masked, 32));
        }
        return;
    }

    registers.insert(name.to_string(), value);
}

pub(crate) fn normalize_register_name(name: &str) -> String {
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16)
        || name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16)
        || name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16)
    {
        return "eax".to_string();
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
        if name == x86_common::reg_id_name(register.capstone_reg_id()) {
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
        stable_register_name(*register) == name
            || x86_common::reg_id_name(register.capstone_reg_id()) == name
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

    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let eax_value = registers
        .get(&eax_name)
        .cloned()
        .unwrap_or_else(BigUint::zero);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);

    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        return mask_to_bits_wide(eax_value, 16);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        return mask_to_bits_wide(eax_value >> 8usize, 8);
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        return mask_to_bits_wide(eax_value, 8);
    }
    if name == rax_name {
        return mask_to_bits_wide(
            registers
                .get(&rax_name)
                .cloned()
                .unwrap_or_else(BigUint::zero),
            bits,
        );
    }
    if name == eax_name {
        return mask_to_bits_wide(
            registers
                .get(&rax_name)
                .cloned()
                .unwrap_or_else(BigUint::zero),
            bits,
        );
    }
    if name == rsp_name {
        return mask_to_bits_wide(
            registers
                .get(&rsp_name)
                .cloned()
                .unwrap_or_else(BigUint::zero),
            bits,
        );
    }
    if name == esp_name {
        return mask_to_bits_wide(
            registers
                .get(&rsp_name)
                .cloned()
                .unwrap_or_else(BigUint::zero),
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
    let eax_name = x86_common::reg_id_name(X86Reg::X86_REG_EAX as u16);
    let rax_name = x86_common::reg_id_name(X86Reg::X86_REG_RAX as u16);
    let esp_name = x86_common::reg_id_name(X86Reg::X86_REG_ESP as u16);
    let rsp_name = x86_common::reg_id_name(X86Reg::X86_REG_RSP as u16);
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AX as u16) {
        let current = registers
            .get(&eax_name)
            .cloned()
            .unwrap_or_else(BigUint::zero);
        let next = ((&current >> 16usize) << 16usize) | mask_to_bits_wide(value, 16);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AL as u16) {
        let current = registers
            .get(&eax_name)
            .cloned()
            .unwrap_or_else(BigUint::zero);
        let next = ((&current >> 8usize) << 8usize) | mask_to_bits_wide(value, 8);
        registers.insert(eax_name, next);
        return;
    }
    if name == x86_common::reg_id_name(X86Reg::X86_REG_AH as u16) {
        let current = registers
            .get(&eax_name)
            .cloned()
            .unwrap_or_else(BigUint::zero);
        let low = mask_to_bits_wide(current.clone(), 8);
        let high = (&current >> 16usize) << 16usize;
        registers.insert(
            eax_name,
            high | (mask_to_bits_wide(value, 8) << 8usize) | low,
        );
        return;
    }
    if name == eax_name {
        let masked = mask_to_bits_wide(value, 32);
        registers.insert(eax_name.clone(), masked.clone());
        if registers.contains_key(&rax_name) {
            registers.insert(rax_name, masked);
        }
        return;
    }
    if name == rax_name {
        let masked = mask_to_bits_wide(value, 64);
        registers.insert(rax_name.clone(), masked.clone());
        if registers.contains_key(&eax_name) {
            registers.insert(eax_name, mask_to_bits_wide(masked, 32));
        }
        return;
    }
    if name == esp_name {
        let masked = mask_to_bits_wide(value, 32);
        registers.insert(esp_name.clone(), masked.clone());
        if registers.contains_key(&rsp_name) {
            registers.insert(rsp_name, masked);
        }
        return;
    }
    if name == rsp_name {
        let masked = mask_to_bits_wide(value, 64);
        registers.insert(rsp_name.clone(), masked.clone());
        if registers.contains_key(&esp_name) {
            registers.insert(esp_name, mask_to_bits_wide(masked, 32));
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

    pub(crate) fn capstone_reg_id(self) -> u16 {
        match self {
            Self::Eax => X86Reg::X86_REG_EAX as u16,
            Self::Rax => X86Reg::X86_REG_RAX as u16,
            Self::Ebx => X86Reg::X86_REG_EBX as u16,
            Self::Rbx => X86Reg::X86_REG_RBX as u16,
            Self::Ecx => X86Reg::X86_REG_ECX as u16,
            Self::Rcx => X86Reg::X86_REG_RCX as u16,
            Self::Edx => X86Reg::X86_REG_EDX as u16,
            Self::Rdx => X86Reg::X86_REG_RDX as u16,
            Self::Esi => X86Reg::X86_REG_ESI as u16,
            Self::Rsi => X86Reg::X86_REG_RSI as u16,
            Self::Edi => X86Reg::X86_REG_EDI as u16,
            Self::Rdi => X86Reg::X86_REG_RDI as u16,
            Self::Ebp => X86Reg::X86_REG_EBP as u16,
            Self::Rbp => X86Reg::X86_REG_RBP as u16,
            Self::Esp => X86Reg::X86_REG_ESP as u16,
            Self::Rsp => X86Reg::X86_REG_RSP as u16,
            Self::Xmm0 => X86Reg::X86_REG_XMM0 as u16,
            Self::Xmm1 => X86Reg::X86_REG_XMM1 as u16,
            Self::Xmm2 => X86Reg::X86_REG_XMM2 as u16,
            Self::Ymm0 => X86Reg::X86_REG_YMM0 as u16,
            Self::Ymm1 => X86Reg::X86_REG_YMM1 as u16,
            Self::Ymm2 => X86Reg::X86_REG_YMM2 as u16,
        }
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
