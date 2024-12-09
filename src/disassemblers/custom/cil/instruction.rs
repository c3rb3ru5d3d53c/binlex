use std::io::Error;
use crate::disassemblers::custom::cil::Mnemonic;
use std::collections::BTreeSet;
use crate::Binary;

pub struct Instruction <'instruction> {
    pub mnemonic: Mnemonic,
    bytes: &'instruction [u8],
    pub address: u64,
}

impl <'instruction> Instruction <'instruction> {
    pub fn new(bytes: &'instruction [u8], address: u64) -> Result<Self, Error> {
        let mnemonic = Mnemonic::from_bytes(bytes)?;
        Ok(Self {mnemonic, bytes, address})
    }

    pub fn pattern(&self) -> String {
        if self.is_wildcard() { return "??".repeat(self.size()); }
        let mut pattern = Binary::to_hex(&self.mnemonic_bytes());
        pattern.push_str(&"??".repeat(self.operand_size()));
        pattern
    }

    pub fn mnemonic_bytes(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        for byte in &self.bytes[..self.mnemonic_size()] {
            result.push(*byte);
        }
        result
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        for byte in &self.bytes[..self.mnemonic_size() + self.operand_size()] {
            result.push(*byte);
        }
        result
    }

    pub fn operand_bytes(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        for byte in &self.bytes[self.mnemonic_size()..self.mnemonic_size() + self.operand_size()] {
            result.push(*byte);
        }
        result
    }

    pub fn edges(&self) -> usize {
        if self.is_unconditional_jump() {
            return 1;
        }
        if self.is_return() {
            return 1;
        }
        if self.is_conditional_jump() {
            return 2;
        }
        return 0;
    }

    pub fn size(&self) -> usize {
        self.mnemonic_size() + self.operand_size()
    }

    pub fn operand_size(&self) -> usize {
        if self.is_switch() {
            let count = self.bytes
                .get(self.mnemonic_size()..self.mnemonic_size() + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .map(|v| v as u32).unwrap();
            return 4 + (count as usize * 4);
        }
        self.mnemonic.operand_size() / 8
    }

    pub fn mnemonic_size(&self) -> usize {
        if self.mnemonic as u16 >> 8 == 0xfe {
            return 2;
        }
        return 1;
    }

    pub fn is_wildcard(&self) -> bool {
        self.is_nop()
    }

    pub fn is_nop(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Nop => true,
            _ => false,
        }
    }

    pub fn is_jump(&self) -> bool {
        self.is_conditional_jump() || self.is_unconditional_jump()
    }

    pub fn next(&self) -> Option<u64> {
        if self.is_unconditional_jump() || self.is_return() || self.is_switch() { return None; }
        Some(self.address + self.size() as u64)
    }

    pub fn to(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();

        if self.is_switch() {
            let address = self.address as i64;
            let count = self.bytes
                .get(self.mnemonic_size()..self.mnemonic_size() + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .map(|v| v as u32).unwrap();
            for index in 1..=count {
                let start = self.mnemonic_size() + (index as usize * 4);
                let end = start + 4;

                let relative_offset = self.bytes
                    .get(start..end)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(i32::from_le_bytes)
                    .unwrap();

                result.insert(
                    address.wrapping_add(relative_offset as i64) as u64
                    + self.size() as u64,
                );
            }
        } else if self.is_jump() {
            let operand_bytes = self.operand_bytes();
            let address = self.address as i64;
            let relative_offset = match self.operand_size() {
                1 => {
                    operand_bytes.get(0).map(|&b| i8::from_le_bytes([b]) as i64)
                }
                2 => {
                    operand_bytes
                        .get(..2)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(i16::from_le_bytes)
                        .map(|v| v as i64)
                }
                4 => {
                    operand_bytes
                        .get(..4)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(i32::from_le_bytes)
                        .map(|v| v as i64)
                }
                _ => None,
            };
            if let Some(relative) = relative_offset {
                result.insert(address.wrapping_add(relative) as u64 + self.size() as u64);
            }
        }
        result
    }

    pub fn is_switch(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Switch => true,
            _ => false,
        }
    }

    pub fn is_conditional_jump(&self) -> bool {
        match self.mnemonic {
            Mnemonic::BrFalse => true,
            Mnemonic::BrFalseS => true,
            Mnemonic::BrTrue => true,
            Mnemonic::BrTrueS => true,
            Mnemonic::BneUn => true,
            Mnemonic::BneUnS => true,
            Mnemonic::Blt => true,
            Mnemonic::BltS => true,
            Mnemonic::BltUn => true,
            Mnemonic::BltUnS => true,
            Mnemonic::Beq => true,
            Mnemonic::BeqS => true,
            Mnemonic::Bge => true,
            Mnemonic::BgeS => true,
            Mnemonic::BgeUn => true,
            Mnemonic::BgeUnS => true,
            Mnemonic::Bgt => true,
            Mnemonic::BgtS => true,
            Mnemonic::BgtUn => true,
            Mnemonic::BgtUnS => true,
            Mnemonic::Ble => true,
            Mnemonic::BleS => true,
            Mnemonic::BleUn => true,
            Mnemonic::BleUnS => true,
            _ => false,
        }
    }

    pub fn is_return(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Ret => true,
            Mnemonic::Throw => true,
            _ => false,
        }
    }

    pub fn is_call(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Call => true,
            Mnemonic::CallI => true,
            Mnemonic::CallVirt => true,
            _ => false,
        }
    }

    pub fn is_unconditional_jump(&self) -> bool {
        match self.mnemonic {
            Mnemonic::Br => true,
            Mnemonic::Jmp => true,
            Mnemonic::BrS => true,
            Mnemonic::Leave => true,
            Mnemonic::LeaveS => true,
            _ => false,
        }
    }
}
