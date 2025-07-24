// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::disassemblers::custom::cil::Mnemonic;
use crate::Binary;
use std::collections::BTreeSet;
use std::io::Error;

pub struct Instruction<'instruction> {
    pub mnemonic: Mnemonic,
    bytes: &'instruction [u8],
    pub address: u64,
}

impl<'instruction> Instruction<'instruction> {
    pub fn new(bytes: &'instruction [u8], address: u64) -> Result<Self, Error> {
        let mnemonic = Mnemonic::from_bytes(bytes)?;
        Ok(Self {
            mnemonic,
            bytes,
            address,
        })
    }

    pub fn pattern(&self) -> String {
        if self.is_wildcard() {
            return "??".repeat(self.size());
        }
        if self.is_metadata_token_wildcard_instruction() {
            let mut pattern = Binary::to_hex(&self.mnemonic_bytes());
            pattern.push_str(&"??".repeat(self.operand_size() - 1));
            pattern.push_str(&Binary::to_hex(std::slice::from_ref(
                self.operand_bytes().last().unwrap(),
            )));
            return pattern;
        }
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
        0
    }

    pub fn size(&self) -> usize {
        self.mnemonic_size() + self.operand_size()
    }

    pub fn operand_size(&self) -> usize {
        if self.is_switch() {
            let count = self
                .bytes
                .get(self.mnemonic_size()..self.mnemonic_size() + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap();
            return 4 + (count as usize * 4);
        }
        self.mnemonic.operand_size() / 8
    }

    pub fn mnemonic_size(&self) -> usize {
        if self.mnemonic as u16 >> 8 == 0xfe {
            return 2;
        }
        1
    }

    pub fn is_wildcard(&self) -> bool {
        self.is_nop()
    }

    pub fn is_nop(&self) -> bool {
        matches!(self.mnemonic, Mnemonic::Nop)
    }

    pub fn is_jump(&self) -> bool {
        self.is_conditional_jump() || self.is_unconditional_jump()
    }

    pub fn next(&self) -> Option<u64> {
        if self.is_unconditional_jump() || self.is_return() || self.is_switch() {
            return None;
        }
        Some(self.address + self.size() as u64)
    }

    pub fn to(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();

        if self.is_switch() {
            let address = self.address as i64;
            let count = self
                .bytes
                .get(self.mnemonic_size()..self.mnemonic_size() + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap();
            for index in 1..=count {
                let start = self.mnemonic_size() + (index as usize * 4);
                let end = start + 4;

                let relative_offset = self
                    .bytes
                    .get(start..end)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(i32::from_le_bytes)
                    .unwrap();

                result.insert(
                    address.wrapping_add(relative_offset as i64) as u64 + self.size() as u64,
                );
            }
        } else if self.is_jump() {
            let operand_bytes = self.operand_bytes();
            let address = self.address as i64;
            let relative_offset = match self.operand_size() {
                1 => operand_bytes
                    .first()
                    .map(|&b| i8::from_le_bytes([b]) as i64),
                2 => operand_bytes
                    .get(..2)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(i16::from_le_bytes)
                    .map(|v| v as i64),
                4 => operand_bytes
                    .get(..4)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(i32::from_le_bytes)
                    .map(|v| v as i64),
                _ => None,
            };
            if let Some(relative) = relative_offset {
                result.insert(address.wrapping_add(relative) as u64 + self.size() as u64);
            }
        }
        result
    }

    pub fn is_switch(&self) -> bool {
        matches!(self.mnemonic, Mnemonic::Switch)
    }

    pub fn is_metadata_token_wildcard_instruction(&self) -> bool {
        matches!(
            self.mnemonic,
            Mnemonic::Call
                | Mnemonic::CallVirt
                | Mnemonic::LdSFld
                | Mnemonic::LdFld
                | Mnemonic::NewObj
        )
    }

    pub fn get_call_metadata_token(&self) -> Option<u32> {
        if matches!(self.mnemonic, Mnemonic::Call | Mnemonic::CallVirt) {
            let operand_bytes = self.operand_bytes();
            if operand_bytes.len() >= 4 {
                return Some(u32::from_le_bytes([
                    operand_bytes[0],
                    operand_bytes[1],
                    operand_bytes[2],
                    operand_bytes[3],
                ]));
            }
        }
        None
    }

    pub fn is_conditional_jump(&self) -> bool {
        matches!(
            self.mnemonic,
            Mnemonic::BrFalse
                | Mnemonic::BrFalseS
                | Mnemonic::BrTrue
                | Mnemonic::BrTrueS
                | Mnemonic::BneUn
                | Mnemonic::BneUnS
                | Mnemonic::Blt
                | Mnemonic::BltS
                | Mnemonic::BltUn
                | Mnemonic::BltUnS
                | Mnemonic::Beq
                | Mnemonic::BeqS
                | Mnemonic::Bge
                | Mnemonic::BgeS
                | Mnemonic::BgeUn
                | Mnemonic::BgeUnS
                | Mnemonic::Bgt
                | Mnemonic::BgtS
                | Mnemonic::BgtUn
                | Mnemonic::BgtUnS
                | Mnemonic::Ble
                | Mnemonic::BleS
                | Mnemonic::BleUn
                | Mnemonic::BleUnS
        )
    }

    pub fn is_return(&self) -> bool {
        matches!(self.mnemonic, Mnemonic::Ret | Mnemonic::Throw)
    }

    pub fn is_call(&self) -> bool {
        matches!(
            self.mnemonic,
            Mnemonic::Call | Mnemonic::CallI | Mnemonic::CallVirt
        )
    }

    pub fn is_unconditional_jump(&self) -> bool {
        matches!(
            self.mnemonic,
            Mnemonic::Br | Mnemonic::Jmp | Mnemonic::BrS | Mnemonic::Leave | Mnemonic::LeaveS
        )
    }
}
