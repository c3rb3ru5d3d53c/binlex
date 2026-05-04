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

use crate::controlflow::{FloatOperand, ImmediateOperand, Operand, OperandKind};
use crate::disassemblers::cil::Mnemonic;
use crate::hex;
use std::collections::{BTreeMap, BTreeSet};
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
            let mut pattern = hex::encode(&self.mnemonic_bytes());
            pattern.push_str(&"??".repeat(self.operand_size() - 1));
            pattern.push_str(&hex::encode(std::slice::from_ref(
                self.operand_bytes().last().unwrap(),
            )));
            return pattern;
        }
        let mut pattern = hex::encode(&self.mnemonic_bytes());
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

    pub fn mnemonic_text(&self) -> String {
        self.mnemonic.name()
    }

    pub fn disassembly_text(&self, metadata_token_addresses: &BTreeMap<u64, u64>) -> String {
        let mnemonic = self.mnemonic_text();
        let operands = self.disassembly_operands(metadata_token_addresses);
        if operands.is_empty() {
            mnemonic
        } else {
            format!("{} {}", mnemonic, operands.join(", "))
        }
    }

    pub fn normalized_operands(
        &self,
        _metadata_token_addresses: &BTreeMap<u64, u64>,
    ) -> Vec<Operand> {
        if let Some(index) = self.argument_index() {
            return vec![Operand {
                kind: OperandKind::Immediate(ImmediateOperand {
                    value: index as i128,
                }),
            }];
        }

        if let Some(index) = self.local_index() {
            return vec![Operand {
                kind: OperandKind::Immediate(ImmediateOperand {
                    value: index as i128,
                }),
            }];
        }

        if let Some(value) = self.inline_i32_constant() {
            return vec![Operand {
                kind: OperandKind::Immediate(ImmediateOperand {
                    value: value as i128,
                }),
            }];
        }

        if let Some(value) = self.inline_i64_constant() {
            return vec![Operand {
                kind: OperandKind::Immediate(ImmediateOperand {
                    value: value as i128,
                }),
            }];
        }

        if let Some(value) = self.inline_f32_constant() {
            return vec![Operand {
                kind: OperandKind::Float(FloatOperand {
                    value: value as f64,
                }),
            }];
        }

        if let Some(value) = self.inline_f64_constant() {
            return vec![Operand {
                kind: OperandKind::Float(FloatOperand { value }),
            }];
        }

        if self.is_switch() {
            return self
                .switch_offsets()
                .into_iter()
                .map(|offset| Operand {
                    kind: OperandKind::Immediate(ImmediateOperand {
                        value: offset as i128,
                    }),
                })
                .collect();
        }

        if self.is_jump() {
            if let Some(offset) = self.raw_branch_offset() {
                return vec![Operand {
                    kind: OperandKind::Immediate(ImmediateOperand {
                        value: offset as i128,
                    }),
                }];
            }
        }

        if let Some(token) = self.metadata_token() {
            return vec![Operand {
                kind: OperandKind::Immediate(ImmediateOperand {
                    value: token as i128,
                }),
            }];
        }

        if matches!(self.mnemonic, Mnemonic::No | Mnemonic::Unaligned) {
            return vec![Operand {
                kind: OperandKind::Immediate(ImmediateOperand {
                    value: self.operand_u8() as i128,
                }),
            }];
        }

        Vec::new()
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

    pub fn fallthrough(&self) -> Option<u64> {
        if self.is_unconditional_jump() || self.is_return() || self.is_switch() {
            return None;
        }
        Some(self.address + self.size() as u64)
    }

    pub fn branches(&self) -> BTreeSet<u64> {
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

    fn disassembly_operands(&self, metadata_token_addresses: &BTreeMap<u64, u64>) -> Vec<String> {
        if self.is_short_argument_or_local_form() {
            return Vec::new();
        }
        if let Some(index) = self.argument_index() {
            return vec![index.to_string()];
        }
        if let Some(index) = self.local_index() {
            return vec![index.to_string()];
        }
        if let Some(value) = self.inline_i32_constant() {
            return vec![value.to_string()];
        }
        if let Some(value) = self.inline_i64_constant() {
            return vec![value.to_string()];
        }
        if let Some(value) = self.inline_f32_constant() {
            return vec![format!("{value}")];
        }
        if let Some(value) = self.inline_f64_constant() {
            return vec![format!("{value}")];
        }
        if self.is_switch() {
            let targets = self
                .switch_targets()
                .into_iter()
                .map(|target| format!("0x{target:x}"))
                .collect::<Vec<_>>();
            return vec![format!("({})", targets.join(", "))];
        }
        if self.is_jump() {
            if let Some(target) = self.branch_target() {
                return vec![format!("0x{target:x}")];
            }
        }
        if let Some(token) = self.metadata_token() {
            let mut text = format!("0x{token:08x}");
            if let Some(address) = metadata_token_addresses.get(&(token as u64)) {
                text.push_str(&format!(" -> 0x{address:x}"));
            }
            return vec![text];
        }
        if matches!(self.mnemonic, Mnemonic::No | Mnemonic::Unaligned) {
            return vec![self.operand_u8().to_string()];
        }
        Vec::new()
    }

    fn inline_i32_constant(&self) -> Option<i32> {
        match self.mnemonic {
            Mnemonic::LdcI4M1 => Some(-1),
            Mnemonic::LdcI40 => Some(0),
            Mnemonic::LdcI41 => Some(1),
            Mnemonic::LdcI42 => Some(2),
            Mnemonic::LdcI43 => Some(3),
            Mnemonic::LdcI44 => Some(4),
            Mnemonic::LdcI45 => Some(5),
            Mnemonic::LdcI46 => Some(6),
            Mnemonic::LdcI47 => Some(7),
            Mnemonic::LdcI48 => Some(8),
            Mnemonic::LdcI4S => Some(self.operand_i8() as i32),
            Mnemonic::LdcI4 => Some(self.operand_i32()),
            _ => None,
        }
    }

    fn inline_i64_constant(&self) -> Option<i64> {
        matches!(self.mnemonic, Mnemonic::LdcI8).then(|| self.operand_i64())
    }

    fn inline_f32_constant(&self) -> Option<f32> {
        matches!(self.mnemonic, Mnemonic::LdcR4).then(|| self.operand_f32())
    }

    fn inline_f64_constant(&self) -> Option<f64> {
        matches!(self.mnemonic, Mnemonic::LdcR8).then(|| self.operand_f64())
    }

    fn branch_target(&self) -> Option<u64> {
        self.branches().iter().next().copied()
    }

    fn switch_targets(&self) -> Vec<u64> {
        self.branches().into_iter().collect()
    }

    fn switch_offsets(&self) -> Vec<i32> {
        let count = self
            .bytes
            .get(self.mnemonic_size()..self.mnemonic_size() + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or_default() as usize;
        let mut result = Vec::with_capacity(count);
        let start = self.mnemonic_size() + 4;
        for index in 0..count {
            let offset = start + index * 4;
            let bytes = self
                .bytes
                .get(offset..offset + 4)
                .and_then(|value| value.try_into().ok())
                .unwrap_or([0u8; 4]);
            result.push(i32::from_le_bytes(bytes));
        }
        result
    }

    fn metadata_token(&self) -> Option<u32> {
        if !matches!(
            self.mnemonic,
            Mnemonic::Box
                | Mnemonic::Call
                | Mnemonic::CallI
                | Mnemonic::CallVirt
                | Mnemonic::CastClass
                | Mnemonic::Constrained
                | Mnemonic::Cpobj
                | Mnemonic::InitObj
                | Mnemonic::IsInst
                | Mnemonic::Jmp
                | Mnemonic::LdElm
                | Mnemonic::LdElmA
                | Mnemonic::LdFld
                | Mnemonic::LdFldA
                | Mnemonic::LdFtn
                | Mnemonic::LdObj
                | Mnemonic::LdSFld
                | Mnemonic::LdSFldA
                | Mnemonic::LdStr
                | Mnemonic::LdToken
                | Mnemonic::LdVirtFtn
                | Mnemonic::MkRefAny
                | Mnemonic::NewArr
                | Mnemonic::NewObj
                | Mnemonic::RefAnyVal
                | Mnemonic::SizeOf
                | Mnemonic::StElem
                | Mnemonic::StFld
                | Mnemonic::StObj
                | Mnemonic::StSFld
                | Mnemonic::Unbox
                | Mnemonic::UnboxAny
        ) {
            return None;
        }
        let operand = self.operand_bytes();
        (operand.len() >= 4)
            .then(|| u32::from_le_bytes([operand[0], operand[1], operand[2], operand[3]]))
    }

    fn argument_index(&self) -> Option<u32> {
        match self.mnemonic {
            Mnemonic::LdArg0 => Some(0),
            Mnemonic::LdArg1 => Some(1),
            Mnemonic::LdArg2 => Some(2),
            Mnemonic::LdArg3 => Some(3),
            Mnemonic::LdArgS | Mnemonic::LdArgAS | Mnemonic::StArgS => {
                Some(self.operand_u8() as u32)
            }
            Mnemonic::LdArg | Mnemonic::LdArgA | Mnemonic::StArg => Some(self.operand_u16() as u32),
            _ => None,
        }
    }

    fn local_index(&self) -> Option<u32> {
        match self.mnemonic {
            Mnemonic::LdLoc0 | Mnemonic::StLoc0 => Some(0),
            Mnemonic::LdLoc1 | Mnemonic::StLoc1 => Some(1),
            Mnemonic::LdLoc2 | Mnemonic::StLoc2 => Some(2),
            Mnemonic::LdLoc3 | Mnemonic::StLoc3 => Some(3),
            Mnemonic::LdLocS | Mnemonic::LdLocAS | Mnemonic::StLocS => {
                Some(self.operand_u8() as u32)
            }
            Mnemonic::LdLoc | Mnemonic::LdLocA | Mnemonic::SLoc => Some(self.operand_u16() as u32),
            _ => None,
        }
    }

    fn is_short_argument_or_local_form(&self) -> bool {
        matches!(
            self.mnemonic,
            Mnemonic::LdArg0
                | Mnemonic::LdArg1
                | Mnemonic::LdArg2
                | Mnemonic::LdArg3
                | Mnemonic::LdLoc0
                | Mnemonic::LdLoc1
                | Mnemonic::LdLoc2
                | Mnemonic::LdLoc3
                | Mnemonic::StLoc0
                | Mnemonic::StLoc1
                | Mnemonic::StLoc2
                | Mnemonic::StLoc3
                | Mnemonic::LdcI4M1
                | Mnemonic::LdcI40
                | Mnemonic::LdcI41
                | Mnemonic::LdcI42
                | Mnemonic::LdcI43
                | Mnemonic::LdcI44
                | Mnemonic::LdcI45
                | Mnemonic::LdcI46
                | Mnemonic::LdcI47
                | Mnemonic::LdcI48
        )
    }

    fn operand_u8(&self) -> u8 {
        self.operand_bytes().first().copied().unwrap_or_default()
    }

    fn operand_i8(&self) -> i8 {
        i8::from_le_bytes([self.operand_u8()])
    }

    fn operand_u16(&self) -> u16 {
        let operand = self.operand_bytes();
        let bytes = operand
            .get(..2)
            .and_then(|value| value.try_into().ok())
            .unwrap_or([0u8; 2]);
        u16::from_le_bytes(bytes)
    }

    fn operand_i32(&self) -> i32 {
        let operand = self.operand_bytes();
        let bytes = operand
            .get(..4)
            .and_then(|value| value.try_into().ok())
            .unwrap_or([0u8; 4]);
        i32::from_le_bytes(bytes)
    }

    fn operand_i64(&self) -> i64 {
        let operand = self.operand_bytes();
        let bytes = operand
            .get(..8)
            .and_then(|value| value.try_into().ok())
            .unwrap_or([0u8; 8]);
        i64::from_le_bytes(bytes)
    }

    fn operand_f32(&self) -> f32 {
        let operand = self.operand_bytes();
        let bytes = operand
            .get(..4)
            .and_then(|value| value.try_into().ok())
            .unwrap_or([0u8; 4]);
        f32::from_le_bytes(bytes)
    }

    fn operand_f64(&self) -> f64 {
        let operand = self.operand_bytes();
        let bytes = operand
            .get(..8)
            .and_then(|value| value.try_into().ok())
            .unwrap_or([0u8; 8]);
        f64::from_le_bytes(bytes)
    }

    fn raw_branch_offset(&self) -> Option<i32> {
        match self.mnemonic {
            Mnemonic::BrS
            | Mnemonic::BrFalseS
            | Mnemonic::BrTrueS
            | Mnemonic::BneUnS
            | Mnemonic::BltS
            | Mnemonic::BltUnS
            | Mnemonic::BeqS
            | Mnemonic::BgeS
            | Mnemonic::BgeUnS
            | Mnemonic::BgtS
            | Mnemonic::BgtUnS
            | Mnemonic::BleS
            | Mnemonic::BleUnS
            | Mnemonic::LeaveS => Some(self.operand_i8() as i32),
            Mnemonic::Br
            | Mnemonic::BrFalse
            | Mnemonic::BrTrue
            | Mnemonic::BneUn
            | Mnemonic::Blt
            | Mnemonic::BltUn
            | Mnemonic::Beq
            | Mnemonic::Bge
            | Mnemonic::BgeUn
            | Mnemonic::Bgt
            | Mnemonic::BgtUn
            | Mnemonic::Ble
            | Mnemonic::BleUn
            | Mnemonic::Leave
            | Mnemonic::Jmp => Some(self.operand_i32()),
            _ => None,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldarg0_exposes_mnemonic_and_operand() {
        let instruction = Instruction::new(&[0x02], 0x1000).expect("ldarg.0 should decode");
        let operands = instruction.normalized_operands(&BTreeMap::new());
        assert_eq!(instruction.mnemonic_text(), "ldarg.0");
        assert_eq!(instruction.disassembly_text(&BTreeMap::new()), "ldarg.0");
        assert_eq!(operands.len(), 1);
        let OperandKind::Immediate(immediate) = &operands[0].kind else {
            panic!("expected immediate operand");
        };
        assert_eq!(immediate.value, 0);
    }

    #[test]
    fn branch_operands_resolve_absolute_target() {
        let instruction = Instruction::new(&[0x2b, 0x02], 0x1000).expect("br.s should decode");
        let operands = instruction.normalized_operands(&BTreeMap::new());
        assert_eq!(instruction.mnemonic_text(), "br.s");
        assert_eq!(
            instruction.disassembly_text(&BTreeMap::new()),
            "br.s 0x1004"
        );
        let OperandKind::Immediate(immediate) = &operands[0].kind else {
            panic!("expected immediate operand");
        };
        assert_eq!(immediate.value, 2);
    }

    #[test]
    fn call_token_operand_tracks_resolution() {
        let instruction =
            Instruction::new(&[0x28, 0x01, 0x00, 0x00, 0x06], 0x2000).expect("call should decode");
        let mut metadata_token_addresses = BTreeMap::new();
        metadata_token_addresses.insert(0x06000001, 0x3456);
        let operands = instruction.normalized_operands(&metadata_token_addresses);
        assert_eq!(
            instruction.disassembly_text(&metadata_token_addresses),
            "call 0x06000001 -> 0x3456"
        );
        let OperandKind::Immediate(immediate) = &operands[0].kind else {
            panic!("expected immediate operand");
        };
        assert_eq!(immediate.value, 0x06000001);
    }

    #[test]
    fn switch_exposes_one_immediate_per_target() {
        let instruction = Instruction::new(
            &[
                0x45, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            ],
            0x3000,
        )
        .expect("switch should decode");
        let operands = instruction.normalized_operands(&BTreeMap::new());
        assert_eq!(operands.len(), 2);
        let values = operands
            .into_iter()
            .map(|operand| match operand.kind {
                OperandKind::Immediate(immediate) => immediate.value,
                _ => panic!("expected immediate operand"),
            })
            .collect::<Vec<_>>();
        assert_eq!(values, vec![4, 8]);
    }
}
