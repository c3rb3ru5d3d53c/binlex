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

use crate::Architecture;
use crate::disassemblers::arm64::disassembler::Disassembler;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::{Insn, Instructions};
use std::io::Error;

impl<'disassembler> Disassembler<'disassembler> {
    pub fn get_instruction_operands(&self, instruction: &Insn) -> Result<Vec<ArchOperand>, Error> {
        let detail = self
            .cs
            .insn_detail(instruction)
            .map_err(|_| Error::other("failed to get instruction detail"))?;
        let arch = detail.arch_detail();
        Ok(arch.operands())
    }

    pub fn get_instruction_condition_code(&self, instruction: &Insn) -> Result<Option<u64>, Error> {
        let detail = self
            .cs
            .insn_detail(instruction)
            .map_err(|_| Error::other("failed to get instruction detail"))?;
        let arch = detail.arch_detail();
        if let Some(detail) = arch.arm64() {
            Ok(Some(detail.cc() as u64))
        } else {
            Ok(None)
        }
    }

    pub fn get_instruction_operand(
        &self,
        instruction: &Insn,
        index: usize,
    ) -> Result<ArchOperand, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        operands
            .get(index)
            .cloned()
            .ok_or_else(|| Error::other("failed to get instruction operand"))
    }

    pub fn disassemble_instructions(
        &self,
        address: u64,
        count: u64,
    ) -> Result<Instructions<'_>, Error> {
        let Some(start) = self.image_offset(address) else {
            return Err(Error::other("address out of bounds"));
        };
        let instructions = self
            .cs
            .disasm_count(&self.image[start..], address, count as usize)
            .map_err(|_| Error::other("failed to disassemble instructions"))?;
        if instructions.is_empty() {
            return Err(Error::other("no instructions found"));
        }
        Ok(instructions)
    }

    pub(crate) fn cs_new(machine: Architecture, detail: bool) -> Result<Capstone, Error> {
        match machine {
            Architecture::ARM64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(detail)
                .build()
                .map_err(|e| Error::other(format!("capstone error: {:?}", e))),
            _ => Err(Error::other("unsupported architecture")),
        }
    }
}
