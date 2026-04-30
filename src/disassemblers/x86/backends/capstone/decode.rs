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

use crate::disassemblers::x86::disassembler::Disassembler;
use crate::Architecture;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::{Insn, Instructions};
use std::io::{Error, ErrorKind};

impl<'disassembler> Disassembler<'disassembler> {
    #[allow(dead_code)]
    pub fn get_instruction_operands(&self, instruction: &Insn) -> Result<Vec<ArchOperand>, Error> {
        let detail = self
            .cs
            .insn_detail(instruction)
            .map_err(|_| Error::new(ErrorKind::Other, "failed to get instruction detail"))?;
        let arch = detail.arch_detail();
        Ok(arch.operands())
    }

    #[allow(dead_code)]
    pub fn get_instruction_operand(
        &self,
        instruction: &Insn,
        index: usize,
    ) -> Result<ArchOperand, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        let operand = match operands.get(index) {
            Some(operand) => operand.clone(),
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "failed to get instruction operand",
                ));
            }
        };
        Ok(operand)
    }

    pub fn disassemble_instructions(
        &self,
        address: u64,
        count: u64,
    ) -> Result<Instructions<'_>, Error> {
        if (address as usize) >= self.image.len() {
            return Err(Error::new(ErrorKind::Other, "address out of bounds"));
        }
        let instructions = self
            .cs
            .disasm_count(&self.image[address as usize..], address, count as usize)
            .map_err(|_| Error::new(ErrorKind::Other, "failed to disassemble instructions"))?;
        if instructions.is_empty() {
            return Err(Error::new(ErrorKind::Other, "no instructions found"));
        }
        Ok(instructions)
    }

    pub(crate) fn cs_new(machine: Architecture, detail: bool) -> Result<Capstone, Error> {
        match machine {
            Architecture::AMD64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(detail)
                .build()
                .map_err(|e| Error::new(ErrorKind::Other, format!("capstone error: {:?}", e))),
            Architecture::I386 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(detail)
                .build()
                .map_err(|e| Error::new(ErrorKind::Other, format!("capstone error: {:?}", e))),
            _ => Err(Error::new(ErrorKind::Other, "unsupported architecture")),
        }
    }
}
