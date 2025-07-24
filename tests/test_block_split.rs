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

use binlex::binary::Binary;
use binlex::controlflow::{Function, Graph};
use binlex::disassemblers::capstone::Disassembler;
use binlex::{Architecture, Config};
use std::collections::BTreeMap;

fn pattern_matches_bytes(pattern: &str, bytes: &[u8]) -> bool {
    if pattern.len() != bytes.len() * 2 {
        return false;
    }
    for (i, byte) in bytes.iter().enumerate() {
        let chunk = &pattern[i * 2..i * 2 + 2];
        let hex = format!("{:02x}", byte);
        let b0 = chunk.as_bytes()[0];
        let b1 = chunk.as_bytes()[1];
        if b0 != b'?' && b0.to_ascii_lowercase() != hex.as_bytes()[0] {
            return false;
        }
        if b1 != b'?' && b1.to_ascii_lowercase() != hex.as_bytes()[1] {
            return false;
        }
    }
    true
}

#[test]
fn test_block_split_pending() {
    // assembly: jz 0x4; nop; nop; ret
    let bytes = vec![0x74, 0x02, 0x90, 0x90, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm = Disassembler::new(Architecture::I386, &bytes, ranges.clone(), config.clone())
        .expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config.clone());
    // pre-mark address 2 as a block start
    graph.blocks.enqueue(2);
    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");
    let func = Function::new(0, &graph).expect("function");
    let mut blocks = func.blocks.iter();
    let first = blocks.next().unwrap().1;
    assert_eq!(
        Binary::to_hex(&first.bytes()),
        "7402",
        "first block incorrect"
    );
}

#[test]
fn test_full_function_disassembly() {
    let hex = "558bec5657668b7d0c33f6833d88cc4300020fb7d77d2a8b4d088bf1668b0183c1026685c075f583e9023bce740966393975f48bc1eb6733c06639110f44c1eb5d8b5508eb110fb702663bc70f44f26685c0744883c2028d4201a80e75e833c0663bc7751eb80100ffff660f6ec8eb0383c2100f1002660f3a63c81575f28d044aeb1b0fb7c7660f6ec0660f3a63024173038d344a740583c210ebee8bc65f5e5dc3";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm = Disassembler::new(Architecture::I386, &bytes, ranges.clone(), config.clone())
        .expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config.clone());
    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");
    let func = Function::new(0, &graph).expect("function");
    assert_eq!(graph.listing.len(), 62, "incorrect instruction count");
    assert_eq!(func.blocks.len(), 14, "incorrect block count");
    let mut collected = Vec::<u8>::new();
    for addr in graph.instruction_addresses().iter().copied() {
        let instr = graph.get_instruction(addr).unwrap();
        collected.extend(instr.bytes);
    }
    assert_eq!(Binary::to_hex(&collected), hex, "listing bytes mismatch");

    // ensure that the bytes returned by Function::bytes() match the input
    let func_bytes = func.bytes().expect("function bytes");
    assert_eq!(Binary::to_hex(&func_bytes), hex, "function bytes mismatch");

    // verify chromosome pattern length and matching
    let pattern = func.pattern().expect("pattern");
    assert_eq!(pattern.len(), hex.len(), "pattern length mismatch");
    assert!(
        pattern_matches_bytes(&pattern, &func_bytes),
        "pattern does not match bytes"
    );

    // verify the function is contiguous
    assert!(func.contiguous(), "function should be contiguous");
}
