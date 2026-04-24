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

use binlex::controlflow::{Function, Graph};
use binlex::disassemblers::capstone::Disassembler;
use binlex::hex;
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
    assert_eq!(hex::encode(&first.bytes()), "7402", "first block incorrect");
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
    assert_eq!(func.blocks.len(), 23, "incorrect block count");
    let mut collected = Vec::<u8>::new();
    for addr in graph.instruction_addresses().iter().copied() {
        let instr = graph.get_instruction(addr).unwrap();
        collected.extend(instr.bytes);
    }
    assert_eq!(hex::encode(&collected), hex, "listing bytes mismatch");

    // ensure that the bytes returned by Function::bytes() match the input
    let func_bytes = func.bytes().expect("function bytes");
    assert_eq!(hex::encode(&func_bytes), hex, "function bytes mismatch");

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

#[test]
fn test_direct_call_outside_executable_range_is_not_enqueued_as_function() {
    // assembly: call 0xa; ret
    let bytes = vec![0xe8, 0x05, 0x00, 0x00, 0x00, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert!(
        instruction.is_call,
        "instruction should be identified as call"
    );
    assert!(
        instruction.functions.is_empty(),
        "out-of-range call target should not be tracked as a function"
    );
    assert!(
        graph.functions.dequeue_all().is_empty(),
        "out-of-range call target should not be enqueued"
    );
}

#[test]
fn test_direct_jump_inside_executable_range_is_not_enqueued_as_function() {
    // assembly: jmp 0x2; ret
    let bytes = vec![0xeb, 0x00, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert!(
        instruction.is_jump,
        "instruction should be identified as jump"
    );
    assert_eq!(instruction.to, [2u64].into_iter().collect());
    assert!(
        instruction.functions.is_empty(),
        "direct jump target should not be tracked as a function"
    );
    assert!(
        graph.functions.dequeue_all().is_empty(),
        "direct jump target should not be enqueued as a function"
    );
}

#[test]
fn test_i386_indirect_call_absolute_memory_resolves_function_target() {
    // assembly:
    //   call dword ptr [0x8]
    //   ret
    //   db 0x90
    //   dd 0x0c
    //   ret
    let bytes = vec![
        0xff, 0x15, 0x08, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x0c, 0x00, 0x00, 0x00, 0xc3,
    ];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert!(
        instruction.is_call,
        "instruction should be identified as call"
    );
    assert_eq!(
        instruction.functions,
        [12u64].into_iter().collect(),
        "indirect call target should be tracked as a function"
    );
    assert_eq!(
        graph.functions.dequeue_all(),
        [12u64].into_iter().collect(),
        "indirect call target should be enqueued as a function"
    );
}

#[test]
fn test_i386_indirect_jump_absolute_memory_resolves_block_target_only() {
    // assembly:
    //   jmp dword ptr [0x8]
    //   ret
    //   db 0x90
    //   dd 0x0c
    //   ret
    let bytes = vec![
        0xff, 0x25, 0x08, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x0c, 0x00, 0x00, 0x00, 0xc3,
    ];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert!(
        instruction.is_jump,
        "instruction should be identified as jump"
    );
    assert_eq!(
        instruction.to,
        [12u64].into_iter().collect(),
        "indirect jump target should be tracked as a control-flow target"
    );
    assert!(
        instruction.functions.is_empty(),
        "indirect jump target should not be tracked as a function"
    );
    assert!(
        graph.functions.dequeue_all().is_empty(),
        "indirect jump target should not be enqueued as a function"
    );
}

#[test]
fn test_i386_indexed_jump_table_memory_recovers_all_targets() {
    // assembly:
    //   cmp ecx, 2
    //   ja 0xc
    //   jmp dword ptr [ecx*4 + 0x14]
    // 0xc:
    //   ret
    // 0x14:
    //   dd 0x20, 0x21, 0x22
    // 0x20:
    //   ret
    // 0x21:
    //   ret
    // 0x22:
    //   ret
    let bytes = vec![
        0x83, 0xf9, 0x02, 0x77, 0x07, 0xff, 0x24, 0x8d, 0x14, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x20, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x22, 0x00,
        0x00, 0x00, 0xc3, 0xc3, 0xc3,
    ];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(5).expect("jump table instruction");
    assert!(
        instruction.has_indirect_target,
        "jump table should be marked as indirect"
    );
    assert_eq!(
        instruction.to,
        [0x20u64, 0x21u64, 0x22u64].into_iter().collect(),
        "indexed jump table should recover all case targets"
    );
    assert_eq!(
        instruction.edges, 3,
        "jump table should expose three outgoing edges"
    );
}

#[test]
fn test_i386_register_jump_table_recovers_all_targets() {
    // assembly:
    //   cmp ecx, 2
    //   ja 0xe
    //   mov eax, dword ptr [ecx*4 + 0x18]
    //   jmp eax
    // 0xe:
    //   ret
    // 0x18:
    //   dd 0x24, 0x25, 0x26
    // 0x24:
    //   ret
    // 0x25:
    //   ret
    // 0x26:
    //   ret
    let bytes = vec![
        0x83, 0xf9, 0x02, 0x77, 0x09, 0x8b, 0x04, 0x8d, 0x18, 0x00, 0x00, 0x00, 0xff, 0xe0, 0xc3,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x24, 0x00, 0x00, 0x00, 0x25, 0x00,
        0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0xc3, 0xc3, 0xc3,
    ];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(12).expect("jump table instruction");
    assert_eq!(
        instruction.to,
        [0x24u64, 0x25u64, 0x26u64].into_iter().collect(),
        "register-indirect jump table should recover all case targets"
    );
    assert_eq!(
        instruction.edges, 3,
        "jump table should expose three outgoing edges"
    );
}

#[test]
fn test_amd64_relative_register_jump_table_recovers_all_targets() {
    // assembly:
    //   cmp ecx, 2
    //   ja 0x15
    //   lea rdx, [rip + 0x14]
    //   movsxd rax, dword ptr [rdx + rcx*4]
    //   add rax, rdx
    //   jmp rax
    // 0x15:
    //   ret
    // 0x20:
    //   dd 0x10, 0x11, 0x12
    // 0x30:
    //   ret
    // 0x31:
    //   ret
    // 0x32:
    //   ret
    let bytes = vec![
        0x83, 0xf9, 0x02, 0x77, 0x10, 0x48, 0x8d, 0x15, 0x14, 0x00, 0x00, 0x00, 0x48, 0x63, 0x04,
        0x8a, 0x48, 0x01, 0xd0, 0xff, 0xe0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3, 0xc3, 0xc3,
    ];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::AMD64, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::AMD64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(19).expect("jump table instruction");
    assert_eq!(
        instruction.to,
        [0x30u64, 0x31u64, 0x32u64].into_iter().collect(),
        "relative jump table should recover all case targets"
    );
    assert_eq!(
        instruction.edges, 3,
        "jump table should expose three outgoing edges"
    );
}

#[test]
fn test_i386_lea_absolute_memory_resolves_executable_address() {
    // assembly: lea eax, [0x6]; ret
    let bytes = vec![0x8d, 0x05, 0x06, 0x00, 0x00, 0x00, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert_eq!(
        instruction.functions,
        [6u64].into_iter().collect(),
        "lea should recover the executable absolute address on i386"
    );
    assert_eq!(
        graph.functions.dequeue_all(),
        [6u64].into_iter().collect(),
        "lea-discovered executable address should be enqueued"
    );
}

#[test]
fn test_block_split_keeps_predecessor_terminator_metadata() {
    // assembly: nop; nop; ret
    let bytes = vec![0x90, 0x90, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    graph.blocks.enqueue(1);
    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let func = Function::new(0, &graph).expect("function");
    let first = func.blocks.get(&0).expect("first block");

    assert_eq!(
        hex::encode(&first.bytes()),
        "90",
        "first block bytes incorrect"
    );
    assert_eq!(
        first.number_of_instructions(),
        1,
        "first block should not include the next block's first instruction"
    );
    assert_eq!(
        first.edges(),
        1,
        "split block should have one outgoing edge"
    );
    assert_eq!(first.blocks(), [1u64].into_iter().collect());
}

#[test]
fn test_executable_address_end_is_exclusive() {
    let bytes = vec![0x90, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("decode at start should succeed");
    disasm
        .disassemble_instruction(1, &mut graph)
        .expect("decode inside range should succeed");
    assert!(
        disasm
            .disassemble_instruction(bytes.len() as u64, &mut graph)
            .is_err(),
        "decoding at the exclusive end should fail"
    );
}

#[test]
fn test_return_instruction_has_zero_edges() {
    let bytes = vec![0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm =
        Disassembler::new(Architecture::I386, &bytes, ranges, config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert!(
        instruction.is_return,
        "instruction should be identified as return"
    );
    assert_eq!(
        instruction.edges, 0,
        "return should not report outgoing edges"
    );
    assert_eq!(
        instruction.next(),
        None,
        "return should not have fallthrough"
    );
}
