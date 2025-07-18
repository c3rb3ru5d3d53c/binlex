use binlex::binary::Binary;
use binlex::controlflow::{Graph, Function};
use binlex::disassemblers::capstone::Disassembler;
use binlex::{Architecture, Config};
use std::collections::BTreeMap;

#[test]
fn test_block_split_pending() {
    // assembly: jz 0x4; nop; nop; ret
    let bytes = vec![0x74, 0x02, 0x90, 0x90, 0xc3];
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    let config = Config::new();
    let disasm = Disassembler::new(Architecture::I386, &bytes, ranges.clone(), config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config.clone());
    // pre-mark address 2 as a block start
    graph.blocks.enqueue(2);
    disasm.disassemble_function(0, &mut graph).expect("disassemble");
    let func = Function::new(0, &graph).expect("function");
    let mut blocks = func.blocks.iter();
    let first = blocks.next().unwrap().1;
    assert_eq!(Binary::to_hex(&first.bytes()), "7402", "first block incorrect");
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
    let disasm = Disassembler::new(Architecture::I386, &bytes, ranges.clone(), config.clone()).expect("disasm");
    let mut graph = Graph::new(Architecture::I386, config.clone());
    disasm.disassemble_function(0, &mut graph).expect("disassemble");
    let func = Function::new(0, &graph).expect("function");
    assert_eq!(graph.listing.len(), 62, "incorrect instruction count");
    assert_eq!(func.blocks.len(), 14, "incorrect block count");
    let mut collected = Vec::<u8>::new();
    for addr in graph.instruction_addresses().iter().copied() {
        let instr = graph.get_instruction(addr).unwrap();
        collected.extend(instr.bytes);
    }
    assert_eq!(Binary::to_hex(&collected), hex, "function bytes mismatch");
}
