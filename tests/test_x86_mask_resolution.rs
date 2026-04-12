use std::collections::BTreeMap;

use binlex::controlflow::Graph;
use binlex::disassemblers::capstone::Disassembler;
use binlex::{Architecture, Config};

#[test]
fn x86_immediate_masks_full_operand_bytes_and_normalizes_them() {
    let config = Config::default();
    let bytes = vec![0xE8, 0x78, 0x56, 0x34, 0x12]; // call rel32
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let disassembler = Disassembler::from_bytes(Architecture::I386, &bytes, ranges, config.clone())
        .expect("disassembler should build");
    let mut graph = Graph::new(Architecture::I386, config);

    disassembler
        .disassemble_instruction(0, &mut graph)
        .expect("instruction should disassemble");

    let instruction = graph.get_instruction(0).expect("instruction should exist");

    assert_eq!(instruction.bytes, bytes);
    assert_eq!(
        instruction.chromosome_mask,
        vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(instruction.pattern, "e8????????");
    assert_eq!(
        instruction.chromosome().masked(),
        vec![0xE8, 0x00, 0x00, 0x00, 0x00]
    );
}
