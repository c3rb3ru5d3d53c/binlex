use std::collections::BTreeMap;

use binlex::controlflow::Graph;
use binlex::disassemblers::capstone::Disassembler;
use binlex::{Architecture, Config};

fn arm64_disassembler(bytes: &[u8], config: Config) -> Disassembler<'_> {
    let mut ranges = BTreeMap::new();
    ranges.insert(0u64, bytes.len() as u64);
    Disassembler::new(Architecture::ARM64, bytes, ranges, config).expect("disasm")
}

#[test]
fn test_arm64_absolute_register_jump_table_recovers_all_targets() {
    // assembly:
    //   cmp  w1, #2
    //   b.hi fallback
    //   adr  x2, table
    //   ldr  x3, [x2, w1, uxtw #3]
    //   br   x3
    // fallback:
    //   ret
    // table:
    //   .xword case0, case1, case2
    // case0:
    //   ret
    // case1:
    //   ret
    // case2:
    //   ret
    let bytes = vec![
        0x3f, 0x08, 0x00, 0x71, 0x88, 0x00, 0x00, 0x54, 0x82, 0x00, 0x00, 0x10, 0x43, 0x58, 0x61,
        0xf8, 0x60, 0x00, 0x1f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(16).expect("jump table instruction");
    assert!(
        instruction.has_indirect_target,
        "jump table should be marked as indirect"
    );
    assert_eq!(
        instruction.to,
        [0x30u64, 0x34u64, 0x38u64].into_iter().collect(),
        "absolute register jump table should recover all case targets"
    );
    assert_eq!(
        instruction.edges, 3,
        "jump table should expose three outgoing edges"
    );
}

#[test]
fn test_arm64_relative_register_jump_table_recovers_all_targets() {
    // assembly:
    //   cmp   w1, #2
    //   b.hi  fallback
    //   adr   x2, table
    //   ldrsw x3, [x2, w1, uxtw #2]
    //   add   x3, x2, x3
    //   br    x3
    // fallback:
    //   ret
    // table:
    //   .word case0 - table
    //   .word case1 - table
    //   .word case2 - table
    // case0:
    //   ret
    // case1:
    //   ret
    // case2:
    //   ret
    let bytes = vec![
        0x3f, 0x08, 0x00, 0x71, 0xa8, 0x00, 0x00, 0x54, 0xa2, 0x00, 0x00, 0x10, 0x43, 0x58, 0xa1,
        0xb8, 0x43, 0x00, 0x03, 0x8b, 0x60, 0x00, 0x1f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6, 0x0c, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0xc0, 0x03, 0x5f, 0xd6, 0xc0,
        0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(20).expect("jump table instruction");
    assert!(
        instruction.has_indirect_target,
        "jump table should be marked as indirect"
    );
    assert_eq!(
        instruction.to,
        [0x28u64, 0x2cu64, 0x30u64].into_iter().collect(),
        "relative register jump table should recover all case targets"
    );
    assert_eq!(
        instruction.edges, 3,
        "jump table should expose three outgoing edges"
    );
}

#[test]
fn test_arm64_prologue_and_adr_executable_address_requires_target_prologue() {
    // assembly:
    //   stp x29, x30, [sp, #-16]!
    //   mov x29, sp
    //   adr x0, target
    //   ret
    // target:
    //   ret
    let bytes = vec![
        0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0x40, 0x00, 0x00, 0x10, 0xc0, 0x03, 0x5f,
        0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let prologue = graph.get_instruction(0).expect("prologue instruction");
    assert!(
        prologue.is_block_start,
        "function start should start a block"
    );
    assert!(
        prologue.is_function_start,
        "function start should be marked"
    );
    assert!(
        prologue.is_prologue,
        "common ARM64 frame setup should be marked"
    );

    let adr = graph.get_instruction(8).expect("adr instruction");
    assert!(
        adr.functions.is_empty(),
        "adr should not promote an executable target that lacks a prologue"
    );
    assert!(
        graph.functions.dequeue_all().is_empty(),
        "adr-discovered executable target should not be enqueued without a prologue"
    );
}

#[test]
fn test_arm64_memory_instruction_masks_addressing_bits_only() {
    // assembly: ldr x3, [x2, w1, uxtw #3]
    let bytes = vec![0x43, 0x58, 0x61, 0xf8];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert_eq!(instruction.bytes, bytes);
    assert_eq!(instruction.chromosome_mask, vec![0xE0, 0xFF, 0x1F, 0x00]);
    assert_eq!(instruction.pattern, "?3????f8");
    assert_eq!(
        instruction.chromosome().masked(),
        vec![0x03, 0x00, 0x60, 0xF8]
    );
}

#[test]
fn test_arm64_pair_memory_instruction_masks_pair_addressing_bits_only() {
    // assembly: stp x29, x30, [sp, #-16]!
    let bytes = vec![0xfd, 0x7b, 0xbf, 0xa9];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("instruction");
    assert_eq!(instruction.bytes, bytes);
    assert_eq!(instruction.chromosome_mask, vec![0xE0, 0xFF, 0x3F, 0x00]);
    assert_eq!(instruction.pattern, "?d????a9");
    assert_eq!(
        instruction.chromosome().masked(),
        vec![0x1D, 0x00, 0x80, 0xA9]
    );
}

#[test]
fn test_arm64_register_indirect_jump_resolves_target_through_adr_add() {
    // assembly:
    //   adr x2, anchor
    //   add x0, x2, #0x10
    //   br  x0
    // anchor:
    //   ret
    //   .space 12
    // target:
    //   ret
    let bytes = vec![
        0x62, 0x00, 0x00, 0x10, 0x40, 0x40, 0x00, 0x91, 0x00, 0x00, 0x1f, 0xd6, 0xc0, 0x03, 0x5f,
        0xd6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(8).expect("indirect jump instruction");
    assert!(
        instruction.has_indirect_target,
        "register-indirect jump should be marked as indirect"
    );
    assert_eq!(
        instruction.to,
        [0x1cu64].into_iter().collect(),
        "adr/add/br should recover the indirect jump target"
    );
    assert!(
        instruction.functions.is_empty(),
        "indirect jump target should not be tracked as a function"
    );
}

#[test]
fn test_arm64_register_indirect_call_resolves_function_target_through_mov() {
    // assembly:
    //   adr x0, target
    //   mov x16, x0
    //   blr x16
    //   ret
    // target:
    //   ret
    let bytes = vec![
        0x80, 0x00, 0x00, 0x10, 0xf0, 0x03, 0x00, 0xaa, 0x00, 0x02, 0x3f, 0xd6, 0xc0, 0x03, 0x5f,
        0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(8).expect("indirect call instruction");
    assert!(
        instruction.is_call,
        "instruction should be identified as call"
    );
    assert!(
        instruction.has_indirect_target,
        "register-indirect call should be marked as indirect"
    );
    assert_eq!(
        instruction.functions,
        [0x10u64].into_iter().collect(),
        "adr/mov/blr should recover the indirect call target as a function"
    );
    assert_eq!(
        graph.functions.dequeue_all(),
        [0x10u64].into_iter().collect(),
        "indirect call target should be enqueued as a function"
    );
}

#[test]
fn test_arm64_conditional_controlflow_instructions_recover_targets_and_edges() {
    // assembly:
    //   cbz  x0, target0
    //   cbnz w1, target1
    //   tbz  w2, #3, target2
    //   tbnz w3, #7, target3
    //   ret
    // target0:
    //   ret
    // target1:
    //   ret
    // target2:
    //   ret
    // target3:
    //   ret
    let bytes = vec![
        0xa0, 0x00, 0x00, 0xb4, 0xa1, 0x00, 0x00, 0x35, 0xa2, 0x00, 0x18, 0x36, 0xa3, 0x00, 0x38,
        0x37, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03,
        0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    for (address, target) in [(0u64, 0x14u64), (4, 0x18), (8, 0x1c), (12, 0x20)] {
        let instruction = graph.get_instruction(address).expect("conditional branch");
        assert!(instruction.is_jump, "conditional branch should be a jump");
        assert!(
            instruction.is_conditional,
            "conditional branch should be marked conditional"
        );
        assert_eq!(
            instruction.to,
            [target].into_iter().collect(),
            "conditional branch should recover its immediate target"
        );
        assert_eq!(
            instruction.edges, 2,
            "conditional branch should expose both taken and fallthrough edges"
        );
    }
}

#[test]
fn test_arm64_direct_call_tracks_function_target() {
    // assembly:
    //   bl target
    //   ret
    // target:
    //   ret
    let bytes = vec![
        0x02, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_instruction(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(0).expect("direct call instruction");
    assert!(
        instruction.is_call,
        "instruction should be identified as call"
    );
    assert_eq!(
        instruction.functions,
        [0x8u64].into_iter().collect(),
        "direct call target should be tracked as a function"
    );
    assert_eq!(
        graph.functions.dequeue_all(),
        [0x8u64].into_iter().collect(),
        "direct call target should be enqueued as a function"
    );
}

#[test]
fn test_arm64_register_copy_cycle_does_not_overflow_indirect_target_resolution() {
    // assembly:
    //   mov x0, x1
    //   mov x1, x0
    //   br  x0
    let bytes = vec![
        0xe0, 0x03, 0x01, 0xaa, 0xe1, 0x03, 0x00, 0xaa, 0x00, 0x00, 0x1f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config.clone());
    let mut graph = Graph::new(Architecture::ARM64, config);

    disasm
        .disassemble_function(0, &mut graph)
        .expect("disassemble");

    let instruction = graph.get_instruction(8).expect("indirect jump instruction");
    assert!(
        instruction.has_indirect_target,
        "register-indirect jump should still be marked as indirect"
    );
    assert!(
        instruction.to.is_empty(),
        "cyclic register copies should not produce a fabricated target"
    );
}

#[test]
fn test_arm64_sweep_discovers_direct_call_target_after_valid_runs_from_two_callers() {
    // assembly:
    //   mov x0, x0
    //   mov x1, x1
    //   mov x2, x2
    //   mov x3, x3
    //   bl  target
    //   mov x5, x5
    //   mov x6, x6
    //   mov x7, x7
    //   mov x8, x8
    //   bl  target
    //   ret
    // target:
    //   mov x4, x4
    //   ret
    let bytes = vec![
        0xe0, 0x03, 0x00, 0xaa, 0xe1, 0x03, 0x01, 0xaa, 0xe2, 0x03, 0x02, 0xaa, 0xe3, 0x03,
        0x03, 0xaa, 0x07, 0x00, 0x00, 0x94, 0xe5, 0x03, 0x05, 0xaa, 0xe6, 0x03, 0x06, 0xaa,
        0xe7, 0x03, 0x07, 0xaa, 0xe8, 0x03, 0x08, 0xaa, 0x02, 0x00, 0x00, 0x94, 0xc0, 0x03,
        0x5f, 0xd6, 0xe4, 0x03, 0x04, 0xaa, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config);

    assert_eq!(
        disasm.disassemble_sweep(),
        [0x2cu64].into_iter().collect(),
        "sweep should discover the direct call target after two qualifying direct callers"
    );
}

#[test]
fn test_arm64_sweep_rejects_direct_call_without_preceding_valid_run() {
    // assembly:
    //   bl  target
    //   ret
    // target:
    //   mov x4, x4
    //   ret
    let bytes = vec![
        0x02, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6, 0xe4, 0x03, 0x04, 0xaa, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let config = Config::new();
    let disasm = arm64_disassembler(&bytes, config);

    assert!(
        disasm.disassemble_sweep().is_empty(),
        "sweep should ignore direct calls that are not preceded by a sufficient valid decode run"
    );
}
