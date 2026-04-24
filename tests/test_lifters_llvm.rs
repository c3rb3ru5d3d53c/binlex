use std::collections::{BTreeMap, BTreeSet};

use binlex::controlflow::{Block, Function, Graph, Instruction};
use binlex::lifters::llvm::Lifter;
use binlex::semantics::{SemanticDiagnosticKind, SemanticStatus};
use binlex::{Architecture, Config};

fn disassemble_graph(architecture: Architecture, bytes: &[u8]) -> Graph {
    let config = Config::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
        architecture,
        bytes,
        ranges,
        config.clone(),
    )
    .expect("disassembler");

    let mut graph = Graph::new(architecture, config);
    let mut entrypoints = BTreeSet::new();
    entrypoints.insert(0);
    disassembler
        .disassemble(entrypoints, &mut graph)
        .expect("graph should disassemble");
    graph
}

fn build_noncontiguous_function_graph() -> Graph {
    let config = Config::default();
    let mut graph = Graph::new(Architecture::I386, config.clone());

    let mut jump = Instruction::create(0x1000, Architecture::I386, config.clone());
    jump.bytes = vec![0xE9, 0xFB, 0x0F, 0x00, 0x00];
    jump.pattern = "e9fb0f0000".to_string();
    jump.is_jump = true;
    jump.to.insert(0x2000);
    jump.edges = jump.blocks().len();
    graph.insert_instruction(jump);

    let mut ret = Instruction::create(0x2000, Architecture::I386, config);
    ret.bytes = vec![0xC3];
    ret.pattern = "c3".to_string();
    ret.is_return = true;
    graph.insert_instruction(ret);

    assert!(graph.set_block(0x1000));
    assert!(graph.set_block(0x2000));
    assert!(graph.set_function(0x1000));

    graph
}

fn verify_all_entity_lifts(graph: &Graph) {
    let functions = graph.functions();
    assert!(
        !functions.is_empty(),
        "graph should recover at least one function"
    );

    for function in functions {
        let mut function_lifter = Lifter::new(Config::default());
        function_lifter
            .lift_function(&function)
            .expect("function should lift");
        function_lifter
            .verify()
            .expect("function module should verify");

        for block in function.blocks() {
            let mut block_lifter = Lifter::new(Config::default());
            block_lifter.lift_block(&block).expect("block should lift");
            block_lifter.verify().expect("block module should verify");

            for instruction in block.instructions() {
                let mut instruction_lifter = Lifter::new(Config::default());
                instruction_lifter
                    .lift_instruction(&instruction)
                    .expect("instruction should lift");
                instruction_lifter
                    .verify()
                    .expect("instruction module should verify");
            }
        }
    }
}

fn verify_instruction_and_block_lifts(graph: &Graph) {
    let instructions = graph.instructions();
    assert!(
        !instructions.is_empty(),
        "graph should recover at least one instruction"
    );

    for instruction in instructions {
        let mut instruction_lifter = Lifter::new(Config::default());
        instruction_lifter
            .lift_instruction(&instruction)
            .expect("instruction should lift");
        instruction_lifter
            .verify()
            .expect("instruction module should verify");
    }

    let blocks = graph.blocks();
    for block in blocks {
        let mut block_lifter = Lifter::new(Config::default());
        block_lifter.lift_block(&block).expect("block should lift");
        block_lifter.verify().expect("block module should verify");
    }
}

fn assert_all_instruction_semantics_status(graph: &Graph, status: SemanticStatus) {
    let instructions = graph.instructions();
    assert!(
        !instructions.is_empty(),
        "graph should recover at least one instruction"
    );

    for instruction in instructions {
        let semantics = instruction
            .semantics
            .as_ref()
            .expect("instruction should have semantics");
        assert_eq!(
            semantics.status, status,
            "unexpected semantics status for instruction at 0x{:x}",
            instruction.address
        );
    }
}

#[test]
fn llvm_lifter_renders_instruction_block_and_function_ir() {
    let graph = disassemble_graph(Architecture::I386, &[0x31, 0xc0, 0x40, 0xc3]); // xor eax,eax; inc eax; ret
    let instruction = graph.get_instruction(0).expect("instruction");
    let block = Block::new(0, &graph).expect("block");
    let function = Function::new(0, &graph).expect("function");

    let mut instruction_lifter = Lifter::new(Config::default());
    instruction_lifter
        .lift_instruction(&instruction)
        .expect("instruction should lift");
    instruction_lifter
        .verify()
        .expect("instruction module should verify");
    let instruction_ir = instruction_lifter.text();
    let instruction_bc = instruction_lifter.bitcode();
    assert!(instruction_ir.contains("define void @instruction_0()"));
    assert!(instruction_ir.contains("ret void"));
    assert_eq!(&instruction_bc[..4], b"BC\xc0\xde");
    let instruction_normalized = instruction_lifter
        .normalized()
        .expect("normalized instruction module");
    let instruction_normalized_text = instruction_normalized.text();
    assert_eq!(&instruction_normalized.bitcode()[..4], b"BC\xc0\xde");
    assert!(instruction_normalized_text.contains("define void @f0()"));

    let mut block_lifter = Lifter::new(Config::default());
    block_lifter.lift_block(&block).expect("block should lift");
    block_lifter.verify().expect("block module should verify");
    let block_ir = block_lifter.text();
    assert!(block_ir.contains("define void @block_0()"));

    let mut function_lifter = Lifter::new(Config::default());
    function_lifter
        .lift_function(&function)
        .expect("function should lift");
    function_lifter
        .verify()
        .expect("function module should verify");
    let function_ir = function_lifter.text();
    let function_bc = function_lifter.bitcode();
    assert!(function_ir.contains("define void @function_0()"));
    assert!(function_ir.contains("entry:"));
    assert!(function_ir.contains("block_0:"));
    assert!(function_ir.contains("source_filename = \"binlex\""));
    assert_eq!(&function_bc[..4], b"BC\xc0\xde");
    let function_normalized = function_lifter
        .normalized()
        .expect("normalized function module");
    let function_normalized_text = function_normalized.text();
    assert!(function_normalized_text.contains("define void @f0()"));
    assert!(function_normalized_text.contains("b0:"));
}

#[test]
fn llvm_lifter_handles_noncontiguous_functions() {
    let graph = build_noncontiguous_function_graph();
    let function = Function::new(0x1000, &graph).expect("function");

    assert_eq!(function.block_addresses(), vec![0x1000, 0x2000]);

    let mut lifter = Lifter::new(Config::default());
    lifter
        .lift_function(&function)
        .expect("non-contiguous function should lift");
    lifter
        .verify()
        .expect("non-contiguous function module should verify");

    let ir = lifter.text();
    assert!(ir.contains("define void @function_1000()"));
    assert!(ir.contains("entry:"));
    assert!(ir.contains("block_1000:"));
    assert!(ir.contains("block_2000:"));
    assert!(ir.contains("br label %block_1000"));
    assert!(ir.contains("br label %block_2000"));
    let normalized = lifter
        .normalized()
        .expect("normalized non-contiguous function");
    let normalized_text = normalized.text();
    assert!(normalized_text.contains("define void @f0()"));
    assert!(normalized_text.contains("b0:"));
    assert!(normalized_text.contains("b1:"));
}

#[test]
fn llvm_lifter_optimizers_chain_and_preserve_outputs() {
    let graph = disassemble_graph(Architecture::I386, &[0x31, 0xc0, 0x40, 0xc3]);
    let function = Function::new(0, &graph).expect("function");

    let mut lifter = Lifter::new(Config::default());
    lifter
        .lift_function(&function)
        .expect("function should lift before optimization");

    let populated = lifter
        .optimizers()
        .expect("optimizer namespace")
        .mem2reg()
        .expect("mem2reg")
        .instcombine()
        .expect("instcombine")
        .cfg()
        .expect("cfg")
        .gvn()
        .expect("gvn")
        .sroa()
        .expect("sroa")
        .dce()
        .expect("dce")
        .into_lifter();

    populated.verify().expect("optimized module should verify");

    let text = populated.text();
    assert!(text.contains("define void @function_0()"));
    assert_eq!(&populated.bitcode()[..4], b"BC\xc0\xde");

    let normalized = populated.normalized().expect("normalized optimized module");
    assert!(normalized.text().contains("define void @f0()"));
}

#[test]
fn llvm_json_output_respects_entity_config_flags() {
    let mut config = Config::default();
    let graph = {
        let mut ranges = BTreeMap::new();
        let bytes = [0x31, 0xc0, 0x40, 0xc3];
        ranges.insert(0, bytes.len() as u64);
        let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
            Architecture::I386,
            &bytes,
            ranges,
            config.clone(),
        )
        .expect("disassembler");
        let mut graph = Graph::new(Architecture::I386, config.clone());
        let mut entrypoints = BTreeSet::new();
        entrypoints.insert(0);
        disassembler
            .disassemble(entrypoints, &mut graph)
            .expect("graph should disassemble");
        graph
    };

    let instruction = graph.get_instruction(0).expect("instruction");
    let block = Block::new(0, &graph).expect("block");
    let function = Function::new(0, &graph).expect("function");

    let instruction_json =
        serde_json::to_value(instruction.process()).expect("serialize instruction");
    let block_json = serde_json::to_value(block.process()).expect("serialize block");
    let function_json = serde_json::to_value(function.process()).expect("serialize function");
    assert!(instruction_json.get("lifters").is_none());
    assert!(block_json.get("lifters").is_none());
    assert!(function_json.get("lifters").is_none());

    config.instructions.lifters.llvm.enabled = true;
    config.blocks.lifters.llvm.enabled = true;
    config.functions.lifters.llvm.enabled = true;

    let graph = {
        let mut ranges = BTreeMap::new();
        let bytes = [0x31, 0xc0, 0x40, 0xc3];
        ranges.insert(0, bytes.len() as u64);
        let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
            Architecture::I386,
            &bytes,
            ranges,
            config.clone(),
        )
        .expect("disassembler");
        let mut graph = Graph::new(Architecture::I386, config.clone());
        let mut entrypoints = BTreeSet::new();
        entrypoints.insert(0);
        disassembler
            .disassemble(entrypoints, &mut graph)
            .expect("graph should disassemble");
        graph
    };

    let instruction = graph.get_instruction(0).expect("instruction");
    let block = Block::new(0, &graph).expect("block");
    let function = Function::new(0, &graph).expect("function");

    let instruction_json =
        serde_json::to_value(instruction.process()).expect("serialize instruction");
    let block_json = serde_json::to_value(block.process()).expect("serialize block");
    let function_json = serde_json::to_value(function.process()).expect("serialize function");

    assert_eq!(
        instruction_json["lifters"]["llvm"]["text"]
            .as_str()
            .map(|s| s.contains("@instruction_0()")),
        Some(true)
    );
    assert_eq!(
        block_json["lifters"]["llvm"]["text"]
            .as_str()
            .map(|s| s.contains("@block_0()")),
        Some(true)
    );
    assert_eq!(
        function_json["lifters"]["llvm"]["text"]
            .as_str()
            .map(|s| s.contains("@function_0()")),
        Some(true)
    );
    assert_eq!(
        instruction_json
            .get("lifters")
            .and_then(|value| value.get("llvm"))
            .and_then(|value| value.get("normalized")),
        None
    );
    assert_eq!(
        block_json
            .get("lifters")
            .and_then(|value| value.get("llvm"))
            .and_then(|value| value.get("normalized")),
        None
    );
}

#[test]
fn llvm_lifter_handles_shift_and_rotate_family() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xD3, 0xE8, // shr eax, cl
            0xD1, 0xF8, // sar eax, 1
            0xD1, 0xC0, // rol eax, 1
            0xD1, 0xC8, // ror eax, 1
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_bit_test_family() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0xA3, 0xC8, // bt eax, ecx
            0x0F, 0xAB, 0xC8, // bts eax, ecx
            0x0F, 0xB3, 0xC8, // btr eax, ecx
            0x0F, 0xBB, 0xC8, // btc eax, ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_partial_width_register_updates() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x30, 0xC0, // xor al, al
            0x66, 0x83, 0xC0, 0x01, // add ax, 1
            0x0F, 0xB6, 0xC0, // movzx eax, al
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_memory_operand_widths() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x88, 0x08, // mov [eax], cl
            0x66, 0x89, 0x08, // mov [eax], cx
            0x89, 0x08, // mov [eax], ecx
            0x8A, 0x08, // mov cl, [eax]
            0x66, 0x8B, 0x08, // mov cx, [eax]
            0x8B, 0x08, // mov ecx, [eax]
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_conditional_control_flow() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x31, 0xC0, // xor eax, eax
            0x74, 0x01, // jz +1
            0x40, // inc eax
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_internal_call_and_return() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xE8, 0x01, 0x00, 0x00, 0x00, // call 6
            0xC3, // ret
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_carry_and_borrow_arithmetic() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x11, 0xC8, // adc eax, ecx
            0x19, 0xC8, // sbb eax, ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_extension_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0xBE, 0xC0, // movsx eax, al
            0x0F, 0xB7, 0xC8, // movzx ecx, ax
            0x99, // cdq
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_double_precision_shifts() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0xA4, 0xC8, 0x04, // shld eax, ecx, 4
            0x0F, 0xAC, 0xC8, 0x03, // shrd eax, ecx, 3
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_flag_to_value_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x31, 0xC0, // xor eax, eax
            0x39, 0xC8, // cmp eax, ecx
            0x0F, 0x94, 0xC0, // sete al
            0x0F, 0x44, 0xC1, // cmove eax, ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_stack_manipulation_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x50, // push eax
            0x59, // pop ecx
            0xC9, // leave
            0xC2, 0x04, 0x00, // ret 4
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_implicit_width_arithmetic() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xF7, 0xE1, // mul ecx
            0xF7, 0xE9, // imul ecx
            0xF7, 0xF1, // div ecx
            0xF7, 0xF9, // idiv ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_bit_scan_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0xBC, 0xC8, // bsf ecx, eax
            0x0F, 0xBD, 0xC8, // bsr ecx, eax
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_read_modify_write_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x91, // xchg eax, ecx
            0x0F, 0xC1, 0xC8, // xadd eax, ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_lea_and_test_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x8D, 0x44, 0x48, 0x10, // lea eax, [eax + ecx*2 + 0x10]
            0x85, 0xC8, // test eax, ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_amd64_zero_extension_behavior() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
            0x01, 0xC8, // add eax, ecx
            0x48, 0x0F, 0xB6, 0xC0, // movzx rax, al
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_amd64_rip_relative_addressing() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x48, 0x8D, 0x05, 0x08, 0x00, 0x00, 0x00, // lea rax, [rip + 8]
            0x48, 0x8B, 0x0D, 0x01, 0x00, 0x00, 0x00, // mov rcx, [rip + 1]
            0xC3, // ret
            0x90, // padding/data byte for RIP-relative load target
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_cmpxchg_register_and_memory_forms() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0xB1, 0xC1, // cmpxchg ecx, eax
            0x0F, 0xB1, 0x08, // cmpxchg [eax], ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_indirect_call_and_jump() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xFF, 0xD0, // call eax
            0xFF, 0xE0, // jmp eax
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_pushf_and_popf() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x9C, // pushf
            0x9D, // popf
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_string_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xA4, // movsb
            0xAA, // stosb
            0xA6, // cmpsb
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_loop_family_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xE3, 0x02, // jecxz +2
            0xE2, 0x00, // loop +0
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
    assert_all_instruction_semantics_status(&graph, SemanticStatus::Complete);
}

#[test]
fn llvm_lifter_handles_extended_counter_control_flow_completely() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0xE3, 0x04, // jrcxz +4
            0xE1, 0x02, // loope +2
            0xE0, 0x00, // loopne +0
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
    assert_all_instruction_semantics_status(&graph, SemanticStatus::Complete);
}

#[test]
fn llvm_lifter_handles_amd64_indirect_control_flow() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0xFF, 0xD0, // call rax
            0xFF, 0xE0, // jmp rax
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_amd64_qword_memory_operands() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x48, 0x89, 0x08, // mov [rax], rcx
            0x48, 0x8B, 0x08, // mov rcx, [rax]
            0x48, 0x39, 0x08, // cmp [rax], rcx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_additional_conditional_branches() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x31, 0xC0, // xor eax, eax
            0x75, 0x02, // jne +2
            0x73, 0x00, // jae +0
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_more_cmov_variants() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0x42, 0xC1, // cmovb eax, ecx
            0x0F, 0x45, 0xC1, // cmovne eax, ecx
            0x0F, 0x48, 0xC1, // cmovs eax, ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_more_setcc_variants() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0x92, 0xC0, // setb al
            0x0F, 0x95, 0xC1, // setne cl
            0x0F, 0x98, 0xC2, // sets dl
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_additional_convert_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x66, 0x98, // cbw/cwde-family operand-size form
            0x98, // cwde
            0x66, 0x99, // cwd
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_logical_and_unary_integer_ops() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x21, 0xC8, // and eax, ecx
            0x09, 0xC8, // or eax, ecx
            0x31, 0xC8, // xor eax, ecx
            0xF7, 0xD0, // not eax
            0xF7, 0xD8, // neg eax
            0x40, // inc eax
            0x48, // dec eax
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_additional_datatransfer_ops() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0xC8, // bswap eax
            0x87, 0x08, // xchg [eax], ecx
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_additional_string_ops() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xAC, // lodsb
            0xAE, // scasb
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_misc_frame_and_noop_ops() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x90, // nop
            0xC8, 0x08, 0x00, 0x00, // enter 8, 0
            0xC9, // leave
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_amd64_convert_family() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x48, 0x98, // cdqe
            0x48, 0x99, // cqo
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_supported_sse_vector_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x0F, 0x10, 0xC1, // movups xmm0, xmm1
            0x0F, 0x57, 0xC1, // xorps xmm0, xmm1
            0x0F, 0x54, 0xC1, // andps xmm0, xmm1
            0x66, 0x0F, 0x14, 0xC1, // unpcklpd xmm0, xmm1
            0x66, 0x0F, 0x73, 0xD8, 0x01, // psrldq xmm0, 1
            0x66, 0x0F, 0xC5, 0xC0, 0x01, // pextrw eax, xmm0, 1
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_packed_integer_vector_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x66, 0x0F, 0xEB, 0xC1, // por xmm0, xmm1
            0x66, 0x0F, 0xDB, 0xC1, // pand xmm0, xmm1
            0x66, 0x0F, 0xDF, 0xC1, // pandn xmm0, xmm1
            0x66, 0x0F, 0xEF, 0xC1, // pxor xmm0, xmm1
            0x66, 0x0F, 0xFC, 0xC1, // paddb xmm0, xmm1
            0x66, 0x0F, 0xFD, 0xC1, // paddw xmm0, xmm1
            0x66, 0x0F, 0xFE, 0xC1, // paddd xmm0, xmm1
            0x66, 0x0F, 0xF8, 0xC1, // psubb xmm0, xmm1
            0x66, 0x0F, 0xF9, 0xC1, // psubw xmm0, xmm1
            0x66, 0x0F, 0xFA, 0xC1, // psubd xmm0, xmm1
            0x66, 0x0F, 0x74, 0xC1, // pcmpeqb xmm0, xmm1
            0x66, 0x0F, 0x75, 0xC1, // pcmpeqw xmm0, xmm1
            0x66, 0x0F, 0x76, 0xC1, // pcmpeqd xmm0, xmm1
            0x66, 0x0F, 0x64, 0xC1, // pcmpgtb xmm0, xmm1
            0x66, 0x0F, 0x65, 0xC1, // pcmpgtw xmm0, xmm1
            0x66, 0x0F, 0x66, 0xC1, // pcmpgtd xmm0, xmm1
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_vector_unpack_extract_insert_and_masks() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x66, 0x0F, 0x60, 0xC1, // punpcklbw xmm0, xmm1
            0x66, 0x0F, 0x68, 0xC1, // punpckhbw xmm0, xmm1
            0x66, 0x0F, 0x61, 0xC1, // punpcklwd xmm0, xmm1
            0x66, 0x0F, 0x69, 0xC1, // punpckhwd xmm0, xmm1
            0x66, 0x0F, 0x62, 0xC1, // punpckldq xmm0, xmm1
            0x66, 0x0F, 0x6A, 0xC1, // punpckhdq xmm0, xmm1
            0x66, 0x0F, 0x6C, 0xC1, // punpcklqdq xmm0, xmm1
            0x66, 0x0F, 0x6D, 0xC1, // punpckhqdq xmm0, xmm1
            0x66, 0x0F, 0x15, 0xC1, // unpckhpd xmm0, xmm1
            0x0F, 0x14, 0xC1, // unpcklps xmm0, xmm1
            0x0F, 0x15, 0xC1, // unpckhps xmm0, xmm1
            0x66, 0x0F, 0x3A, 0x14, 0xC0, 0x01, // pextrb eax, xmm0, 1
            0x66, 0x0F, 0x3A, 0x16, 0xC0, 0x01, // pextrd eax, xmm0, 1
            0x66, 0x0F, 0x3A, 0x20, 0xC0, 0x01, // pinsrb xmm0, eax, 1
            0x66, 0x0F, 0x3A, 0x22, 0xC0, 0x01, // pinsrd xmm0, eax, 1
            0x0F, 0x50, 0xC0, // movmskps eax, xmm0
            0x66, 0x0F, 0x50, 0xC0, // movmskpd eax, xmm0
            0x66, 0x0F, 0xD7, 0xC0, // pmovmskb eax, xmm0
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_vector_widen_and_shuffle_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x66, 0x0F, 0x38, 0x20, 0xC1, // pmovsxbw xmm0, xmm1
            0x66, 0x0F, 0x38, 0x21, 0xC1, // pmovsxbd xmm0, xmm1
            0x66, 0x0F, 0x38, 0x22, 0xC1, // pmovsxbq xmm0, xmm1
            0x66, 0x0F, 0x38, 0x23, 0xC1, // pmovsxwd xmm0, xmm1
            0x66, 0x0F, 0x38, 0x24, 0xC1, // pmovsxwq xmm0, xmm1
            0x66, 0x0F, 0x38, 0x25, 0xC1, // pmovsxdq xmm0, xmm1
            0x66, 0x0F, 0x38, 0x30, 0xC1, // pmovzxbw xmm0, xmm1
            0x66, 0x0F, 0x38, 0x31, 0xC1, // pmovzxbd xmm0, xmm1
            0x66, 0x0F, 0x38, 0x32, 0xC1, // pmovzxbq xmm0, xmm1
            0x66, 0x0F, 0x38, 0x33, 0xC1, // pmovzxwd xmm0, xmm1
            0x66, 0x0F, 0x38, 0x34, 0xC1, // pmovzxwq xmm0, xmm1
            0x66, 0x0F, 0x38, 0x35, 0xC1, // pmovzxdq xmm0, xmm1
            0x66, 0x0F, 0x70, 0xC1, 0x1B, // pshufd xmm0, xmm1, 0x1b
            0xF3, 0x0F, 0x70, 0xC1, 0x1B, // pshufhw xmm0, xmm1, 0x1b
            0xF2, 0x0F, 0x70, 0xC1, 0x1B, // pshuflw xmm0, xmm1, 0x1b
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_partial_lane_move_vector_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x0F, 0x12, 0xC1, // movhlps xmm0, xmm1
            0x0F, 0x16, 0xC1, // movlhps xmm0, xmm1
            0x66, 0x0F, 0x16, 0x00, // movhpd xmm0, qword ptr [rax]
            0x66, 0x0F, 0x12, 0x00, // movlpd xmm0, qword ptr [rax]
            0x0F, 0x16, 0x00, // movhps xmm0, qword ptr [rax]
            0x0F, 0x12, 0x00, // movlps xmm0, qword ptr [rax]
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_vector_byte_shuffle_and_remaining_extract_insert_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x66, 0x0F, 0x38, 0x00, 0xC1, // pshufb xmm0, xmm1
            0x66, 0x48, 0x0F, 0x3A, 0x16, 0xC0, 0x01, // pextrq rax, xmm0, 1
            0x66, 0x48, 0x0F, 0x3A, 0x22, 0xC0, 0x01, // pinsrq xmm0, rax, 1
            0x66, 0x0F, 0x3A, 0x17, 0xC0, 0x01, // extractps eax, xmm0, 1
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_supported_scalar_fp_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0xF2, 0x0F, 0x10, 0xC1, // movsd xmm0, xmm1
            0xF2, 0x0F, 0x58, 0xC1, // addsd xmm0, xmm1
            0x66, 0x0F, 0x2F, 0xC1, // comisd xmm0, xmm1
            0xF2, 0x0F, 0x2C, 0xC0, // cvttsd2si eax, xmm0
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_basic_x87_ops() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xD9, 0xE8, // fld1
            0xD9, 0xEE, // fldz
            0xD9, 0xE1, // fabs
            0xD9, 0xE0, // fchs
            0xD9, 0xC9, // fxch st(1)
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_supported_system_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0xF3, 0x90, // pause
            0x0F, 0xAE, 0xE8, // lfence
            0xFA, // cli
            0xFB, // sti
            0x9C, // pushfq
            0x9D, // popfq
            0x0F, 0x31, // rdtsc
            0x0F, 0x01, 0xF9, // rdtscp
            0x0F, 0xC7, 0xF0, // rdrand eax
            0x0F, 0xC7, 0xF8, // rdseed eax
            0x0F, 0x05, // syscall
        ],
    );

    verify_instruction_and_block_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_trap_instructions() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xCC, // int3
            0xCD, 0x80, // int 0x80
            0x0F, 0x0B, // ud2
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_additional_supported_sse_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x66, 0x0F, 0x6F, 0xC1, // movdqa xmm0, xmm1
            0xF3, 0x0F, 0x6F, 0xC1, // movdqu xmm0, xmm1
            0xF2, 0x0F, 0x5D, 0xC1, // minsd xmm0, xmm1
            0x66, 0x0F, 0x2E, 0xC1, // ucomisd xmm0, xmm1
            0x66, 0x0F, 0xE6, 0xC1, // cvtdq2pd xmm0, xmm1
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_supported_mmx_datamove_ops() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0x6E, 0xC0, // movd mm0, eax
            0x0F, 0x6F, 0xC8, // movq mm1, mm0
            0x0F, 0x7E, 0xC8, // movd eax, mm1
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_additional_x87_intrinsics() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xD9, 0xE8, // fld1
            0xD8, 0xC1, // fadd st(0), st(1)
            0xD8, 0xC9, // fmul st(0), st(1)
            0xD8, 0xF1, // fdiv st(0), st(1)
            0xD8, 0xE1, // fsub st(0), st(1)
            0xD8, 0xD1, // fcom st(1)
            0xDD, 0xD9, // fstp st(1)
            0xDF, 0xE0, // fnstsw ax
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_additional_supported_system_intrinsics() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x9C, // pushfd
            0x6D, // insd
            0x6F, // outsd
            0xC3, // ret
        ],
    );

    verify_instruction_and_block_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_more_operand_forms_for_existing_ops() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x13, 0x08, // adc ecx, [eax]
            0x1B, 0x08, // sbb ecx, [eax]
            0x0F, 0xA3, 0x08, // bt [eax], ecx
            0x0F, 0xAB, 0x08, // bts [eax], ecx
            0x0F, 0xA5, 0x08, 0x04, // shld [eax], ecx, 4
            0x0F, 0xAD, 0x08, 0x03, // shrd [eax], ecx, 3
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_more_branch_condition_variants() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x72, 0x02, // jb +2
            0x76, 0x00, // jbe +0
            0x7F, 0x00, // jg +0
            0x7D, 0x00, // jge +0
            0x7A, 0x00, // jp +0
            0x70, 0x00, // jo +0
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_more_cmovcc_and_setcc_variants() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x0F, 0x46, 0xC1, // cmovbe eax, ecx
            0x0F, 0x4C, 0xC1, // cmovl eax, ecx
            0x0F, 0x4F, 0xC1, // cmovg eax, ecx
            0x0F, 0x96, 0xC0, // setbe al
            0x0F, 0x9C, 0xC1, // setl cl
            0x0F, 0x9F, 0xC2, // setg dl
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_more_x87_intrinsic_variants() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0xD9, 0xE8, // fld1
            0xD9, 0xEE, // fldz
            0xDA, 0xE9, // fucompp
            0xDE, 0xC1, // faddp st(1), st
            0xDE, 0xC9, // fmulp st(1), st
            0xD8, 0xF9, // fdivr st, st(1)
            0xD8, 0xE9, // fsubr st, st(1)
            0xDD, 0xD0, // fst st(0)
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_handles_more_memory_form_sse_ops() {
    let graph = disassemble_graph(
        Architecture::AMD64,
        &[
            0x0F, 0x28, 0x00, // movaps xmm0, [rax]
            0x0F, 0x10, 0x08, // movups xmm1, [rax]
            0x66, 0x0F, 0x6F, 0x10, // movdqa xmm2, [rax]
            0xF3, 0x0F, 0x6F, 0x18, // movdqu xmm3, [rax]
            0x66, 0x0F, 0xD6, 0x00, // movq [rax], xmm0
            0x66, 0x0F, 0x7E, 0x08, // movd [rax], xmm1
            0xC3, // ret
        ],
    );

    verify_all_entity_lifts(&graph);
}

#[test]
fn llvm_lifter_preserves_unsupported_instruction_fallback() {
    let graph = disassemble_graph(
        Architecture::I386,
        &[
            0x27, // daa
            0xC3, // ret
        ],
    );

    let instruction = graph.get_instruction(0).expect("instruction");
    let semantics = instruction
        .semantics
        .as_ref()
        .expect("unsupported instruction should still have fallback semantics");
    assert_eq!(semantics.status, binlex::semantics::SemanticStatus::Partial);
    assert!(
        semantics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == SemanticDiagnosticKind::UnsupportedInstruction)
    );

    let mut instruction_lifter = Lifter::new(Config::default());
    instruction_lifter
        .lift_instruction(&instruction)
        .expect("unsupported instruction should still lift");
    instruction_lifter
        .verify()
        .expect("unsupported instruction module should verify");
}

#[test]
fn llvm_supported_semantics_cases_are_complete() {
    let complete_cases: &[(&str, Architecture, &[u8])] = &[
        (
            "shift_rotate_i386",
            Architecture::I386,
            &[
                0xD3, 0xE8, // shr eax, cl
                0xD1, 0xF8, // sar eax, 1
                0xD1, 0xC0, // rol eax, 1
                0xD1, 0xC8, // ror eax, 1
                0xC3, // ret
            ],
        ),
        (
            "bit_test_i386",
            Architecture::I386,
            &[
                0x0F, 0xA3, 0xC8, // bt eax, ecx
                0x0F, 0xAB, 0xC8, // bts eax, ecx
                0x0F, 0xB3, 0xC8, // btr eax, ecx
                0x0F, 0xBB, 0xC8, // btc eax, ecx
                0xC3, // ret
            ],
        ),
        (
            "counter_control_i386",
            Architecture::I386,
            &[
                0xE3, 0x02, // jecxz +2
                0xE2, 0x00, // loop +0
                0xC3, // ret
            ],
        ),
        (
            "counter_control_amd64",
            Architecture::AMD64,
            &[
                0xE3, 0x04, // jrcxz +4
                0xE1, 0x02, // loope +2
                0xE0, 0x00, // loopne +0
                0xC3, // ret
            ],
        ),
        (
            "system_supported_amd64",
            Architecture::AMD64,
            &[
                0xF8, // clc
                0xF9, // stc
                0xF5, // cmc
                0xFC, // cld
                0xFD, // std
                0x9F, // lahf
                0x9E, // sahf
                0xF3, 0x90, // pause
                0x0F, 0xAE, 0xE8, // lfence
                0xFA, // cli
                0xFB, // sti
                0x9C, // pushfq
                0x9D, // popfq
                0x0F, 0x05, // syscall
            ],
        ),
        (
            "scalar_fp_amd64",
            Architecture::AMD64,
            &[
                0xF2, 0x0F, 0x10, 0xC1, // movsd xmm0, xmm1
                0xF2, 0x0F, 0x58, 0xC1, // addsd xmm0, xmm1
                0x66, 0x0F, 0x2F, 0xC1, // comisd xmm0, xmm1
                0xF2, 0x0F, 0x2C, 0xC0, // cvttsd2si eax, xmm0
                0xC3, // ret
            ],
        ),
        (
            "vector_amd64",
            Architecture::AMD64,
            &[
                0x0F, 0x10, 0xC1, // movups xmm0, xmm1
                0x0F, 0x57, 0xC1, // xorps xmm0, xmm1
                0x0F, 0x54, 0xC1, // andps xmm0, xmm1
                0x66, 0x0F, 0x14, 0xC1, // unpcklpd xmm0, xmm1
                0x66, 0x0F, 0x73, 0xD8, 0x01, // psrldq xmm0, 1
                0x66, 0x0F, 0xC5, 0xC0, 0x01, // pextrw eax, xmm0, 1
                0xC3, // ret
            ],
        ),
        (
            "x87_i386",
            Architecture::I386,
            &[
                0xD9, 0xE8, // fld1
                0xD8, 0xC1, // fadd st(0), st(1)
                0xD8, 0xC9, // fmul st(0), st(1)
                0xD8, 0xF1, // fdiv st(0), st(1)
                0xD8, 0xE1, // fsub st(0), st(1)
                0xDF, 0xE0, // fnstsw ax
                0xC3, // ret
            ],
        ),
        (
            "repeat_and_atomic_i386",
            Architecture::I386,
            &[
                0xF0, 0x0F, 0xC7, 0x08, // lock cmpxchg8b qword ptr [eax]
                0xF3, 0xAB, // rep stosd
                0xF3, 0x66, 0xAB, // rep stosw
                0xF3, 0xA4, // rep movsb
                0xC3, // ret
            ],
        ),
        (
            "bit_scan_bmi_amd64",
            Architecture::AMD64,
            &[
                0x0F, 0xBC, 0xC8, // bsf ecx, eax
                0x0F, 0xBD, 0xC8, // bsr ecx, eax
                0xF3, 0x0F, 0xBC, 0xC8, // tzcnt ecx, eax
                0xF3, 0x0F, 0xBD, 0xC8, // lzcnt ecx, eax
                0xC4, 0xE2, 0x78, 0xF3, 0xD9, // blsi eax, ecx
                0xC4, 0xE2, 0x78, 0xF3, 0xD1, // blsmsk eax, ecx
                0xC4, 0xE2, 0x78, 0xF3, 0xC9, // blsr eax, ecx
                0x8F, 0xEA, 0x78, 0x10, 0xC1, 0x21, 0x00, 0x00, 0x00, // bextr eax, ecx, 0x21
                0xC4, 0xE2, 0x70, 0xF2, 0xC2, // andn eax, ecx, edx
                0xC4, 0xE2, 0x68, 0xF5, 0xC1, // bzhi eax, ecx, edx
                0xC4, 0xE2, 0x63, 0xF6, 0xC1, // mulx eax, ebx, ecx
                0xC4, 0xE2, 0x71, 0xF7, 0xC3, // shlx eax, ebx, ecx
                0xC4, 0xE2, 0x73, 0xF7, 0xC3, // shrx eax, ebx, ecx
                0xC4, 0xE2, 0x72, 0xF7, 0xC3, // sarx eax, ebx, ecx
                0xC4, 0xE3, 0x7B, 0xF0, 0xC3, 0x07, // rorx eax, ebx, 7
                0xC4, 0xE2, 0x63, 0xF5, 0xC1, // pdep eax, ebx, ecx
                0xC4, 0xE2, 0x62, 0xF5, 0xC1, // pext eax, ebx, ecx
                0x0F, 0xC8, // bswap eax
                0xF3, 0x0F, 0xB8, 0xC3, // popcnt eax, ebx
                0x0F, 0x38, 0xF0, 0x00, // movbe eax, dword ptr [eax]
                0x0F, 0x38, 0xF1, 0x18, // movbe dword ptr [eax], ebx
                0x66, 0x0F, 0x38, 0xF6, 0xC3, // adcx eax, ebx
                0xF3, 0x0F, 0x38, 0xF6, 0xC3, // adox eax, ebx
                0xC3, // ret
            ],
        ),
    ];

    for (name, architecture, bytes) in complete_cases {
        let graph = disassemble_graph(*architecture, bytes);
        verify_instruction_and_block_lifts(&graph);
        for instruction in graph.instructions() {
            let semantics = instruction.semantics.as_ref().unwrap_or_else(|| {
                panic!(
                    "{name}: instruction 0x{:x} missing semantics",
                    instruction.address
                )
            });
            assert_eq!(
                semantics.status,
                SemanticStatus::Complete,
                "{name}: instruction 0x{:x} is not complete",
                instruction.address
            );
        }
    }
}

#[test]
fn llvm_accuracy_gated_semantics_cases_remain_partial() {
    let partial_cases: &[(&str, Architecture, &[u8], &[u64])] = &[];

    for (name, architecture, bytes, partial_addresses) in partial_cases {
        let graph = disassemble_graph(*architecture, bytes);
        verify_instruction_and_block_lifts(&graph);
        let expected = partial_addresses.iter().copied().collect::<BTreeSet<_>>();
        for instruction in graph.instructions() {
            let semantics = instruction.semantics.as_ref().unwrap_or_else(|| {
                panic!(
                    "{name}: instruction 0x{:x} missing semantics",
                    instruction.address
                )
            });
            if expected.contains(&instruction.address) {
                assert_eq!(
                    semantics.status,
                    SemanticStatus::Partial,
                    "{name}: instruction 0x{:x} should remain partial",
                    instruction.address
                );
                assert!(
                    !semantics.diagnostics.is_empty(),
                    "{name}: instruction 0x{:x} should carry diagnostics",
                    instruction.address
                );
            } else {
                assert_eq!(
                    semantics.status,
                    SemanticStatus::Complete,
                    "{name}: instruction 0x{:x} should stay complete",
                    instruction.address
                );
            }
        }
    }
}
