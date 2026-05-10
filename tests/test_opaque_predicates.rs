use std::collections::{BTreeMap, BTreeSet};

use binlex::assemblers::{Assembler, AssemblerBackend};
use binlex::controlflow::Graph;
use binlex::disassemblers::capstone::Disassembler;
use binlex::{Architecture, Configuration};

fn assemble(architecture: Architecture, assembly: &str) -> Vec<u8> {
    let assembler = Assembler::new(architecture, Configuration::default(), AssemblerBackend::Default)
        .expect("assembler");
    assembler.assemble(0, assembly).expect("assemble")
}

fn disassemble_function(architecture: Architecture, bytes: &[u8]) -> Graph {
    let config = Configuration::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);
    let disassembler =
        Disassembler::from_bytes(architecture, bytes, ranges, config.clone()).expect("disassembler");
    let mut graph = Graph::new(architecture, config);
    disassembler
        .disassemble(BTreeSet::from([0]), &mut graph)
        .expect("disassemble");
    graph
}

fn assert_fallthrough_opaque_predicate(graph: &Graph) {
    let block = graph.get_block(0).expect("entry block");
    assert!(!block.conditional(), "resolved opaque predicate should not stay conditional");
    assert!(block.opaque_predicate(), "entry block should be marked opaque predicate");
    assert!(block.branches().is_empty(), "always-false opaque predicate should drop taken edge");
    assert_eq!(block.successors().len(), 1, "only one CFG successor should survive");

    let terminator = block.terminator.clone();
    assert!(terminator.is_jump, "terminator should remain a jump instruction");
    assert!(!terminator.is_conditional, "terminator should be normalized to non-conditional");
    assert!(
        terminator.is_opaque_predicate,
        "terminator should be marked as an opaque predicate"
    );
    assert!(
        terminator.fallthrough().is_some(),
        "resolved false branch should retain only fallthrough"
    );
}

#[test]
fn i386_single_block_opaque_predicate_resolves_cfg() {
    let bytes = assemble(
        Architecture::I386,
        "
        mov eax, 1
        sub eax, 1
        cmp eax, 0
        jne target
        ret
target:
        ret
        ",
    );
    let graph = disassemble_function(Architecture::I386, &bytes);
    assert_fallthrough_opaque_predicate(&graph);
}

#[test]
fn amd64_single_block_opaque_predicate_resolves_cfg() {
    let bytes = assemble(
        Architecture::AMD64,
        "
        mov eax, 1
        sub eax, 1
        cmp eax, 0
        jne target
        ret
target:
        ret
        ",
    );
    let graph = disassemble_function(Architecture::AMD64, &bytes);
    assert_fallthrough_opaque_predicate(&graph);
}

#[test]
fn arm64_single_block_opaque_predicate_resolves_cfg() {
    let bytes = assemble(
        Architecture::ARM64,
        "
        mov w0, #1
        sub w0, w0, #1
        cbnz w0, target
        ret
target:
        ret
        ",
    );
    let graph = disassemble_function(Architecture::ARM64, &bytes);
    assert_fallthrough_opaque_predicate(&graph);
}
