use std::collections::BTreeMap;

use binlex::controlflow::{Graph, Instruction};
use binlex::semantics::{
    InstructionSemantics, SemanticDiagnostic, SemanticDiagnosticKind, SemanticStatus,
    SemanticTerminator,
};
use binlex::{Architecture, Config};

fn disassemble_single(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
) -> binlex::controlflow::Instruction {
    let config = Config::default();
    let mut ranges = BTreeMap::new();
    ranges.insert(0, bytes.len() as u64);

    let mut graph = Graph::new(architecture, config.clone());

    match architecture {
        Architecture::CIL => {
            let disassembler = binlex::disassemblers::cil::Disassembler::new(
                architecture,
                bytes,
                BTreeMap::new(),
                ranges,
                config,
            )
            .expect("disassembler");
            disassembler
                .disassemble_instruction(0, &mut graph)
                .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
        }
        _ => {
            let disassembler = binlex::disassemblers::capstone::Disassembler::from_bytes(
                architecture,
                bytes,
                ranges,
                config,
            )
            .expect("disassembler");
            disassembler
                .disassemble_instruction(0, &mut graph)
                .unwrap_or_else(|error| panic!("{name}: instruction should disassemble: {error}"));
        }
    }

    graph.get_instruction(0).expect("instruction should exist")
}

fn assert_complete_semantics(name: &str, architecture: Architecture, bytes: &[u8]) {
    let instruction = disassemble_single(name, architecture, bytes);
    let semantics = instruction
        .semantics
        .as_ref()
        .unwrap_or_else(|| panic!("{name}: missing semantics"));

    assert_eq!(
        semantics.status,
        SemanticStatus::Complete,
        "{name}: expected complete semantics, got {:?} with diagnostics {:?}",
        semantics.status,
        semantics
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        semantics.diagnostics.is_empty(),
        "{name}: expected no diagnostics, got {:?}",
        semantics
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );
}

fn partial_semantics(message: &str) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: SemanticTerminator::FallThrough,
        diagnostics: vec![SemanticDiagnostic {
            kind: SemanticDiagnosticKind::ArchSpecific {
                name: "test.partial".to_string(),
            },
            message: message.to_string(),
        }],
    }
}

fn complete_semantics() -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    }
}

#[test]
fn integer_semantics_regressions_stay_complete() {
    let cases = [
        ("add eax, ebx", Architecture::I386, vec![0x01, 0xd8]),
        ("adc eax, ebx", Architecture::I386, vec![0x11, 0xd8]),
        (
            "btc eax, 1",
            Architecture::I386,
            vec![0x0f, 0xba, 0xf8, 0x01],
        ),
        ("xadd eax, ebx", Architecture::I386, vec![0x0f, 0xc1, 0xd8]),
        (
            "lock xadd dword ptr [eax], ebx",
            Architecture::I386,
            vec![0xf0, 0x0f, 0xc1, 0x18],
        ),
        (
            "cmpxchg eax, ebx",
            Architecture::I386,
            vec![0x0f, 0xb1, 0xd8],
        ),
        (
            "lock cmpxchg8b qword ptr [eax]",
            Architecture::I386,
            vec![0xf0, 0x0f, 0xc7, 0x08],
        ),
        ("shl eax, cl", Architecture::I386, vec![0xd3, 0xe0]),
        (
            "shld eax, edx, cl",
            Architecture::I386,
            vec![0x0f, 0xa5, 0xd0],
        ),
        (
            "shrd eax, edx, cl",
            Architecture::I386,
            vec![0x0f, 0xad, 0xd0],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn stack_and_string_semantics_regressions_stay_complete() {
    let cases = [
        (
            "enter 0x10, 0x00",
            Architecture::I386,
            vec![0xc8, 0x10, 0x00, 0x00],
        ),
        (
            "enter 0x10, 0x01",
            Architecture::I386,
            vec![0xc8, 0x10, 0x00, 0x01],
        ),
        ("stosb", Architecture::I386, vec![0xaa]),
        ("stosw", Architecture::I386, vec![0x66, 0xab]),
        ("stosd", Architecture::I386, vec![0xab]),
        ("rep stosd", Architecture::I386, vec![0xf3, 0xab]),
        ("rep stosw", Architecture::I386, vec![0xf3, 0x66, 0xab]),
        ("movsw", Architecture::I386, vec![0x66, 0xa5]),
        ("rep movsb", Architecture::I386, vec![0xf3, 0xa4]),
        ("scasd", Architecture::I386, vec![0xaf]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn vector_and_scalar_fp_semantics_regressions_stay_complete() {
    let cases = [
        (
            "movsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x10, 0xc1],
        ),
        (
            "addsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x58, 0xc1],
        ),
        (
            "subsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x5c, 0xc1],
        ),
        (
            "mulsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x59, 0xc1],
        ),
        (
            "divsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x5e, 0xc1],
        ),
        (
            "minsd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x5d, 0xc1],
        ),
        (
            "andps xmm0, xmm1",
            Architecture::AMD64,
            vec![0x0f, 0x54, 0xc1],
        ),
        (
            "unpcklpd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x14, 0xc1],
        ),
        (
            "pextrw eax, xmm0, 1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0xc5, 0xc0, 0x01],
        ),
        (
            "comisd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x2f, 0xc1],
        ),
        (
            "ucomisd xmm0, xmm1",
            Architecture::AMD64,
            vec![0x66, 0x0f, 0x2e, 0xc1],
        ),
        (
            "cvttsd2si eax, xmm0",
            Architecture::AMD64,
            vec![0xf2, 0x0f, 0x2c, 0xc0],
        ),
        (
            "cvtdq2pd xmm0, xmm1",
            Architecture::AMD64,
            vec![0xf3, 0x0f, 0xe6, 0xc1],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn system_and_io_semantics_regressions_stay_complete() {
    let cases = [
        ("sti", Architecture::AMD64, vec![0xfb]),
        ("pushfq", Architecture::AMD64, vec![0x9c]),
        ("popfq", Architecture::AMD64, vec![0x9d]),
        ("pushfd", Architecture::I386, vec![0x9c]),
        ("pause", Architecture::I386, vec![0xf3, 0x90]),
        ("insd", Architecture::AMD64, vec![0x6d]),
        ("outsd", Architecture::AMD64, vec![0x6f]),
        (
            "fimul word ptr [rax]",
            Architecture::AMD64,
            vec![0xde, 0x08],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn x87_semantics_regressions_stay_complete() {
    let cases = [
        ("fld dword ptr [eax]", Architecture::I386, vec![0xd9, 0x00]),
        ("fld1", Architecture::I386, vec![0xd9, 0xe8]),
        ("fldz", Architecture::I386, vec![0xd9, 0xee]),
        ("fild dword ptr [eax]", Architecture::I386, vec![0xdb, 0x00]),
        ("fst dword ptr [eax]", Architecture::I386, vec![0xd9, 0x10]),
        ("fstp dword ptr [eax]", Architecture::I386, vec![0xd9, 0x18]),
        ("fadd dword ptr [eax]", Architecture::I386, vec![0xd8, 0x00]),
        ("faddp st(1)", Architecture::I386, vec![0xde, 0xc1]),
        ("fmul dword ptr [eax]", Architecture::I386, vec![0xd8, 0x08]),
        ("fmulp st(1)", Architecture::I386, vec![0xde, 0xc9]),
        (
            "fsubr dword ptr [eax]",
            Architecture::I386,
            vec![0xd8, 0x28],
        ),
        ("fsub dword ptr [eax]", Architecture::I386, vec![0xd8, 0x20]),
        ("fsubp st(1)", Architecture::I386, vec![0xde, 0xe9]),
        ("fsubrp st(1)", Architecture::I386, vec![0xde, 0xe1]),
        ("fdiv dword ptr [eax]", Architecture::I386, vec![0xd8, 0x30]),
        (
            "fdivr dword ptr [eax]",
            Architecture::I386,
            vec![0xd8, 0x38],
        ),
        ("fdivrp st(1)", Architecture::I386, vec![0xde, 0xf1]),
        (
            "fcomp dword ptr [eax]",
            Architecture::I386,
            vec![0xd8, 0x18],
        ),
        ("fcom dword ptr [eax]", Architecture::I386, vec![0xd8, 0x10]),
        ("fcompp", Architecture::I386, vec![0xde, 0xd9]),
        ("fucom st(1)", Architecture::I386, vec![0xdd, 0xe1]),
        ("fucomp st(1)", Architecture::I386, vec![0xdd, 0xe9]),
        ("fnstsw ax", Architecture::I386, vec![0xdf, 0xe0]),
        ("fabs", Architecture::I386, vec![0xd9, 0xe1]),
        ("fchs", Architecture::I386, vec![0xd9, 0xe0]),
        ("fxch st(1)", Architecture::I386, vec![0xd9, 0xc9]),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn cil_simple_semantics_regressions_stay_complete() {
    let cases = [
        ("ldc.i4.0", Architecture::CIL, vec![0x16]),
        ("ldc.i4.s", Architecture::CIL, vec![0x1f, 0x7f]),
        (
            "ldc.i8",
            Architecture::CIL,
            vec![0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
        (
            "ldc.r4",
            Architecture::CIL,
            vec![0x22, 0x00, 0x00, 0x80, 0x3f],
        ),
        (
            "ldc.r8",
            Architecture::CIL,
            vec![0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f],
        ),
        ("ldnull", Architecture::CIL, vec![0x14]),
        ("dup", Architecture::CIL, vec![0x25]),
        ("pop", Architecture::CIL, vec![0x26]),
        ("add", Architecture::CIL, vec![0x58]),
        ("sub", Architecture::CIL, vec![0x59]),
        ("mul", Architecture::CIL, vec![0x5a]),
        ("div", Architecture::CIL, vec![0x5b]),
        ("and", Architecture::CIL, vec![0x5f]),
        ("or", Architecture::CIL, vec![0x60]),
        ("xor", Architecture::CIL, vec![0x61]),
        ("shl", Architecture::CIL, vec![0x62]),
        ("shr.un", Architecture::CIL, vec![0x64]),
        ("neg", Architecture::CIL, vec![0x65]),
        ("not", Architecture::CIL, vec![0x66]),
        ("ceq", Architecture::CIL, vec![0xfe, 0x01]),
        ("cgt", Architecture::CIL, vec![0xfe, 0x02]),
        ("clt.un", Architecture::CIL, vec![0xfe, 0x05]),
        ("conv.i4", Architecture::CIL, vec![0x69]),
        ("conv.r8", Architecture::CIL, vec![0x6c]),
        ("ldarg.0", Architecture::CIL, vec![0x02]),
        ("ldarg.s", Architecture::CIL, vec![0x0e, 0x01]),
        ("ldarga.s", Architecture::CIL, vec![0x0f, 0x01]),
        ("ldloc.1", Architecture::CIL, vec![0x07]),
        ("ldloc.s", Architecture::CIL, vec![0x11, 0x01]),
        ("ldloca.s", Architecture::CIL, vec![0x12, 0x01]),
        ("stloc.0", Architecture::CIL, vec![0x0a]),
        ("stloc.1", Architecture::CIL, vec![0x0b]),
        ("stloc.s", Architecture::CIL, vec![0x13, 0x01]),
        ("starg.s", Architecture::CIL, vec![0x10, 0x01]),
        (
            "ldstr",
            Architecture::CIL,
            vec![0x72, 0x01, 0x00, 0x00, 0x70],
        ),
        (
            "ldtoken",
            Architecture::CIL,
            vec![0xd0, 0x01, 0x00, 0x00, 0x01],
        ),
        (
            "ldfld",
            Architecture::CIL,
            vec![0x7b, 0x01, 0x00, 0x00, 0x04],
        ),
        (
            "ldflda",
            Architecture::CIL,
            vec![0x7c, 0x01, 0x00, 0x00, 0x04],
        ),
        (
            "ldsfld",
            Architecture::CIL,
            vec![0x7e, 0x01, 0x00, 0x00, 0x04],
        ),
        (
            "ldsflda",
            Architecture::CIL,
            vec![0x7f, 0x01, 0x00, 0x00, 0x04],
        ),
        (
            "stfld",
            Architecture::CIL,
            vec![0x7d, 0x01, 0x00, 0x00, 0x04],
        ),
        (
            "stsfld",
            Architecture::CIL,
            vec![0x80, 0x01, 0x00, 0x00, 0x04],
        ),
        ("ldelem.i4", Architecture::CIL, vec![0x94]),
        ("stelem.i4", Architecture::CIL, vec![0x9e]),
        (
            "ldelema",
            Architecture::CIL,
            vec![0x8f, 0x01, 0x00, 0x00, 0x01],
        ),
        ("ldelem.ref", Architecture::CIL, vec![0x9a]),
        ("stelem.ref", Architecture::CIL, vec![0xa2]),
        ("ldind.i4", Architecture::CIL, vec![0x4a]),
        ("stind.i4", Architecture::CIL, vec![0x54]),
        (
            "ldobj",
            Architecture::CIL,
            vec![0x71, 0x01, 0x00, 0x00, 0x01],
        ),
        (
            "stobj",
            Architecture::CIL,
            vec![0x81, 0x01, 0x00, 0x00, 0x01],
        ),
        (
            "newarr",
            Architecture::CIL,
            vec![0x8d, 0x01, 0x00, 0x00, 0x01],
        ),
        (
            "newobj",
            Architecture::CIL,
            vec![0x73, 0x01, 0x00, 0x00, 0x0a],
        ),
        ("box", Architecture::CIL, vec![0x8c, 0x01, 0x00, 0x00, 0x01]),
        (
            "unbox.any",
            Architecture::CIL,
            vec![0xa5, 0x01, 0x00, 0x00, 0x01],
        ),
        (
            "castclass",
            Architecture::CIL,
            vec![0x74, 0x01, 0x00, 0x00, 0x01],
        ),
        (
            "isinst",
            Architecture::CIL,
            vec![0x75, 0x01, 0x00, 0x00, 0x01],
        ),
        (
            "sizeof",
            Architecture::CIL,
            vec![0xfe, 0x1c, 0x01, 0x00, 0x00, 0x01],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn cil_controlflow_semantics_regressions_stay_complete() {
    let cases = [
        (
            "call",
            Architecture::CIL,
            vec![0x28, 0x01, 0x00, 0x00, 0x0a],
        ),
        ("brtrue.s", Architecture::CIL, vec![0x2d, 0x00]),
        ("brfalse.s", Architecture::CIL, vec![0x2c, 0x00]),
        ("beq.s", Architecture::CIL, vec![0x2e, 0x00]),
        ("bne.un.s", Architecture::CIL, vec![0x33, 0x00]),
        ("bgt.s", Architecture::CIL, vec![0x30, 0x00]),
        ("ble.un.s", Architecture::CIL, vec![0x36, 0x00]),
        ("br.s", Architecture::CIL, vec![0x2b, 0x00]),
        ("leave.s", Architecture::CIL, vec![0xde, 0x00]),
        ("jmp", Architecture::CIL, vec![0x27, 0x01, 0x00, 0x00, 0x0a]),
        (
            "switch",
            Architecture::CIL,
            vec![0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
    ];

    for (name, architecture, bytes) in cases {
        assert_complete_semantics(name, architecture, &bytes);
    }
}

#[test]
fn instruction_semantics_survive_snapshot_roundtrip() {
    let instruction = disassemble_single("adc eax, ebx", Architecture::I386, &[0x11, 0xd8]);
    let original = instruction
        .semantics
        .clone()
        .expect("instruction should carry semantics");

    let config = Config::default();
    let mut graph = Graph::new(Architecture::I386, config.clone());
    graph.insert_instruction(instruction);

    let restored =
        Graph::from_snapshot(graph.snapshot(), config).expect("snapshot roundtrip should restore");
    let restored_instruction = restored
        .get_instruction(0)
        .expect("restored instruction should exist");
    let restored_semantics = restored_instruction
        .semantics
        .expect("restored instruction should keep semantics");

    assert_eq!(restored_semantics.status, original.status);
    assert_eq!(
        restored_semantics.terminator.kind(),
        original.terminator.kind()
    );
    assert_eq!(restored_semantics.effects.len(), original.effects.len());
    assert_eq!(
        restored_semantics.diagnostics.len(),
        original.diagnostics.len()
    );
}

#[test]
fn graph_merge_prefers_more_complete_instruction_semantics() {
    let config = Config::default();
    let mut base = Graph::new(Architecture::AMD64, config.clone());
    let mut incoming = Graph::new(Architecture::AMD64, config.clone());

    let mut partial_instruction = Instruction::create(0x1000, Architecture::AMD64, config.clone());
    partial_instruction.bytes = vec![0x90];
    partial_instruction.pattern = "90".to_string();
    partial_instruction.semantics = Some(partial_semantics("partial semantics"));
    base.insert_instruction(partial_instruction);

    let mut complete_instruction = Instruction::create(0x1000, Architecture::AMD64, config);
    complete_instruction.bytes = vec![0x90];
    complete_instruction.pattern = "90".to_string();
    complete_instruction.semantics = Some(complete_semantics());
    incoming.insert_instruction(complete_instruction);

    base.merge(&mut incoming);

    let merged = base
        .get_instruction(0x1000)
        .expect("merged instruction should exist")
        .semantics
        .expect("merged instruction should keep semantics");

    assert_eq!(merged.status, SemanticStatus::Complete);
    assert!(merged.diagnostics.is_empty());
}

#[test]
fn graph_update_instruction_preserves_attached_semantics() {
    let config = Config::default();
    let mut graph = Graph::new(Architecture::I386, config.clone());
    let mut instruction =
        disassemble_single("btc eax, 1", Architecture::I386, &[0x0f, 0xba, 0xf8, 0x01]);
    let original = instruction
        .semantics
        .clone()
        .expect("instruction should have semantics");

    graph.insert_instruction(instruction.clone());
    instruction.pattern = "0f baf8 01".replace(' ', "");
    graph.update_instruction(instruction);

    let updated = graph
        .get_instruction(0)
        .expect("updated instruction should exist")
        .semantics
        .expect("updated instruction should retain semantics");

    assert_eq!(updated.status, original.status);
    assert_eq!(updated.effects.len(), original.effects.len());
    assert_eq!(updated.terminator.kind(), original.terminator.kind());
}
