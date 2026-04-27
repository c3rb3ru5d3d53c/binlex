use super::super::support::{I386Fixture, assert_i386_instruction_roundtrip_match_unicorn};
use super::{I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases};
use crate::Architecture;

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "btr",
    instruction: "btr eax, 1",
    architecture: Architecture::I386,
    bytes: &[0x0f, 0xba, 0xf0, 0x01],
    expected_status: None,
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Eax, 0b10)],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn btr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn btr_roundtrip_i386_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "btr eax, 3",
        &[0x0f, 0xba, 0xf0, 0x03],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x0000_0008),
                (I386Register::Ebx, 0x5566_7788),
                (I386Register::Ecx, 0x99aa_bbcc),
                (I386Register::Edx, 0xddee_ff00),
                (I386Register::Esi, 0x1234_5678),
                (I386Register::Edi, 0x8765_4321),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
