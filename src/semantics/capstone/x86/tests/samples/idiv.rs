use super::super::support::{I386Fixture, assert_i386_instruction_roundtrip_match_unicorn};
use super::{I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases};
use crate::Architecture;

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "idiv",
    instruction: "idiv ecx",
    architecture: Architecture::I386,
    bytes: &[0xf7, 0xf9],
    expected_status: None,
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0xffff_ff9c),
            (I386Register::Ecx, 5),
            (I386Register::Edx, 0xffff_ffff),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn idiv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn idiv_roundtrip_i386_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "idiv ecx",
        &[0xf7, 0xf9],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0xffff_ff9c),
                (I386Register::Ecx, 5),
                (I386Register::Edx, 0xffff_ffff),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
