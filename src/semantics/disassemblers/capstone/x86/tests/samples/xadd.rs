use super::super::support::{I386Fixture, assert_i386_instruction_roundtrip_match_unicorn};
use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "xadd",
    instruction: "xadd eax, ebx",
    architecture: Architecture::I386,
    bytes: &[0x0f, 0xc1, 0xd8],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0x7fff_ffff),
            (I386Register::Ebx, 0x0000_0001),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn xadd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn xadd_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn xadd_roundtrip_i386_register_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xadd eax, ebx",
        &[0x0f, 0xc1, 0xd8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x7fff_ffff),
                (I386Register::Ebx, 0x0000_0001),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn xadd_roundtrip_i386_memory_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "xadd dword ptr [ebx+4], eax",
        &[0x0f, 0xc1, 0x43, 0x04],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x7fff_ffff),
                (I386Register::Ebx, 0x3000),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![(0x3004, vec![0x01, 0x00, 0x00, 0x00])],
        },
    );
}
