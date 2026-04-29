use super::super::support::{
    I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn,
    assert_i386_instruction_roundtrip_match_unicorn,
};
use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "bsf",
    instruction: "bsf ecx, eax",
    architecture: Architecture::I386,
    bytes: &[0x0f, 0xbc, 0xc8],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Eax, 0x0000_0010), (I386Register::Ecx, 0)],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn bsf_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bsf_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn bsf_roundtrip_i386_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bsf ecx, eax",
        &[0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0x1000_0040),
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

#[test]
fn bsf_roundtrip_i386_zero_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "bsf ecx, eax",
        &[0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
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

#[test]
fn bsf_roundtrip_amd64_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bsf rcx, rax",
        &[0x48, 0x0f, 0xbc, 0xc8],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0x1000_0000_0000_0040),
                (I386Register::Rbx, 0x8877_6655_4433_2211),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
