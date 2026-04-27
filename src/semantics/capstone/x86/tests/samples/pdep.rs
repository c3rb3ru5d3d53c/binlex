use super::super::support::{I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn};
use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "pdep",
    instruction: "pdep eax, ebx, ecx",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x63, 0xf5, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0),
            (I386Register::Ebx, 0b1011),
            (I386Register::Ecx, 0b0011_0101),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn pdep_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn pdep_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn pdep_roundtrip_amd64_eax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pdep eax, ebx, ecx",
        &[0xc4, 0xe2, 0x63, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ebx, 0b1011),
                (I386Register::Ecx, 0b0011_0101),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}

#[test]
fn pdep_roundtrip_amd64_rax_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "pdep rax, rbx, rcx",
        &[0xc4, 0xe2, 0xe3, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Rax, 0),
                (I386Register::Rbx, 0x0000_0000_0000_000b),
                (I386Register::Rcx, 0x8000_0000_0000_0035),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
