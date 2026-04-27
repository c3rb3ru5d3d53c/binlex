use super::super::support::{I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn};
use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "bzhi",
    instruction: "bzhi eax, ecx, edx",
    architecture: Architecture::AMD64,
    bytes: &[0xc4, 0xe2, 0x68, 0xf5, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 0),
            (I386Register::Ecx, 0xffff_ffff),
            (I386Register::Edx, 5),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn bzhi_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bzhi_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn bzhi_roundtrip_amd64_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bzhi eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf5, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0xffff_ffff),
                (I386Register::Edx, 5),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
