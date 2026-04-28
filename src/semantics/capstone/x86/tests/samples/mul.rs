use super::super::support::{I386Fixture, assert_i386_instruction_roundtrip_match_unicorn};
use super::{I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "mul",
    instruction: "mul ecx",
    architecture: Architecture::I386,
    bytes: &[0xf7, 0xe1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Eax, 7),
            (I386Register::Ecx, 9),
            (I386Register::Edx, 0),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn mul_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn mul_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn mul_roundtrip_i386_matches_unicorn() {
    assert_i386_instruction_roundtrip_match_unicorn(
        "mul ecx",
        &[0xf7, 0xe1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 7),
                (I386Register::Ecx, 9),
                (I386Register::Edx, 0),
                (I386Register::Ebp, 0x2ff0),
                (I386Register::Esp, 0x2ff0),
            ],
            eflags: 0x202,
            memory: vec![],
        },
    );
}
