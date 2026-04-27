use super::super::support::{I386Fixture, assert_amd64_instruction_roundtrip_match_unicorn};
use super::{I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "bextr",
        instruction: "bextr eax, ecx, 0x21",
        architecture: Architecture::AMD64,
        bytes: &[0x8f, 0xea, 0x78, 0x10, 0xc1, 0x21, 0x00, 0x00, 0x00],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "bextr",
        instruction: "bextr eax, ecx, edx",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "bextr",
        instruction: "bextr eax, ecx, edx",
        architecture: Architecture::AMD64,
        bytes: &[0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1110_1100),
                (I386Register::Edx, 0x0000_0201),
            ],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
];

#[test]
fn bextr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bextr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}

#[test]
fn bextr_roundtrip_amd64_matches_unicorn() {
    assert_amd64_instruction_roundtrip_match_unicorn(
        "bextr eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1110_1100),
                (I386Register::Edx, 0x0000_0201),
                (I386Register::Rbp, 0x2ff0),
                (I386Register::Rsp, 0x2ff0),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
