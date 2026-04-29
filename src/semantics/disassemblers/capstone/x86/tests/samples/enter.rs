use super::{I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses};
use crate::{Architecture, semantics::SemanticStatus};

pub(crate) const SAMPLES: &[X86Sample] = &[
    X86Sample {
        mnemonic: "enter",
        instruction: "enter 0x10, 0x00",
        architecture: Architecture::I386,
        bytes: &[0xc8, 0x10, 0x00, 0x00],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "enter",
        instruction: "enter 0x10, 0x01",
        architecture: Architecture::I386,
        bytes: &[0xc8, 0x10, 0x00, 0x01],
        expected_status: Some(SemanticStatus::Complete),
        semantics_fixture: None,
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "enter",
        instruction: "enter 0x10, 0x00",
        architecture: Architecture::I386,
        bytes: &[0xc8, 0x10, 0x00, 0x00],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
    X86Sample {
        mnemonic: "enter",
        instruction: "enter 0x10, 0x01",
        architecture: Architecture::I386,
        bytes: &[0xc8, 0x10, 0x00, 0x01],
        expected_status: None,
        semantics_fixture: Some(X86FixtureSpec {
            registers: &[(I386Register::Esp, 0x2900), (I386Register::Ebp, 0x2800)],
            eflags: 1 << 1,
            memory: &[],
        }),
        roundtrip_fixture: None,
    },
];

#[test]
fn enter_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn enter_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
