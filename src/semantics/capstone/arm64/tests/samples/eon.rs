use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "eon",
        instruction: "eon	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x22, 0xca],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "eon",
        instruction: "eon	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x22, 0xca],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0xf0f0_0000_f0f0_0000), ("x2", 0x0ff0_0ff0_0ff0_0ff0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "eon",
        instruction: "eon	w0, w1, w2",
        bytes: &[0x20, 0x00, 0x22, 0x4a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xf0f0_0000), ("w2", 0x0ff0_0ff0)],
            memory: &[],
        }),
    },
];

#[test]
fn eon_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn eon_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
