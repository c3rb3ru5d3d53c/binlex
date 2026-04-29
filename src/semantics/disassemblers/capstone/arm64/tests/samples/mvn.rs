use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "mvn",
        instruction: "mvn x0, x1",
        bytes: &[0xe0, 0x03, 0x21, 0xaa],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x00ff_00ff_00ff_00ff)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mvn",
        instruction: "mvn w0, w1",
        bytes: &[0xe0, 0x03, 0x21, 0x2a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x00ff_00ff)],
            memory: &[],
        }),
    },
];

#[test]
fn mvn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn mvn_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
