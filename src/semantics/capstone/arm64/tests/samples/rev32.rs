use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "rev32",
        instruction: "rev32	x0, x1",
        bytes: &[0x20, 0x08, 0xc0, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "rev32",
        instruction: "rev32	x0, x1",
        bytes: &[0x20, 0x08, 0xc0, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1122_3344_5566_7788)],
            memory: &[],
        }),
    },
];

#[test]
fn rev32_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn rev32_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
