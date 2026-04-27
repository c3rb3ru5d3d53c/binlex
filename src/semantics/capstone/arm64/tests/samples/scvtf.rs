use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "scvtf",
        instruction: "scvtf	d0, x1",
        bytes: &[0x20, 0x00, 0x62, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "scvtf",
        instruction: "scvtf	d0, x1",
        bytes: &[0x20, 0x00, 0x62, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 42)],
            memory: &[],
        }),
    },
];

#[test]
fn scvtf_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn scvtf_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
