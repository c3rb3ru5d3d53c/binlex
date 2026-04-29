use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "fneg",
        instruction: "fneg	d0, d1",
        bytes: &[0x20, 0x40, 0x61, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fneg",
        instruction: "fneg	d0, d1",
        bytes: &[0x20, 0x40, 0x61, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("d1", 0x4008_0000_0000_0000)],
            memory: &[],
        }),
    },
];

#[test]
fn fneg_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn fneg_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
