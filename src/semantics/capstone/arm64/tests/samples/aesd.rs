use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "aesd",
    instruction: "aesd v0.16b, v1.16b",
    bytes: &[0x20, 0x58, 0x28, 0x4e],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v0", 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128),
            ("v1", 0x0f1e_2d3c_4b5a_6978_8796_a5b4_c3d2_e1f0u128),
        ],
        memory: &[],
    }),
}];

#[test]
fn aesd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn aesd_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
