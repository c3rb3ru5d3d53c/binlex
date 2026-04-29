use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "addhn2",
    instruction: "addhn2	v0.16b, v1.8h, v2.8h",
    bytes: &[0x20, 0x40, 0x22, 0x4e],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v0", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
            ("v1", 0x0080_0100_0180_0200_0280_0300_0380_0400),
            ("v2", 0x0080_0100_0180_0200_0280_0300_0380_0400),
        ],
        memory: &[],
    }),
}];

#[test]
fn addhn2_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn addhn2_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
