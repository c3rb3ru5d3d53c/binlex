use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "aesmc",
    instruction: "aesmc v0.16b, v1.16b",
    bytes: &[0x20, 0x68, 0x28, 0x4e],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v1", 0xfedc_ba98_7654_3210_0011_2233_4455_6677u128)],
        memory: &[],
    }),
}];

#[test]
fn aesmc_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn aesmc_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
