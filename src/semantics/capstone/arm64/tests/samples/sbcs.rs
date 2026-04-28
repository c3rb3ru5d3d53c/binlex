use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "sbcs",
    instruction: "sbcs x0, x1, x2",
    bytes: &[0x20, 0x00, 0x02, 0xfa],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("x1", 0x1000), ("x2", 0x0001), ("c", 1)],
        memory: &[],
    }),
}];

#[test]
fn sbcs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sbcs_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
