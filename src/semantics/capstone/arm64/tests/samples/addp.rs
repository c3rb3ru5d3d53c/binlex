use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "addp",
    instruction: "addp	v0.8h, v1.8h, v2.8h",
    bytes: &[0x20, 0xbc, 0x62, 0x4e],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v1", 0x0008_0007_0006_0005_0004_0003_0002_0001),
            ("v2", 0x0010_000f_000e_000d_000c_000b_000a_0009),
        ],
        memory: &[],
    }),
}];

#[test]
fn addp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn addp_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
