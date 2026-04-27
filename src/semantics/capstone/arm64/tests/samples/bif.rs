use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "bif",
    instruction: "bif	v0.16b, v1.16b, v2.16b",
    bytes: &[0x20, 0x1c, 0xe2, 0x6e],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v0", 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128),
            ("v1", 0xffee_ddcc_bbaa_9988_7766_5544_3322_1100u128),
            ("v2", 0xf0f0_f0f0_0f0f_0f0f_aaaa_5555_cc33_33ccu128),
        ],
        memory: &[],
    }),
}];

#[test]
fn bif_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bif_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
