use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "stnp",
    instruction: "stnp x0, x1, [x2]",
    bytes: &[0x40, 0x04, 0x00, 0xa8],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("x0", 0x1122_3344_5566_7788),
            ("x1", 0x99aa_bbcc_ddee_ff00),
            ("x2", 0x3000),
        ],
        memory: &[(0x3000, &[0; 16])],
    }),
}];

#[test]
fn stnp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn stnp_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
