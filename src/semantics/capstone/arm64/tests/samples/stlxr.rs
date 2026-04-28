use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "stlxr",
    instruction: "stlxr	w0, x1, [x2]",
    bytes: &[0x41, 0xfc, 0x00, 0xc8],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[("x1", 0x1122_3344_5566_7788), ("x2", 0x5000)],
        memory: &[(0x5000, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22])],
    }),
}];

#[test]
fn stlxr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn stlxr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
