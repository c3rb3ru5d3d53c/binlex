use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "bfc",
        instruction: "bfc x0, #8, #12",
        bytes: &[0xe0, 0x2f, 0x78, 0xb3],
        expected_status: Some(SemanticStatus::Partial),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0xffff_ffff_ffff_ffffu128)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "bfc",
        instruction: "bfc w0, #4, #8",
        bytes: &[0xe0, 0x1f, 0x1c, 0x33],
        expected_status: Some(SemanticStatus::Partial),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0xffff_ffffu128)],
            memory: &[],
        }),
    },
];

#[test]
fn bfc_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bfc_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
