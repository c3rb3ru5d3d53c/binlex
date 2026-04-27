use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldr",
        instruction: "ldr x0, [x1, x2]",
        bytes: &[0x20, 0x68, 0x62, 0xf8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000), ("x2", 0x10)],
            memory: &[(0x3010, &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldr",
        instruction: "ldr w0, [x1, x2]",
        bytes: &[0x20, 0x68, 0x62, 0xb8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000), ("x2", 0x10)],
            memory: &[(0x3010, &[0x78, 0x56, 0x34, 0x12])],
        }),
    },
];

#[test]
fn ldr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
