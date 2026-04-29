use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "str",
        instruction: "str x0, [x1, x2]",
        bytes: &[0x20, 0x68, 0x22, 0xf8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0x1122_3344_5566_7788), ("x1", 0x3000), ("x2", 0x10)],
            memory: &[(0x3010, &[0; 8])],
        }),
    },
    Arm64Sample {
        mnemonic: "str",
        instruction: "str w0, [x1, x2]",
        bytes: &[0x20, 0x68, 0x22, 0xb8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x1234_5678), ("x1", 0x3000), ("x2", 0x10)],
            memory: &[(0x3010, &[0; 4])],
        }),
    },
];

#[test]
fn str_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn str_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
