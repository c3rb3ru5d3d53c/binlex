use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldrb",
        instruction: "ldrb	w0, [x1]",
        bytes: &[0x20, 0x00, 0x40, 0x39],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldrb",
        instruction: "ldrb	w0, [x1]",
        bytes: &[0x20, 0x00, 0x40, 0x39],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x2000)],
            memory: &[(0x2000, &[0xab])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldrb",
        instruction: "ldrb	w0, [x1, x2]",
        bytes: &[0x20, 0x68, 0x62, 0x38],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000), ("x2", 0x10)],
            memory: &[(0x3010, &[0xab])],
        }),
    },
];

#[test]
fn ldrb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldrb_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
