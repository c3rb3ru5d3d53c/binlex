use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sxtb",
        instruction: "sxtb	x0, w1",
        bytes: &[0x20, 0x1c, 0x40, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sxtb",
        instruction: "sxtb	x0, w1",
        bytes: &[0x20, 0x1c, 0x40, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x0000_0081)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sxtb",
        instruction: "sxtb	w0, w1",
        bytes: &[0x20, 0x1c, 0x00, 0x13],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x0000_0081)],
            memory: &[],
        }),
    },
];

#[test]
fn sxtb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sxtb_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
