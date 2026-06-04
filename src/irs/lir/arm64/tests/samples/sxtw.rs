use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::irs::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sxtw",
        instruction: "sxtw	x0, w1",
        bytes: &[0x20, 0x7c, 0x40, 0x93],
        expected_status: Some(LirStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sxtw",
        instruction: "sxtw	x0, w1",
        bytes: &[0x20, 0x7c, 0x40, 0x93],
        expected_status: Some(LirStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x8000_0001)],
            memory: &[],
        }),
    },
];

#[test]
fn sxtw_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sxtw_lir_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
