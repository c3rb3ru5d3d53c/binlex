use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::irs::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "smsubl",
        instruction: "smsubl	x0, w1, w2, x3",
        bytes: &[0x20, 0x8c, 0x22, 0x9b],
        expected_status: Some(LirStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "smsubl",
        instruction: "smsubl	x0, w1, w2, x3",
        bytes: &[0x20, 0x8c, 0x22, 0x9b],
        expected_status: Some(LirStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xffff_fffe), ("w2", 3), ("x3", 100)],
            memory: &[],
        }),
    },
];

#[test]
fn smsubl_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn smsubl_lir_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
