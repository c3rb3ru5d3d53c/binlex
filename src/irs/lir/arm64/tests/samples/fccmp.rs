use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::irs::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "fccmp",
        instruction: "fccmp d0, d1, #0, eq",
        bytes: &[0x00, 0x04, 0x61, 0x1e],
        expected_status: Some(LirStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fccmp",
        instruction: "fccmp d0, d1, #0, eq",
        bytes: &[0x00, 0x04, 0x61, 0x1e],
        expected_status: Some(LirStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("n", 0),
                ("z", 0),
                ("c", 0),
                ("v", 0),
                ("d0", 0x4008_0000_0000_0000),
                ("d1", 0x4014_0000_0000_0000),
            ],
            memory: &[],
        }),
    },
];

#[test]
fn fccmp_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn fccmp_lir_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
