use super::{Arm64FixtureSpec, Arm64Sample, assert_sample_statuses};
use crate::irs::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "bl",
        instruction: "bl #0x10",
        bytes: &[0x04, 0x00, 0x00, 0x94],
        expected_status: Some(LirStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "bl",
        instruction: "bl #0x20",
        bytes: &[0x08, 0x00, 0x00, 0x94],
        expected_status: Some(LirStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[],
            memory: &[],
        }),
    },
];

#[test]
fn bl_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}
