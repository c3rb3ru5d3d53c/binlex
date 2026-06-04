use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::irs::lir::LirStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "b_vs",
    instruction: "b.vs	#16",
    bytes: &[0x86, 0x00, 0x00, 0x54],
    expected_status: Some(LirStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v", 0)],
        memory: &[],
    }),
}];

#[test]
fn b_vs_lir_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn b_vs_lir_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
