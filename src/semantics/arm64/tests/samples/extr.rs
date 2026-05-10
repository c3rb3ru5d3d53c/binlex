use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "extr",
        instruction: "extr	w8, w0, w8, #1",
        bytes: &[0x08, 0x04, 0x88, 0x13],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "extr",
        instruction: "extr	x0, x1, x2, #8",
        bytes: &[0x20, 0x20, 0xc2, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "extr",
        instruction: "extr	w8, w0, w8, #1",
        bytes: &[0x08, 0x04, 0x88, 0x13],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x1234_5678), ("w8", 0x89ab_cdef)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "extr",
        instruction: "extr	x0, x1, x2, #8",
        bytes: &[0x20, 0x20, 0xc2, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0123_4567_89ab_cdef), ("x2", 0xfedc_ba98_7654_3210)],
            memory: &[],
        }),
    },
];

#[test]
fn extr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn extr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
