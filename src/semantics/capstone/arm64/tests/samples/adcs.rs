use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "adcs",
        instruction: "adcs	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x02, 0xba],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("x2", 7), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "adcs",
        instruction: "adcs	w0, w1, w2",
        bytes: &[0x20, 0x00, 0x02, 0x3a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("w1", 0xffff_ffff),
                ("w2", 0),
                ("n", 0),
                ("z", 0),
                ("c", 1),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
];

#[test]
fn adcs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn adcs_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
