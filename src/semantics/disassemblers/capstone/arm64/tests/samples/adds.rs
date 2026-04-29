use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "adds",
        instruction: "adds	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x02, 0xab],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x1", 0x7fff_ffff_ffff_ffff),
                ("x2", 1),
                ("n", 0),
                ("z", 0),
                ("c", 0),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "adds",
        instruction: "adds	w0, w1, w2",
        bytes: &[0x20, 0x00, 0x02, 0x2b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("w1", 0xffff_ffff),
                ("w2", 1),
                ("n", 0),
                ("z", 0),
                ("c", 0),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
];

#[test]
fn adds_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn adds_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
