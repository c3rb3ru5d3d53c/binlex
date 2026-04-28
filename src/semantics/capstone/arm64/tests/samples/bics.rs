use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "bics",
        instruction: "bics	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x22, 0xea],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "bics",
        instruction: "bics	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x22, 0xea],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x1", 0xffff_0000_ffff_0000),
                ("x2", 0x00ff_00ff_00ff_00ff),
                ("n", 0),
                ("z", 0),
                ("c", 0),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "bics",
        instruction: "bics	w0, w1, w2",
        bytes: &[0x20, 0x00, 0x22, 0x6a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("w1", 0xffff_0000),
                ("w2", 0x00ff_00ff),
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
fn bics_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bics_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
