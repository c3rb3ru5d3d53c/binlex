use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "tst",
        instruction: "tst x0, x1",
        bytes: &[0x1f, 0x00, 0x01, 0xea],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x0", 0xf0f0_0000_f0f0_0000),
                ("x1", 0x0ff0_0ff0_0ff0_0ff0),
                ("n", 0),
                ("z", 0),
                ("c", 0),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tst",
        instruction: "tst w0, w1",
        bytes: &[0x1f, 0x00, 0x01, 0x6a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("w0", 0xf0f0_0000),
                ("w1", 0x0ff0_0ff0),
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
fn tst_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn tst_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
