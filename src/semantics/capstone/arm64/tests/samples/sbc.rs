use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sbc",
        instruction: "sbc	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x02, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sbc",
        instruction: "sbc	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x02, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x1", 10),
                ("x2", 3),
                ("n", 0),
                ("z", 0),
                ("c", 1),
                ("v", 0),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sbc",
        instruction: "sbc	w0, w1, w2",
        bytes: &[0x20, 0x00, 0x02, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("w1", 10),
                ("w2", 3),
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
fn sbc_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sbc_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
