use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ld1",
        instruction: "ld1	{ v0.16b }, [x1]",
        bytes: &[0x20, 0x70, 0x40, 0x4c],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ld1",
        instruction: "ld1	{ v0.d }[1], [x1]",
        bytes: &[0x20, 0x84, 0x40, 0x4d],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ld1",
        instruction: "ld1	{ v1.s }[1], [x11]",
        bytes: &[0x61, 0x91, 0x40, 0x0d],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ld1",
        instruction: "ld1	{ v0.d }[1], [x1]",
        bytes: &[0x20, 0x84, 0x40, 0x4d],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v0", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                ("x1", 0x5000),
            ],
            memory: &[(0x5000, &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
        }),
    },
    Arm64Sample {
        mnemonic: "ld1",
        instruction: "ld1	{ v1.s }[1], [x11]",
        bytes: &[0x61, 0x91, 0x40, 0x0d],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v1", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                ("x11", 0x6000),
            ],
            memory: &[(0x6000, &[0x78, 0x56, 0x34, 0x12])],
        }),
    },
];

#[test]
fn ld1_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ld1_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
