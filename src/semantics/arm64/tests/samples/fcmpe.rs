use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "fcmpe",
        instruction: "fcmpe	s0, s1",
        bytes: &[0x10, 0x20, 0x21, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fcmpe",
        instruction: "fcmpe	d0, #0.0",
        bytes: &[0x18, 0x20, 0x60, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fcmpe",
        instruction: "fcmpe	s0, #0.0",
        bytes: &[0x18, 0x20, 0x20, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fcmpe",
        instruction: "fcmp	d0, d1",
        bytes: &[0x00, 0x20, 0x61, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("n", 0),
                ("z", 1),
                ("c", 0),
                ("v", 0),
                ("d0", 0x4014_0000_0000_0000),
                ("d1", 0x4008_0000_0000_0000),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fcmpe",
        instruction: "fcmpe	s0, s1",
        bytes: &[0x10, 0x20, 0x21, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("n", 0),
                ("z", 1),
                ("c", 0),
                ("v", 0),
                ("s0", 0x4080_0000),
                ("s1", 0x4040_0000),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fcmpe",
        instruction: "fcmpe	d0, #0.0",
        bytes: &[0x18, 0x20, 0x60, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("n", 0),
                ("z", 1),
                ("c", 0),
                ("v", 0),
                ("d0", 0x4008_0000_0000_0000),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fcmpe",
        instruction: "fcmpe	s0, #0.0",
        bytes: &[0x18, 0x20, 0x20, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("n", 0), ("z", 1), ("c", 0), ("v", 0), ("s0", 0x4040_0000)],
            memory: &[],
        }),
    },
];

#[test]
fn fcmpe_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn fcmpe_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
