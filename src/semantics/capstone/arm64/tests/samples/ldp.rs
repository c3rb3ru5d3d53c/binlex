use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	x29, x30, [sp], #16",
        bytes: &[0xfd, 0x7b, 0xc1, 0xa8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	x0, x1, [x2]",
        bytes: &[0x40, 0x04, 0x40, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x3000)],
            memory: &[(
                0x3000,
                &[
                    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x18, 0x17, 0x16, 0x15, 0x14,
                    0x13, 0x12, 0x11,
                ],
            )],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	x0, x1, [x2], #16",
        bytes: &[0x40, 0x04, 0xc1, 0xa8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x3000)],
            memory: &[(
                0x3000,
                &[
                    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc,
                    0xbb, 0xaa, 0x99,
                ],
            )],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	x0, x1, [sp], #16",
        bytes: &[0xe0, 0x07, 0xc1, 0xa8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("sp", 0x2fe0)],
            memory: &[(
                0x2fe0,
                &[
                    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x18, 0x17, 0x16, 0x15, 0x14,
                    0x13, 0x12, 0x11,
                ],
            )],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	x0, x1, [sp, #-16]!",
        bytes: &[0xe0, 0x07, 0xff, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("sp", 0x2ff0)],
            memory: &[(
                0x2fe0,
                &[
                    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x18, 0x17, 0x16, 0x15, 0x14,
                    0x13, 0x12, 0x11,
                ],
            )],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	w0, w1, [x2]",
        bytes: &[0x40, 0x04, 0x40, 0x29],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x3000)],
            memory: &[(0x3000, &[0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	w0, w1, [x2], #8",
        bytes: &[0x40, 0x04, 0xc1, 0x28],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x3000)],
            memory: &[(0x3000, &[0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	w0, w1, [sp], #8",
        bytes: &[0xe0, 0x07, 0xc1, 0x28],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("sp", 0x2fe8)],
            memory: &[(0x2fe8, &[0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	w0, w1, [sp, #-8]!",
        bytes: &[0xe0, 0x07, 0xff, 0x29],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("sp", 0x2ff0)],
            memory: &[(0x2fe8, &[0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	x29, x30, [sp], #16",
        bytes: &[0xfd, 0x7b, 0xc1, 0xa8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("sp", 0x2fe0)],
            memory: &[(
                0x2fe0,
                &[
                    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc,
                    0xbb, 0xaa, 0x99,
                ],
            )],
        }),
    },
    Arm64Sample {
        mnemonic: "ldp",
        instruction: "ldp	x29, x30, [sp]",
        bytes: &[0xfd, 0x7b, 0x40, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("sp", 0x2fe0)],
            memory: &[(
                0x2fe0,
                &[
                    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x18, 0x17, 0x16, 0x15, 0x14,
                    0x13, 0x12, 0x11,
                ],
            )],
        }),
    },
];

#[test]
fn ldp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldp_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
