use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	x29, x30, [sp, #-16]!",
        bytes: &[0xfd, 0x7b, 0xbf, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	x0, x1, [x2]",
        bytes: &[0x40, 0x04, 0x00, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x0", 0x0102_0304_0506_0708),
                ("x1", 0x1112_1314_1516_1718),
                ("x2", 0x3000),
            ],
            memory: &[(0x3000, &[0; 16])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	x0, x1, [sp, #-16]!",
        bytes: &[0xe0, 0x07, 0xbf, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x0", 0x1122_3344_5566_7788),
                ("x1", 0x99aa_bbcc_ddee_ff00),
                ("sp", 0x2ff0),
            ],
            memory: &[(0x2fe0, &[0; 16])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	x0, x1, [x2], #16",
        bytes: &[0x40, 0x04, 0x81, 0xa8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x0", 0x0102_0304_0506_0708),
                ("x1", 0x1112_1314_1516_1718),
                ("x2", 0x3000),
            ],
            memory: &[(0x3000, &[0; 16])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	w0, w1, [x2]",
        bytes: &[0x40, 0x04, 0x00, 0x29],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x1234_5678), ("w1", 0x89ab_cdef), ("x2", 0x3000)],
            memory: &[(0x3000, &[0; 8])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	w0, w1, [x2], #8",
        bytes: &[0x40, 0x04, 0x81, 0x28],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x0102_0304), ("w1", 0x1112_1314), ("x2", 0x3000)],
            memory: &[(0x3000, &[0; 8])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	w0, w1, [sp, #-8]!",
        bytes: &[0xe0, 0x07, 0xbf, 0x29],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x1234_5678), ("w1", 0x89ab_cdef), ("sp", 0x2ff0)],
            memory: &[(0x2fe8, &[0; 8])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	w0, w1, [sp], #8",
        bytes: &[0xe0, 0x07, 0x81, 0x28],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x0102_0304), ("w1", 0x1112_1314), ("sp", 0x2fe8)],
            memory: &[(0x2fe8, &[0; 8])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	x29, x30, [sp, #-16]!",
        bytes: &[0xfd, 0x7b, 0xbf, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x29", 0x1122_3344_5566_7788),
                ("x30", 0x99aa_bbcc_ddee_ff00),
                ("sp", 0x2ff0),
            ],
            memory: &[(0x2fe0, &[0; 16])],
        }),
    },
    Arm64Sample {
        mnemonic: "stp",
        instruction: "stp	x29, x30, [sp]",
        bytes: &[0xfd, 0x7b, 0x00, 0xa9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("x29", 0x0102_0304_0506_0708),
                ("x30", 0x1112_1314_1516_1718),
                ("sp", 0x2fe0),
            ],
            memory: &[(0x2fe0, &[0; 16])],
        }),
    },
];

#[test]
fn stp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn stp_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
