use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x0, #16",
        bytes: &[0x80, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w0, #16",
        bytes: &[0x80, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x1, #16",
        bytes: &[0x81, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w1, #16",
        bytes: &[0x81, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x2, #16",
        bytes: &[0x82, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w2, #16",
        bytes: &[0x82, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w2", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x3, #16",
        bytes: &[0x83, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w3, #16",
        bytes: &[0x83, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w3", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x4, #16",
        bytes: &[0x84, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x4", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w4, #16",
        bytes: &[0x84, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w4", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x5, #16",
        bytes: &[0x85, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x5", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w5, #16",
        bytes: &[0x85, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w5", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x6, #16",
        bytes: &[0x86, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x6", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w6, #16",
        bytes: &[0x86, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w6", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x7, #16",
        bytes: &[0x87, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x7", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w7, #16",
        bytes: &[0x87, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w7", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x8, #16",
        bytes: &[0x88, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x8", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w8, #16",
        bytes: &[0x88, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w8", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x9, #16",
        bytes: &[0x89, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x9", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w9, #16",
        bytes: &[0x89, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w9", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x10, #16",
        bytes: &[0x8a, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x10", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w10, #16",
        bytes: &[0x8a, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w10", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x11, #16",
        bytes: &[0x8b, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x11", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w11, #16",
        bytes: &[0x8b, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w11", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x12, #16",
        bytes: &[0x8c, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x12", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w12, #16",
        bytes: &[0x8c, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w12", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x13, #16",
        bytes: &[0x8d, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x13", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w13, #16",
        bytes: &[0x8d, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w13", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x14, #16",
        bytes: &[0x8e, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x14", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w14, #16",
        bytes: &[0x8e, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w14", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x15, #16",
        bytes: &[0x8f, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x15", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w15, #16",
        bytes: &[0x8f, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w15", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x16, #16",
        bytes: &[0x90, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x16", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w16, #16",
        bytes: &[0x90, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w16", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x17, #16",
        bytes: &[0x91, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x17", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w17, #16",
        bytes: &[0x91, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w17", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x18, #16",
        bytes: &[0x92, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x18", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w18, #16",
        bytes: &[0x92, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w18", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x19, #16",
        bytes: &[0x93, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x19", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w19, #16",
        bytes: &[0x93, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w19", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x20, #16",
        bytes: &[0x94, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x20", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w20, #16",
        bytes: &[0x94, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w20", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x21, #16",
        bytes: &[0x95, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x21", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w21, #16",
        bytes: &[0x95, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w21", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x22, #16",
        bytes: &[0x96, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x22", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w22, #16",
        bytes: &[0x96, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w22", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x23, #16",
        bytes: &[0x97, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x23", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w23, #16",
        bytes: &[0x97, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w23", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x24, #16",
        bytes: &[0x98, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x24", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w24, #16",
        bytes: &[0x98, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w24", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x25, #16",
        bytes: &[0x99, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x25", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w25, #16",
        bytes: &[0x99, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w25", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x26, #16",
        bytes: &[0x9a, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x26", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w26, #16",
        bytes: &[0x9a, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w26", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x27, #16",
        bytes: &[0x9b, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x27", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w27, #16",
        bytes: &[0x9b, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w27", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x28, #16",
        bytes: &[0x9c, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x28", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w28, #16",
        bytes: &[0x9c, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w28", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x29, #16",
        bytes: &[0x9d, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x29", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w29, #16",
        bytes: &[0x9d, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w29", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	x30, #16",
        bytes: &[0x9e, 0x00, 0x00, 0xb4],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x30", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbz",
        instruction: "cbz	w30, #16",
        bytes: &[0x9e, 0x00, 0x00, 0x34],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w30", 1)],
            memory: &[],
        }),
    },
];

#[test]
fn cbz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cbz_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
