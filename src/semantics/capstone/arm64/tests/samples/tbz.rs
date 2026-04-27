use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w0, #3, #16",
        bytes: &[0x80, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w0, #3, #16",
        bytes: &[0x80, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w1, #3, #16",
        bytes: &[0x81, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x1, #35, #16",
        bytes: &[0x81, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w2, #3, #16",
        bytes: &[0x82, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w2", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x2, #35, #16",
        bytes: &[0x82, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w3, #3, #16",
        bytes: &[0x83, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w3", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x3, #35, #16",
        bytes: &[0x83, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w4, #3, #16",
        bytes: &[0x84, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w4", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x4, #35, #16",
        bytes: &[0x84, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x4", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w5, #3, #16",
        bytes: &[0x85, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w5", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x5, #35, #16",
        bytes: &[0x85, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x5", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w6, #3, #16",
        bytes: &[0x86, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w6", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x6, #35, #16",
        bytes: &[0x86, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x6", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w7, #3, #16",
        bytes: &[0x87, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w7", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x7, #35, #16",
        bytes: &[0x87, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x7", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w8, #3, #16",
        bytes: &[0x88, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w8", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x8, #35, #16",
        bytes: &[0x88, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x8", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w9, #3, #16",
        bytes: &[0x89, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w9", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x9, #35, #16",
        bytes: &[0x89, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x9", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w10, #3, #16",
        bytes: &[0x8a, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w10", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x10, #35, #16",
        bytes: &[0x8a, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x10", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w11, #3, #16",
        bytes: &[0x8b, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w11", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x11, #35, #16",
        bytes: &[0x8b, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x11", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w12, #3, #16",
        bytes: &[0x8c, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w12", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x12, #35, #16",
        bytes: &[0x8c, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x12", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w13, #3, #16",
        bytes: &[0x8d, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w13", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x13, #35, #16",
        bytes: &[0x8d, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x13", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w14, #3, #16",
        bytes: &[0x8e, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w14", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	x14, #35, #16",
        bytes: &[0x8e, 0x00, 0x18, 0xb6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x14", 0x0000_0008_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w15, #3, #16",
        bytes: &[0x8f, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w15", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w16, #3, #16",
        bytes: &[0x90, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w16", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w17, #3, #16",
        bytes: &[0x91, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w17", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w18, #3, #16",
        bytes: &[0x92, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w18", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w19, #3, #16",
        bytes: &[0x93, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w19", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w20, #3, #16",
        bytes: &[0x94, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w20", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w21, #3, #16",
        bytes: &[0x95, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w21", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w22, #3, #16",
        bytes: &[0x96, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w22", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w23, #3, #16",
        bytes: &[0x97, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w23", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w24, #3, #16",
        bytes: &[0x98, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w24", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w25, #3, #16",
        bytes: &[0x99, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w25", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w26, #3, #16",
        bytes: &[0x9a, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w26", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w27, #3, #16",
        bytes: &[0x9b, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w27", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w28, #3, #16",
        bytes: &[0x9c, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w28", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w29, #3, #16",
        bytes: &[0x9d, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w29", 8)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbz",
        instruction: "tbz	w30, #3, #16",
        bytes: &[0x9e, 0x00, 0x18, 0x36],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w30", 8)],
            memory: &[],
        }),
    },
];

#[test]
fn tbz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn tbz_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
