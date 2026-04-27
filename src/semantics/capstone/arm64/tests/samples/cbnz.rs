use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x0, #16",
        bytes: &[0x80, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w0, #16",
        bytes: &[0x80, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x1, #16",
        bytes: &[0x81, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w1, #16",
        bytes: &[0x81, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x2, #16",
        bytes: &[0x82, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w2, #16",
        bytes: &[0x82, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w2", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x3, #16",
        bytes: &[0x83, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w3, #16",
        bytes: &[0x83, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w3", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x4, #16",
        bytes: &[0x84, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x4", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w4, #16",
        bytes: &[0x84, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w4", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x5, #16",
        bytes: &[0x85, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x5", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w5, #16",
        bytes: &[0x85, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w5", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x6, #16",
        bytes: &[0x86, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x6", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w6, #16",
        bytes: &[0x86, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w6", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x7, #16",
        bytes: &[0x87, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x7", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w7, #16",
        bytes: &[0x87, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w7", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x8, #16",
        bytes: &[0x88, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x8", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w8, #16",
        bytes: &[0x88, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w8", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x9, #16",
        bytes: &[0x89, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x9", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w9, #16",
        bytes: &[0x89, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w9", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x10, #16",
        bytes: &[0x8a, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x10", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w10, #16",
        bytes: &[0x8a, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w10", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x11, #16",
        bytes: &[0x8b, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x11", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w11, #16",
        bytes: &[0x8b, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w11", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x12, #16",
        bytes: &[0x8c, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x12", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w12, #16",
        bytes: &[0x8c, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w12", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x13, #16",
        bytes: &[0x8d, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x13", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w13, #16",
        bytes: &[0x8d, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w13", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x14, #16",
        bytes: &[0x8e, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x14", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w14, #16",
        bytes: &[0x8e, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w14", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x15, #16",
        bytes: &[0x8f, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x15", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w15, #16",
        bytes: &[0x8f, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w15", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x16, #16",
        bytes: &[0x90, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x16", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w16, #16",
        bytes: &[0x90, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w16", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x17, #16",
        bytes: &[0x91, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x17", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w17, #16",
        bytes: &[0x91, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w17", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x18, #16",
        bytes: &[0x92, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x18", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w18, #16",
        bytes: &[0x92, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w18", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x19, #16",
        bytes: &[0x93, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x19", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w19, #16",
        bytes: &[0x93, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w19", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x20, #16",
        bytes: &[0x94, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x20", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w20, #16",
        bytes: &[0x94, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w20", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x21, #16",
        bytes: &[0x95, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x21", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w21, #16",
        bytes: &[0x95, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w21", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x22, #16",
        bytes: &[0x96, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x22", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w22, #16",
        bytes: &[0x96, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w22", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x23, #16",
        bytes: &[0x97, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x23", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w23, #16",
        bytes: &[0x97, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w23", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x24, #16",
        bytes: &[0x98, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x24", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w24, #16",
        bytes: &[0x98, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w24", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x25, #16",
        bytes: &[0x99, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x25", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w25, #16",
        bytes: &[0x99, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w25", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x26, #16",
        bytes: &[0x9a, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x26", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w26, #16",
        bytes: &[0x9a, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w26", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x27, #16",
        bytes: &[0x9b, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x27", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w27, #16",
        bytes: &[0x9b, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w27", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x28, #16",
        bytes: &[0x9c, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x28", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w28, #16",
        bytes: &[0x9c, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w28", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x29, #16",
        bytes: &[0x9d, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x29", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w29, #16",
        bytes: &[0x9d, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w29", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	x30, #16",
        bytes: &[0x9e, 0x00, 0x00, 0xb5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x30", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cbnz",
        instruction: "cbnz	w30, #16",
        bytes: &[0x9e, 0x00, 0x00, 0x35],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w30", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn cbnz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cbnz_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
