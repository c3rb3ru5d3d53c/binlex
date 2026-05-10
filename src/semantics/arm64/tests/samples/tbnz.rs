use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w0, #3, #16",
        bytes: &[0x80, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w1, #3, #16",
        bytes: &[0x81, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x1, #35, #16",
        bytes: &[0x81, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w2, #3, #16",
        bytes: &[0x82, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w2", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x2, #35, #16",
        bytes: &[0x82, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w3, #3, #16",
        bytes: &[0x83, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w3", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x3, #35, #16",
        bytes: &[0x83, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w4, #3, #16",
        bytes: &[0x84, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w4", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x4, #35, #16",
        bytes: &[0x84, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x4", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w5, #3, #16",
        bytes: &[0x85, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w5", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x5, #35, #16",
        bytes: &[0x85, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x5", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w6, #3, #16",
        bytes: &[0x86, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w6", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x6, #35, #16",
        bytes: &[0x86, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x6", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w7, #3, #16",
        bytes: &[0x87, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w7", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x7, #35, #16",
        bytes: &[0x87, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x7", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w8, #3, #16",
        bytes: &[0x88, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w8", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x8, #35, #16",
        bytes: &[0x88, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x8", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w9, #3, #16",
        bytes: &[0x89, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w9", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x9, #35, #16",
        bytes: &[0x89, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x9", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w10, #3, #16",
        bytes: &[0x8a, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w10", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x10, #35, #16",
        bytes: &[0x8a, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x10", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w11, #3, #16",
        bytes: &[0x8b, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w11", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x11, #35, #16",
        bytes: &[0x8b, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x11", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w12, #3, #16",
        bytes: &[0x8c, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w12", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x12, #35, #16",
        bytes: &[0x8c, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x12", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w13, #3, #16",
        bytes: &[0x8d, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w13", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x13, #35, #16",
        bytes: &[0x8d, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x13", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w14, #3, #16",
        bytes: &[0x8e, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w14", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	x14, #35, #16",
        bytes: &[0x8e, 0x00, 0x18, 0xb7],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x14", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "tbnz",
        instruction: "tbnz	w15, #3, #16",
        bytes: &[0x8f, 0x00, 0x18, 0x37],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w15", 8)],
            memory: &[],
        }),
    },
];

#[test]
fn tbnz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn tbnz_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
