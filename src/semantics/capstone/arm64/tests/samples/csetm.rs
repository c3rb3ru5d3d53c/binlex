use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, eq",
        bytes: &[0xe0, 0x13, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, eq",
        bytes: &[0xe0, 0x13, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	w0, eq",
        bytes: &[0xe0, 0x13, 0x9f, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, ne",
        bytes: &[0xe0, 0x03, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	w0, ne",
        bytes: &[0xe0, 0x03, 0x9f, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, gt",
        bytes: &[0xe0, 0xd3, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	w0, gt",
        bytes: &[0xe0, 0xd3, 0x9f, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, hi",
        bytes: &[0xe0, 0x93, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	w0, hi",
        bytes: &[0xe0, 0x93, 0x9f, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, vs",
        bytes: &[0xe0, 0x73, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	w0, vs",
        bytes: &[0xe0, 0x73, 0x9f, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, ge",
        bytes: &[0xe0, 0xb3, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	w0, ge",
        bytes: &[0xe0, 0xb3, 0x9f, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	x0, hs",
        bytes: &[0xe0, 0x33, 0x9f, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csetm",
        instruction: "csetm	w0, hs",
        bytes: &[0xe0, 0x33, 0x9f, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 1)],
            memory: &[],
        }),
    },
];

#[test]
fn csetm_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn csetm_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
