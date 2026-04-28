use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, eq",
        bytes: &[0xe0, 0x17, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, eq",
        bytes: &[0xe0, 0x17, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	w0, eq",
        bytes: &[0xe0, 0x17, 0x9f, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, ne",
        bytes: &[0xe0, 0x07, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	w0, ne",
        bytes: &[0xe0, 0x07, 0x9f, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, le",
        bytes: &[0xe0, 0xc7, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	w0, le",
        bytes: &[0xe0, 0xc7, 0x9f, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, lt",
        bytes: &[0xe0, 0xa7, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	w0, lt",
        bytes: &[0xe0, 0xa7, 0x9f, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, ls",
        bytes: &[0xe0, 0x87, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	w0, ls",
        bytes: &[0xe0, 0x87, 0x9f, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, vc",
        bytes: &[0xe0, 0x67, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	w0, vc",
        bytes: &[0xe0, 0x67, 0x9f, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	x0, lo",
        bytes: &[0xe0, 0x27, 0x9f, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cset",
        instruction: "cset	w0, lo",
        bytes: &[0xe0, 0x27, 0x9f, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("c", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn cset_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cset_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
