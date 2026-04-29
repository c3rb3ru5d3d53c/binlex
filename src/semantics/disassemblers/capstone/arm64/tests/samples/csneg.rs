use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, eq",
        bytes: &[0x20, 0x04, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, eq",
        bytes: &[0x20, 0x04, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 5), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	w0, w1, w2, eq",
        bytes: &[0x20, 0x04, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 5), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, mi",
        bytes: &[0x20, 0x44, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 5), ("n", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	w0, w1, w2, mi",
        bytes: &[0x20, 0x44, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 5), ("n", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, le",
        bytes: &[0x20, 0xd4, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	w0, w1, w2, le",
        bytes: &[0x20, 0xd4, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, ls",
        bytes: &[0x20, 0x94, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	w0, w1, w2, ls",
        bytes: &[0x20, 0x94, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, vc",
        bytes: &[0x20, 0x74, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 5), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	w0, w1, w2, vc",
        bytes: &[0x20, 0x74, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 5), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, lt",
        bytes: &[0x20, 0xb4, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 5), ("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	w0, w1, w2, lt",
        bytes: &[0x20, 0xb4, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 5), ("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	x0, x1, x2, lo",
        bytes: &[0x20, 0x34, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 5), ("c", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csneg",
        instruction: "csneg	w0, w1, w2, lo",
        bytes: &[0x20, 0x34, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 5), ("c", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn csneg_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn csneg_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
