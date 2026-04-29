use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, eq",
        bytes: &[0x20, 0x00, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, eq",
        bytes: &[0x20, 0x00, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 0x0f), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	w0, w1, w2, eq",
        bytes: &[0x20, 0x00, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 0x0f), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, pl",
        bytes: &[0x20, 0x50, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 0x0f), ("n", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	w0, w1, w2, pl",
        bytes: &[0x20, 0x50, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 0x0f), ("n", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, le",
        bytes: &[0x20, 0xd0, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 0x0f), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	w0, w1, w2, le",
        bytes: &[0x20, 0xd0, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 0x0f), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, lt",
        bytes: &[0x20, 0xb0, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 0x0f), ("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	w0, w1, w2, lt",
        bytes: &[0x20, 0xb0, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 0x0f), ("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, ls",
        bytes: &[0x20, 0x90, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 0x0f), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	w0, w1, w2, ls",
        bytes: &[0x20, 0x90, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 0x0f), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, vc",
        bytes: &[0x20, 0x70, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 0x0f), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	w0, w1, w2, vc",
        bytes: &[0x20, 0x70, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 0x0f), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	x0, x1, x2, lo",
        bytes: &[0x20, 0x30, 0x82, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("x2", 0x0f), ("c", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csinv",
        instruction: "csinv	w0, w1, w2, lo",
        bytes: &[0x20, 0x30, 0x82, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("w2", 0x0f), ("c", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn csinv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn csinv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
