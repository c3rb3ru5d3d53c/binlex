use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, eq",
        bytes: &[0x20, 0x14, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, eq",
        bytes: &[0x20, 0x14, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	w0, w1, eq",
        bytes: &[0x20, 0x14, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, mi",
        bytes: &[0x20, 0x54, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("n", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	w0, w1, mi",
        bytes: &[0x20, 0x54, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5), ("n", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, le",
        bytes: &[0x20, 0xc4, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	w0, w1, le",
        bytes: &[0x20, 0xc4, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5), ("z", 1), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, ls",
        bytes: &[0x20, 0x84, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	w0, w1, ls",
        bytes: &[0x20, 0x84, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5), ("c", 0), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, vc",
        bytes: &[0x20, 0x64, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	w0, w1, vc",
        bytes: &[0x20, 0x64, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, lt",
        bytes: &[0x20, 0xa4, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	w0, w1, lt",
        bytes: &[0x20, 0xa4, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5), ("n", 1), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	x0, x1, lo",
        bytes: &[0x20, 0x24, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5), ("c", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cneg",
        instruction: "cneg	w0, w1, lo",
        bytes: &[0x20, 0x24, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5), ("c", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn cneg_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cneg_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
