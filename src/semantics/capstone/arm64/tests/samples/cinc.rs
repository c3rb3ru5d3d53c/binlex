use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, eq",
        bytes: &[0x20, 0x14, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, eq",
        bytes: &[0x20, 0x14, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	w0, w1, eq",
        bytes: &[0x20, 0x14, 0x81, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, ne",
        bytes: &[0x20, 0x04, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	w0, w1, ne",
        bytes: &[0x20, 0x04, 0x81, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, gt",
        bytes: &[0x20, 0xd4, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	w0, w1, gt",
        bytes: &[0x20, 0xd4, 0x81, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, hi",
        bytes: &[0x20, 0x94, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	w0, w1, hi",
        bytes: &[0x20, 0x94, 0x81, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, vs",
        bytes: &[0x20, 0x74, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	w0, w1, vs",
        bytes: &[0x20, 0x74, 0x81, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, ge",
        bytes: &[0x20, 0xb4, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	w0, w1, ge",
        bytes: &[0x20, 0xb4, 0x81, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	x0, x1, hs",
        bytes: &[0x20, 0x34, 0x81, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("c", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinc",
        instruction: "cinc	w0, w1, hs",
        bytes: &[0x20, 0x34, 0x81, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x10), ("c", 1)],
            memory: &[],
        }),
    },
];

#[test]
fn cinc_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cinc_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
