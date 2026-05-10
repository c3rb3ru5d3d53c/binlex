use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, eq",
        bytes: &[0x20, 0x00, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, eq",
        bytes: &[0x20, 0x00, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1111), ("x2", 0x2222), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	w0, w1, w2, eq",
        bytes: &[0x20, 0x00, 0x82, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1111), ("w2", 0x2222), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, ne",
        bytes: &[0x20, 0x10, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1111), ("x2", 0x2222), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	w0, w1, w2, ne",
        bytes: &[0x20, 0x10, 0x82, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1111), ("w2", 0x2222), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, gt",
        bytes: &[0x20, 0xc0, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1111), ("x2", 0x2222), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	w0, w1, w2, gt",
        bytes: &[0x20, 0xc0, 0x82, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1111), ("w2", 0x2222), ("z", 0), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, ge",
        bytes: &[0x20, 0xa0, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1111), ("x2", 0x2222), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	w0, w1, w2, ge",
        bytes: &[0x20, 0xa0, 0x82, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1111), ("w2", 0x2222), ("n", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, hi",
        bytes: &[0x20, 0x80, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1111), ("x2", 0x2222), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	w0, w1, w2, hi",
        bytes: &[0x20, 0x80, 0x82, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1111), ("w2", 0x2222), ("c", 1), ("z", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, vs",
        bytes: &[0x20, 0x60, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1111), ("x2", 0x2222), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	w0, w1, w2, vs",
        bytes: &[0x20, 0x60, 0x82, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1111), ("w2", 0x2222), ("v", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	x0, x1, x2, hs",
        bytes: &[0x20, 0x20, 0x82, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1111), ("x2", 0x2222), ("c", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "csel",
        instruction: "csel	w0, w1, w2, hs",
        bytes: &[0x20, 0x20, 0x82, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1111), ("w2", 0x2222), ("c", 1)],
            memory: &[],
        }),
    },
];

#[test]
fn csel_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn csel_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
