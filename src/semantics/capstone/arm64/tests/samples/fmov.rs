use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	d0, d1",
        bytes: &[0x20, 0x40, 0x60, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	d1, x0",
        bytes: &[0x01, 0x00, 0x67, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	s0, w1",
        bytes: &[0x20, 0x00, 0x27, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	d0, #1.00000000",
        bytes: &[0x00, 0x10, 0x6e, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	s0, #1.00000000",
        bytes: &[0x00, 0x10, 0x2e, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	x0, d1",
        bytes: &[0x20, 0x00, 0x66, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	x1, d0",
        bytes: &[0x01, 0x00, 0x66, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	w0, s1",
        bytes: &[0x20, 0x00, 0x26, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	d0, d1",
        bytes: &[0x20, 0x40, 0x60, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("d1", 0x4008_0000_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	d1, x0",
        bytes: &[0x01, 0x00, 0x67, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0x4008_0000_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	s0, w1",
        bytes: &[0x20, 0x00, 0x27, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x4040_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	x0, d1",
        bytes: &[0x20, 0x00, 0x66, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("d1", 0x4008_0000_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	x1, d0",
        bytes: &[0x01, 0x00, 0x66, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("d0", 0x4008_0000_0000_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "fmov",
        instruction: "fmov	w0, s1",
        bytes: &[0x20, 0x00, 0x26, 0x1e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("s1", 0x4040_0000)],
            memory: &[],
        }),
    },
];

#[test]
fn fmov_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn fmov_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
