use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x0, TPIDR_EL0",
        bytes: &[0x40, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x1, TPIDR_EL0",
        bytes: &[0x41, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x2, TPIDR_EL0",
        bytes: &[0x42, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x0, FPCR",
        bytes: &[0x00, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x0, TPIDR_EL0",
        bytes: &[0x40, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x1, TPIDR_EL0",
        bytes: &[0x41, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x2, TPIDR_EL0",
        bytes: &[0x42, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x0, FPCR",
        bytes: &[0x00, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x3, TPIDR_EL0",
        bytes: &[0x43, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x4, TPIDR_EL0",
        bytes: &[0x44, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x5, TPIDR_EL0",
        bytes: &[0x45, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x6, TPIDR_EL0",
        bytes: &[0x46, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x7, TPIDR_EL0",
        bytes: &[0x47, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x8, TPIDR_EL0",
        bytes: &[0x48, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x9, TPIDR_EL0",
        bytes: &[0x49, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x10, TPIDR_EL0",
        bytes: &[0x4a, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x11, TPIDR_EL0",
        bytes: &[0x4b, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x12, TPIDR_EL0",
        bytes: &[0x4c, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x13, TPIDR_EL0",
        bytes: &[0x4d, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x14, TPIDR_EL0",
        bytes: &[0x4e, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x15, TPIDR_EL0",
        bytes: &[0x4f, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x16, TPIDR_EL0",
        bytes: &[0x50, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x17, TPIDR_EL0",
        bytes: &[0x51, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x18, TPIDR_EL0",
        bytes: &[0x52, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x19, TPIDR_EL0",
        bytes: &[0x53, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x20, TPIDR_EL0",
        bytes: &[0x54, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x21, TPIDR_EL0",
        bytes: &[0x55, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x22, TPIDR_EL0",
        bytes: &[0x56, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x23, TPIDR_EL0",
        bytes: &[0x57, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x24, TPIDR_EL0",
        bytes: &[0x58, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x25, TPIDR_EL0",
        bytes: &[0x59, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x26, TPIDR_EL0",
        bytes: &[0x5a, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x27, TPIDR_EL0",
        bytes: &[0x5b, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x28, TPIDR_EL0",
        bytes: &[0x5c, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x29, TPIDR_EL0",
        bytes: &[0x5d, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x30, TPIDR_EL0",
        bytes: &[0x5e, 0xd0, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("tpidr_el0", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x1, FPCR",
        bytes: &[0x01, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x2, FPCR",
        bytes: &[0x02, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x3, FPCR",
        bytes: &[0x03, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x4, FPCR",
        bytes: &[0x04, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x5, FPCR",
        bytes: &[0x05, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x6, FPCR",
        bytes: &[0x06, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x7, FPCR",
        bytes: &[0x07, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x8, FPCR",
        bytes: &[0x08, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x9, FPCR",
        bytes: &[0x09, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x10, FPCR",
        bytes: &[0x0a, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x11, FPCR",
        bytes: &[0x0b, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x12, FPCR",
        bytes: &[0x0c, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x13, FPCR",
        bytes: &[0x0d, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x14, FPCR",
        bytes: &[0x0e, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x15, FPCR",
        bytes: &[0x0f, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x16, FPCR",
        bytes: &[0x10, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x17, FPCR",
        bytes: &[0x11, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x18, FPCR",
        bytes: &[0x12, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x19, FPCR",
        bytes: &[0x13, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x20, FPCR",
        bytes: &[0x14, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x21, FPCR",
        bytes: &[0x15, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mrs",
        instruction: "mrs	x22, FPCR",
        bytes: &[0x16, 0x44, 0x3b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("fpcr", 0x0100_0000)],
            memory: &[],
        }),
    },
];

#[test]
fn mrs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn mrs_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
