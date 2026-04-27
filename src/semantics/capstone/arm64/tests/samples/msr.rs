use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x0",
        bytes: &[0x40, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x1",
        bytes: &[0x41, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x2",
        bytes: &[0x42, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x0",
        bytes: &[0x00, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x0",
        bytes: &[0x40, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x1",
        bytes: &[0x41, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x2",
        bytes: &[0x42, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x0",
        bytes: &[0x00, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x3",
        bytes: &[0x43, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x4",
        bytes: &[0x44, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x4", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x5",
        bytes: &[0x45, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x5", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x6",
        bytes: &[0x46, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x6", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x7",
        bytes: &[0x47, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x7", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x8",
        bytes: &[0x48, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x8", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x9",
        bytes: &[0x49, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x9", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x10",
        bytes: &[0x4a, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x10", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x11",
        bytes: &[0x4b, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x11", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x12",
        bytes: &[0x4c, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x12", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x13",
        bytes: &[0x4d, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x13", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x14",
        bytes: &[0x4e, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x14", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x15",
        bytes: &[0x4f, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x15", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x16",
        bytes: &[0x50, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x16", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x17",
        bytes: &[0x51, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x17", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x18",
        bytes: &[0x52, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x18", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x19",
        bytes: &[0x53, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x19", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x20",
        bytes: &[0x54, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x20", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x21",
        bytes: &[0x55, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x21", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x22",
        bytes: &[0x56, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x22", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x23",
        bytes: &[0x57, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x23", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x24",
        bytes: &[0x58, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x24", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x25",
        bytes: &[0x59, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x25", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x26",
        bytes: &[0x5a, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x26", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x27",
        bytes: &[0x5b, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x27", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x28",
        bytes: &[0x5c, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x28", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x29",
        bytes: &[0x5d, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x29", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	TPIDR_EL0, x30",
        bytes: &[0x5e, 0xd0, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x30", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x1",
        bytes: &[0x01, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x2",
        bytes: &[0x02, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x3",
        bytes: &[0x03, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x4",
        bytes: &[0x04, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x4", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x5",
        bytes: &[0x05, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x5", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x6",
        bytes: &[0x06, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x6", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x7",
        bytes: &[0x07, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x7", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x8",
        bytes: &[0x08, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x8", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x9",
        bytes: &[0x09, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x9", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x10",
        bytes: &[0x0a, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x10", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x11",
        bytes: &[0x0b, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x11", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x12",
        bytes: &[0x0c, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x12", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x13",
        bytes: &[0x0d, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x13", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x14",
        bytes: &[0x0e, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x14", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x15",
        bytes: &[0x0f, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x15", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x16",
        bytes: &[0x10, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x16", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x17",
        bytes: &[0x11, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x17", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x18",
        bytes: &[0x12, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x18", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x19",
        bytes: &[0x13, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x19", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x20",
        bytes: &[0x14, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x20", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x21",
        bytes: &[0x15, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x21", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "msr",
        instruction: "msr	FPCR, x22",
        bytes: &[0x16, 0x44, 0x1b, 0xd5],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x22", 0x0100_0000), ("fpcr", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn msr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn msr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
