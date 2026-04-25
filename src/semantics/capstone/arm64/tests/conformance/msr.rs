use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn msr_semantics_match_unicorn_transitions() {
    let cases = [
(
            "msr TPIDR_EL0, x0",
            vec![0x40, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x0", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x1",
            vec![0x41, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x1", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x2",
            vec![0x42, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x2", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x0",
            vec![0x00, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x0", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x3",
            vec![0x43, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x3", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x4",
            vec![0x44, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x4", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x5",
            vec![0x45, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x5", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x6",
            vec![0x46, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x6", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x7",
            vec![0x47, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x7", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x8",
            vec![0x48, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x8", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x9",
            vec![0x49, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x9", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x10",
            vec![0x4a, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x10", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x11",
            vec![0x4b, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x11", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x12",
            vec![0x4c, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x12", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x13",
            vec![0x4d, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x13", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x14",
            vec![0x4e, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x14", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x15",
            vec![0x4f, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x15", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x16",
            vec![0x50, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x16", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x17",
            vec![0x51, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x17", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x18",
            vec![0x52, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x18", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x19",
            vec![0x53, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x19", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x20",
            vec![0x54, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x20", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x21",
            vec![0x55, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x21", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x22",
            vec![0x56, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x22", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x23",
            vec![0x57, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x23", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x24",
            vec![0x58, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x24", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x25",
            vec![0x59, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x25", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x26",
            vec![0x5a, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x26", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x27",
            vec![0x5b, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x27", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x28",
            vec![0x5c, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x28", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x29",
            vec![0x5d, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x29", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr TPIDR_EL0, x30",
            vec![0x5e, 0xd0, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x30", 0x1234_5678_9abc_def0), ("tpidr_el0", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x1",
            vec![0x01, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x1", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x2",
            vec![0x02, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x2", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x3",
            vec![0x03, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x3", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x4",
            vec![0x04, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x4", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x5",
            vec![0x05, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x5", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x6",
            vec![0x06, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x6", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x7",
            vec![0x07, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x7", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x8",
            vec![0x08, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x8", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x9",
            vec![0x09, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x9", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x10",
            vec![0x0a, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x10", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x11",
            vec![0x0b, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x11", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x12",
            vec![0x0c, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x12", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x13",
            vec![0x0d, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x13", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x14",
            vec![0x0e, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x14", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x15",
            vec![0x0f, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x15", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x16",
            vec![0x10, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x16", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x17",
            vec![0x11, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x17", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x18",
            vec![0x12, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x18", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x19",
            vec![0x13, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x19", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x20",
            vec![0x14, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x20", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x21",
            vec![0x15, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x21", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        ),
(
            "msr FPCR, x22",
            vec![0x16, 0x44, 0x1b, 0xd5],
            Arm64Fixture {
                registers: vec![("x22", 0x0100_0000), ("fpcr", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
