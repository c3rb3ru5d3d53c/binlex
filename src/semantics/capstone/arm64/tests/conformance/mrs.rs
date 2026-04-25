use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn mrs_semantics_match_unicorn_transitions() {
    let cases = [
(
            "mrs x0, TPIDR_EL0",
            vec![0x40, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x1, TPIDR_EL0",
            vec![0x41, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x2, TPIDR_EL0",
            vec![0x42, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x0, FPCR",
            vec![0x00, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x3, TPIDR_EL0",
            vec![0x43, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x4, TPIDR_EL0",
            vec![0x44, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x5, TPIDR_EL0",
            vec![0x45, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x6, TPIDR_EL0",
            vec![0x46, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x7, TPIDR_EL0",
            vec![0x47, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x8, TPIDR_EL0",
            vec![0x48, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x9, TPIDR_EL0",
            vec![0x49, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x10, TPIDR_EL0",
            vec![0x4a, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x11, TPIDR_EL0",
            vec![0x4b, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x12, TPIDR_EL0",
            vec![0x4c, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x13, TPIDR_EL0",
            vec![0x4d, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x14, TPIDR_EL0",
            vec![0x4e, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x15, TPIDR_EL0",
            vec![0x4f, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x16, TPIDR_EL0",
            vec![0x50, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x17, TPIDR_EL0",
            vec![0x51, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x18, TPIDR_EL0",
            vec![0x52, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x19, TPIDR_EL0",
            vec![0x53, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x20, TPIDR_EL0",
            vec![0x54, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x21, TPIDR_EL0",
            vec![0x55, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x22, TPIDR_EL0",
            vec![0x56, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x23, TPIDR_EL0",
            vec![0x57, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x24, TPIDR_EL0",
            vec![0x58, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x25, TPIDR_EL0",
            vec![0x59, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x26, TPIDR_EL0",
            vec![0x5a, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x27, TPIDR_EL0",
            vec![0x5b, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x28, TPIDR_EL0",
            vec![0x5c, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x29, TPIDR_EL0",
            vec![0x5d, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x30, TPIDR_EL0",
            vec![0x5e, 0xd0, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("tpidr_el0", 0x1234_5678_9abc_def0)],
                memory: vec![],
            },
        ),
(
            "mrs x1, FPCR",
            vec![0x01, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x2, FPCR",
            vec![0x02, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x3, FPCR",
            vec![0x03, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x4, FPCR",
            vec![0x04, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x5, FPCR",
            vec![0x05, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x6, FPCR",
            vec![0x06, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x7, FPCR",
            vec![0x07, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x8, FPCR",
            vec![0x08, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x9, FPCR",
            vec![0x09, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x10, FPCR",
            vec![0x0a, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x11, FPCR",
            vec![0x0b, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x12, FPCR",
            vec![0x0c, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x13, FPCR",
            vec![0x0d, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x14, FPCR",
            vec![0x0e, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x15, FPCR",
            vec![0x0f, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x16, FPCR",
            vec![0x10, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x17, FPCR",
            vec![0x11, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x18, FPCR",
            vec![0x12, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x19, FPCR",
            vec![0x13, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x20, FPCR",
            vec![0x14, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x21, FPCR",
            vec![0x15, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        ),
(
            "mrs x22, FPCR",
            vec![0x16, 0x44, 0x3b, 0xd5],
            Arm64Fixture {
                registers: vec![("fpcr", 0x0100_0000)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
