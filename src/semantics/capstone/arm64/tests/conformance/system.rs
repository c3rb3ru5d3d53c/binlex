use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn system_semantics_match_unicorn_transitions() {
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
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
