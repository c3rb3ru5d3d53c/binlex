use super::super::support::assert_complete_semantics;

#[test]
fn system_semantics_regressions_stay_complete() {
    let cases = [
        ("mrs x0, TPIDR_EL0", vec![0x40, 0xd0, 0x3b, 0xd5]),
        ("mrs x1, TPIDR_EL0", vec![0x41, 0xd0, 0x3b, 0xd5]),
        ("mrs x2, TPIDR_EL0", vec![0x42, 0xd0, 0x3b, 0xd5]),
        ("mrs x0, FPCR", vec![0x00, 0x44, 0x3b, 0xd5]),
        ("msr TPIDR_EL0, x0", vec![0x40, 0xd0, 0x1b, 0xd5]),
        ("msr TPIDR_EL0, x1", vec![0x41, 0xd0, 0x1b, 0xd5]),
        ("msr TPIDR_EL0, x2", vec![0x42, 0xd0, 0x1b, 0xd5]),
        ("msr FPCR, x0", vec![0x00, 0x44, 0x1b, 0xd5]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, &bytes);
    }
}
