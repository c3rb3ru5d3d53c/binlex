use super::common::assert_complete_semantics;

#[test]
fn system_semantics_regressions_stay_complete() {
    let cases = [
        ("mrs x0, TPIDR_EL0", vec![0x40, 0xd0, 0x3b, 0xd5]),
        ("msr TPIDR_EL0, x0", vec![0x40, 0xd0, 0x1b, 0xd5]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, &bytes);
    }
}
