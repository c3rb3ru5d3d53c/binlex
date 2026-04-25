use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sxtb_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sxtb x0, w1",
            vec![0x20, 0x1c, 0x40, 0x93],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_0081)],
                memory: vec![],
            },
        ),
(
            "sxtb w0, w1",
            vec![0x20, 0x1c, 0x00, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_0081)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
