use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldrb_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldrb w0, [x1]",
            vec![0x20, 0x00, 0x40, 0x39],
            Arm64Fixture {
                registers: vec![("x1", 0x2000)],
                memory: vec![(0x2000, vec![0xab])],
            },
        ),
(
            "ldrb w0, [x1, x2]",
            vec![0x20, 0x68, 0x62, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0xab])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
