use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn strh_semantics_match_unicorn_transitions() {
    let cases = [
(
            "strh w0, [x1]",
            vec![0x20, 0x00, 0x00, 0x79],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x00, 0x00])],
            },
        ),
(
            "strh w0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0x78],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_abcd), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x00, 0x00])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
