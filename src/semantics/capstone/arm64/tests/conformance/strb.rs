use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn strb_semantics_match_unicorn_transitions() {
    let cases = [
(
            "strb w0, [x1]",
            vec![0x20, 0x00, 0x00, 0x39],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_56ab), ("x1", 0x2000)],
                memory: vec![(0x2000, vec![0x00])],
            },
        ),
(
            "strb w0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0x38],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_56ab), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0x00])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
