use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn str_semantics_match_unicorn_transitions() {
    let cases = [
(
            "str x0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0xf8],
            Arm64Fixture {
                registers: vec![("x0", 0x1122_3344_5566_7788), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0; 8])],
            },
        ),
(
            "str w0, [x1, x2]",
            vec![0x20, 0x68, 0x22, 0xb8],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_5678), ("x1", 0x3000), ("x2", 0x10)],
                memory: vec![(0x3010, vec![0; 4])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
