use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn br_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "br x3",
            vec![0x60, 0x00, 0x1f, 0xd6],
            Arm64Fixture {
                registers: vec![("x3", 0x1020)],
                memory: vec![],
            },
        ),
        (
            "br x17",
            vec![0x20, 0x02, 0x1f, 0xd6],
            Arm64Fixture {
                registers: vec![("x17", 0x1080)],
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
