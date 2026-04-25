use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn blr_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "blr x3",
            vec![0x60, 0x00, 0x3f, 0xd6],
            Arm64Fixture {
                registers: vec![("x3", 0x1020)],
                memory: vec![],
            },
        ),
        (
            "blr x17",
            vec![0x20, 0x02, 0x3f, 0xd6],
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
