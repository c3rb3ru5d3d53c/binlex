use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ret_semantics_match_unicorn_transitions() {
    let cases = [
        (
            "ret",
            vec![0xc0, 0x03, 0x5f, 0xd6],
            Arm64Fixture {
                registers: vec![("x30", 0x1040)],
                memory: vec![],
            },
        ),
        (
            "ret x3",
            vec![0x60, 0x00, 0x5f, 0xd6],
            Arm64Fixture {
                registers: vec![("x3", 0x1080)],
                memory: vec![],
            },
        ),
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
