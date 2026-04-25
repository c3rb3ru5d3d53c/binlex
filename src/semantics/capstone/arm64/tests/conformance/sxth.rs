use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sxth_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sxth x0, w1",
            vec![0x20, 0x3c, 0x40, 0x93],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_8001)],
                memory: vec![],
            },
        ),
(
            "sxth w0, w1",
            vec![0x20, 0x3c, 0x00, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x0000_8001)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
