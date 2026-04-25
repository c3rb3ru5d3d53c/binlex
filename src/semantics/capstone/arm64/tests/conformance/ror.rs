use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ror_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ror x0, x1, #8",
            vec![0x20, 0x20, 0xc1, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
(
            "ror w0, w1, #8",
            vec![0x20, 0x20, 0x81, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0x1234_5678)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
