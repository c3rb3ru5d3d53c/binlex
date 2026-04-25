use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn rev_semantics_match_unicorn_transitions() {
    let cases = [
(
            "rev x0, x1",
            vec![0x20, 0x0c, 0xc0, 0xda],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
(
            "rev w0, w1",
            vec![0x20, 0x08, 0xc0, 0x5a],
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
