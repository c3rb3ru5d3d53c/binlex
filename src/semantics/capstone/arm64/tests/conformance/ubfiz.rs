use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ubfiz_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ubfiz x0, x1, #4, #8",
            vec![0x20, 0x1c, 0x7c, 0xd3],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
(
            "ubfiz w0, w1, #4, #8",
            vec![0x20, 0x1c, 0x1c, 0x53],
            Arm64Fixture {
                registers: vec![("w1", 0x89ab_cdef)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
