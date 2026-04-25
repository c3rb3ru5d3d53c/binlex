use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn lsl_semantics_match_unicorn_transitions() {
    let cases = [
(
            "lsl x0, x1, #3",
            vec![0x20, 0xf0, 0x7d, 0xd3],
            Arm64Fixture {
                registers: vec![("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
(
            "lsl w0, w1, #3",
            vec![0x20, 0x70, 0x1d, 0x53],
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
