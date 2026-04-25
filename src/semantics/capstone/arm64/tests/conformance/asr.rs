use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn asr_semantics_match_unicorn_transitions() {
    let cases = [
(
            "asr x0, x1, #3",
            vec![0x20, 0xfc, 0x43, 0x93],
            Arm64Fixture {
                registers: vec![("x1", 0xf123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
(
            "asr w0, w1, #3",
            vec![0x20, 0x7c, 0x03, 0x13],
            Arm64Fixture {
                registers: vec![("w1", 0xf234_5678)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
