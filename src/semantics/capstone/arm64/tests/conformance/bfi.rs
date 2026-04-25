use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn bfi_semantics_match_unicorn_transitions() {
    let cases = [
(
            "bfi x0, x1, #4, #8",
            vec![0x20, 0x1c, 0x7c, 0xb3],
            Arm64Fixture {
                registers: vec![("x0", 0xffff_0000_ffff_0000), ("x1", 0x0123_4567_89ab_cdef)],
                memory: vec![],
            },
        ),
(
            "bfi w0, w1, #4, #8",
            vec![0x20, 0x1c, 0x1c, 0x33],
            Arm64Fixture {
                registers: vec![("w0", 0xffff_0000), ("w1", 0x89ab_cdef)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
