use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn extr_semantics_match_unicorn_transitions() {
    let cases = [
(
            "extr w8, w0, w8, #1",
            vec![0x08, 0x04, 0x88, 0x13],
            Arm64Fixture {
                registers: vec![("w0", 0x1234_5678), ("w8", 0x89ab_cdef)],
                memory: vec![],
            },
        ),
(
            "extr x0, x1, x2, #8",
            vec![0x20, 0x20, 0xc2, 0x93],
            Arm64Fixture {
                registers: vec![
                    ("x1", 0x0123_4567_89ab_cdef),
                    ("x2", 0xfedc_ba98_7654_3210),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
