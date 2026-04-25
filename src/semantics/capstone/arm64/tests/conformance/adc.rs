use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn adc_semantics_match_unicorn_transitions() {
    let cases = [
(
            "adc x0, x1, x2",
            vec![0x20, 0x00, 0x02, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 5), ("x2", 7), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        ),
(
            "adc w0, w1, w2",
            vec![0x20, 0x00, 0x02, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 5), ("w2", 7), ("n", 0), ("z", 0), ("c", 1), ("v", 0)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
