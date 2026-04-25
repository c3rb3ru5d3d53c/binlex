use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ld1_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ld1 {v0.d}[1], [x1]",
            vec![0x20, 0x84, 0x40, 0x4d],
            Arm64Fixture {
                registers: vec![
                    ("v0", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                    ("x1", 0x5000),
                ],
                memory: vec![(0x5000, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
            },
        ),
(
            "ld1 {v1.s}[1], [x11]",
            vec![0x61, 0x91, 0x40, 0x0d],
            Arm64Fixture {
                registers: vec![
                    ("v1", 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128),
                    ("x11", 0x6000),
                ],
                memory: vec![(0x6000, vec![0x78, 0x56, 0x34, 0x12])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
