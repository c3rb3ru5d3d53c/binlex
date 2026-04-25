use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn stnp_semantics_match_unicorn_transitions() {
    let cases = [
(
            "stnp x0, x1, [x2]",
            vec![0x40, 0x04, 0x00, 0xa8],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0x1122_3344_5566_7788),
                    ("x1", 0x99aa_bbcc_ddee_ff00),
                    ("x2", 0x3000),
                ],
                memory: vec![(0x3000, vec![0; 16])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
