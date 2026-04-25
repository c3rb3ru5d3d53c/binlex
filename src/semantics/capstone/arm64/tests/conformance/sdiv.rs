use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sdiv_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sdiv x0, x1, x2",
            vec![0x20, 0x0c, 0xc2, 0x9a],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_ffff_ffff_ff9c), ("x2", 5)],
                memory: vec![],
            },
        ),
(
            "sdiv w0, w1, w2",
            vec![0x20, 0x0c, 0xc2, 0x1a],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_ff9c), ("w2", 5)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
