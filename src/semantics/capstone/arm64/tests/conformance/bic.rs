use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn bic_semantics_match_unicorn_transitions() {
    let cases = [
(
            "bic x0, x1, x2",
            vec![0x20, 0x00, 0x22, 0x8a],
            Arm64Fixture {
                registers: vec![("x1", 0xffff_0000_ffff_0000), ("x2", 0x00ff_00ff_00ff_00ff)],
                memory: vec![],
            },
        ),
(
            "bic w0, w1, w2",
            vec![0x20, 0x00, 0x22, 0x0a],
            Arm64Fixture {
                registers: vec![("w1", 0xffff_0000), ("w2", 0x00ff_00ff)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
