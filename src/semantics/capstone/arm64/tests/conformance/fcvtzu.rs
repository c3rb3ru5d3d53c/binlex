use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn fcvtzu_semantics_match_unicorn_transitions() {
    let cases = [
(
            "fcvtzu x0, d1",
            vec![0x20, 0x00, 0x79, 0x9e],
            Arm64Fixture {
                registers: vec![("d1", 0x4045_0000_0000_0000)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
