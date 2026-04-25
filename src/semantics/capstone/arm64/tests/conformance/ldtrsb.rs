use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldtrsb_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldtrsb x0, [x1, #8]",
            vec![0x20, 0x88, 0x80, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x81])],
            },
        ),
(
            "ldtrsb w0, [x1, #8]",
            vec![0x20, 0x88, 0xc0, 0x38],
            Arm64Fixture {
                registers: vec![("x1", 0x3000)],
                memory: vec![(0x3008, vec![0x81])],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
