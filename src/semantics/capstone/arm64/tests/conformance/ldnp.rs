use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn ldnp_semantics_match_unicorn_transitions() {
    let cases = [
(
            "ldnp x0, x1, [x2]",
            vec![0x40, 0x04, 0x40, 0xa8],
            Arm64Fixture {
                registers: vec![("x2", 0x3000)],
                memory: vec![(
                    0x3000,
                    vec![
                        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd,
                        0xcc, 0xbb, 0xaa, 0x99,
                    ],
                )],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
