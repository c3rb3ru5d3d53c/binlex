use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn cmn_semantics_match_unicorn_transitions() {
    let cases = [
(
            "cmn x0, x1",
            vec![0x1f, 0x00, 0x01, 0xab],
            Arm64Fixture {
                registers: vec![
                    ("x0", 0x7fff_ffff_ffff_ffff),
                    ("x1", 1),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        ),
(
            "cmn w0, w1",
            vec![0x1f, 0x00, 0x01, 0x2b],
            Arm64Fixture {
                registers: vec![
                    ("w0", 0x7fff_ffff),
                    ("w1", 1),
                    ("n", 0),
                    ("z", 0),
                    ("c", 0),
                    ("v", 0),
                ],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
