use super::super::support::{Arm64Fixture, assert_arm64_semantics_match_unicorn};

#[test]
fn sshll_semantics_match_unicorn_transitions() {
    let cases = [
(
            "sshll v0.8h, v1.8b, #0",
            vec![0x20, 0xa4, 0x08, 0x0f],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_aa55_f010_ff01_7f80u128)],
                memory: vec![],
            },
        ),
(
            "sshll v0.4s, v1.4h, #0",
            vec![0x20, 0xa4, 0x10, 0x0f],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_0000_0000_8001_7fffu128)],
                memory: vec![],
            },
        ),
(
            "sshll v1.4s, v0.4h, #0",
            vec![0x01, 0xa4, 0x10, 0x0f],
            Arm64Fixture {
                registers: vec![("v0", 0x0000_0000_0000_0000_0000_0000_8001_7fffu128)],
                memory: vec![],
            },
        ),
(
            "sshll v0.2d, v1.2s, #0",
            vec![0x20, 0xa4, 0x20, 0x0f],
            Arm64Fixture {
                registers: vec![("v1", 0x0000_0000_0000_0000_ffff_ffff_7fff_ffffu128)],
                memory: vec![],
            },
        )
    ];

    for (name, bytes, fixture) in cases {
        assert_arm64_semantics_match_unicorn(name, &bytes, fixture);
    }
}
