use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn lddqu_semantics_stay_complete() {
    assert_complete_semantics(
        "lddqu xmm0, xmmword ptr [rax]",
        Architecture::AMD64,
        &[0xf2, 0x0f, 0xf0, 0x00],
    );
}

#[test]
fn lddqu_semantics_match_unicorn_transitions() {
    let mem128 = vec![
        0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57,
        0x9b, 0xdf,
    ];

    assert_amd64_semantics_match_unicorn(
        "lddqu xmm0, xmmword ptr [rax]",
        &[0xf2, 0x0f, 0xf0, 0x00],
        I386Fixture {
            registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, 0)],
            eflags: 1 << 1,
            memory: vec![(0x3000, mem128)],
        },
    );
}
