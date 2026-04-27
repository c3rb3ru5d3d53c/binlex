use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn bextr_semantics_stay_complete() {
    let cases = [
        (
            "bextr eax, ecx, 0x21",
            vec![0x8f, 0xea, 0x78, 0x10, 0xc1, 0x21, 0x00, 0x00, 0x00],
        ),
        (
            "bextr eax, ecx, edx",
            vec![0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        ),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}

#[test]
fn bextr_semantics_match_unicorn_transitions() {
    assert_amd64_semantics_match_unicorn(
        "bextr eax, ecx, edx",
        &[0xc4, 0xe2, 0x68, 0xf7, 0xc1],
        I386Fixture {
            registers: vec![
                (I386Register::Eax, 0),
                (I386Register::Ecx, 0b1110_1100),
                (I386Register::Edx, 0x0000_0201),
            ],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
