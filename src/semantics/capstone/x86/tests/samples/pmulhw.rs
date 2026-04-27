use super::super::support::{I386Fixture, I386Register, assert_amd64_semantics_match_unicorn, assert_complete_semantics};
use crate::Architecture;

#[test]
fn pmulhw_semantics_stay_complete() {
    let cases = [
        ("pmulhw xmm0, xmm1", vec![0x66, 0x0f, 0xe5, 0xc1]),
        ("vpmulhw xmm0, xmm2, xmm1", vec![0xc5, 0xe9, 0xe5, 0xc1]),
    ];

    for (name, bytes) in cases {
        assert_complete_semantics(name, Architecture::AMD64, &bytes);
    }
}

#[test]
fn pmulhw_semantics_match_unicorn_transitions() {
    let xmm0 = u128::from_le_bytes([
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22,
    ]);
    let xmm1 = u128::from_le_bytes([
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x99, 0x88,
    ]);

    assert_amd64_semantics_match_unicorn(
        "pmulhw xmm0, xmm1",
        &[0x66, 0x0f, 0xe5, 0xc1],
        I386Fixture {
            registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
            eflags: 1 << 1,
            memory: vec![],
        },
    );
}
