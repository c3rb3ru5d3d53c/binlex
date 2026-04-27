use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn vperm2i128_semantics_stay_complete() {
    assert_complete_semantics(
        "vperm2i128 ymm0, ymm2, ymm1, 0x31",
        Architecture::AMD64,
        &[0xc4, 0xe3, 0x6d, 0x46, 0xc1, 0x31],
    );
}
