use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn vpermq_semantics_stay_complete() {
    assert_complete_semantics(
        "vpermq ymm0, ymm1, 0x1b",
        Architecture::AMD64,
        &[0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b],
    );
}
