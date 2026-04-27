use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn vextracti128_semantics_stay_complete() {
    assert_complete_semantics(
        "vextracti128 xmm0, ymm1, 1",
        Architecture::AMD64,
        &[0xc4, 0xe3, 0x7d, 0x39, 0xc8, 0x01],
    );
}
