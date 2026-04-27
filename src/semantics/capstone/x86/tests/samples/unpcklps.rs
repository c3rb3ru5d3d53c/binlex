use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn unpcklps_semantics_stay_complete() {
    assert_complete_semantics(
        "unpcklps xmm0, xmm1",
        Architecture::AMD64,
        &[0x0f, 0x14, 0xc1],
    );
}
