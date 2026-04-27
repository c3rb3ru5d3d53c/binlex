use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn unpcklpd_semantics_stay_complete() {
    assert_complete_semantics(
        "unpcklpd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x14, 0xc1],
    );
}
