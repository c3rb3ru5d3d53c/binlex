use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn palignr_semantics_stay_complete() {
    assert_complete_semantics(
        "palignr xmm0, xmm1, 8",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x08],
    );
}
