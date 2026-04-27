use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pshuflw_semantics_stay_complete() {
    assert_complete_semantics(
        "pshuflw xmm0, xmm1, 0x1b",
        Architecture::AMD64,
        &[0xf2, 0x0f, 0x70, 0xc1, 0x1b],
    );
}
