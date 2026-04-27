use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pshufhw_semantics_stay_complete() {
    assert_complete_semantics(
        "pshufhw xmm0, xmm1, 0x1b",
        Architecture::AMD64,
        &[0xf3, 0x0f, 0x70, 0xc1, 0x1b],
    );
}
