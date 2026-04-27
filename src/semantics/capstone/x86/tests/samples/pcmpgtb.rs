use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pcmpgtb_semantics_stay_complete() {
    assert_complete_semantics(
        "pcmpgtb xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x64, 0xc1],
    );
}
