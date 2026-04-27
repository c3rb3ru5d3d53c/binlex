use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn vpsignw_semantics_stay_complete() {
    assert_complete_semantics(
        "vpsignw xmm0, xmm2, xmm1",
        Architecture::AMD64,
        &[0xc4, 0xe2, 0x69, 0x09, 0xc1],
    );
}
