use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pminsd_semantics_stay_complete() {
    assert_complete_semantics(
        "pminsd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x39, 0xc1],
    );
}
