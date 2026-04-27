use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pminuw_semantics_stay_complete() {
    assert_complete_semantics(
        "pminuw xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x3a, 0xc1],
    );
}
