use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pminsb_semantics_stay_complete() {
    assert_complete_semantics(
        "pminsb xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x38, 0xc1],
    );
}
