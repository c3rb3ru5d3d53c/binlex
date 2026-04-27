use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movlhps_semantics_stay_complete() {
    assert_complete_semantics(
        "movlhps xmm0, xmm1",
        Architecture::AMD64,
        &[0x0f, 0x16, 0xc1],
    );
}
