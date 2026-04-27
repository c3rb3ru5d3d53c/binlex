use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmovsxwd_semantics_stay_complete() {
    assert_complete_semantics(
        "pmovsxwd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x23, 0xc1],
    );
}
