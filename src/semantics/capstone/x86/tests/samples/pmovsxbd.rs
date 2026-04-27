use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pmovsxbd_semantics_stay_complete() {
    assert_complete_semantics(
        "pmovsxbd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x38, 0x21, 0xc1],
    );
}
