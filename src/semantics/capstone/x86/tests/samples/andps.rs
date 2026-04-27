use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn andps_semantics_stay_complete() {
    assert_complete_semantics(
        "andps xmm0, xmm1",
        Architecture::AMD64,
        &[0x0f, 0x54, 0xc1],
    );
}
