use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn unpckhps_semantics_stay_complete() {
    assert_complete_semantics(
        "unpckhps xmm0, xmm1",
        Architecture::AMD64,
        &[0x0f, 0x15, 0xc1],
    );
}
