use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movmskps_semantics_stay_complete() {
    assert_complete_semantics(
        "movmskps eax, xmm0",
        Architecture::AMD64,
        &[0x0f, 0x50, 0xc0],
    );
}
