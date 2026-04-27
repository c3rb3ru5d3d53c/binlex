use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn paddq_semantics_stay_complete() {
    assert_complete_semantics(
        "paddq xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xd4, 0xc1],
    );
}
