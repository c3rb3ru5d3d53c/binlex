use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn psubq_semantics_stay_complete() {
    assert_complete_semantics(
        "psubq xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xfb, 0xc1],
    );
}
