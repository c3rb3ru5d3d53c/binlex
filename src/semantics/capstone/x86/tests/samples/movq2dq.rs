use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movq2dq_semantics_stay_complete() {
    assert_complete_semantics(
        "movq2dq xmm0, mm1",
        Architecture::AMD64,
        &[0xf3, 0x0f, 0xd6, 0xc1],
    );
}
