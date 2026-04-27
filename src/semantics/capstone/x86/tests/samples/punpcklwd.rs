use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn punpcklwd_semantics_stay_complete() {
    assert_complete_semantics(
        "punpcklwd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x61, 0xc1],
    );
}
