use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn punpckhbw_semantics_stay_complete() {
    assert_complete_semantics(
        "punpckhbw xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x68, 0xc1],
    );
}
