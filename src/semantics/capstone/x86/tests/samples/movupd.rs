use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movupd_semantics_stay_complete() {
    assert_complete_semantics(
        "movupd xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x10, 0xc1],
    );
}
