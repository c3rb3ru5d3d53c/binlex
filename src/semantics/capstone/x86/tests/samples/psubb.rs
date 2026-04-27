use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn psubb_semantics_stay_complete() {
    assert_complete_semantics(
        "psubb xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0xf8, 0xc1],
    );
}
