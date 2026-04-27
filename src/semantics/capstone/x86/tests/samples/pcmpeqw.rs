use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pcmpeqw_semantics_stay_complete() {
    assert_complete_semantics(
        "pcmpeqw xmm0, xmm1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x75, 0xc1],
    );
}
