use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pinsrb_semantics_stay_complete() {
    assert_complete_semantics(
        "pinsrb xmm0, eax, 1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x3a, 0x20, 0xc0, 0x01],
    );
}
