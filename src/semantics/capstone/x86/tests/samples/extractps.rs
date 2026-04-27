use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn extractps_semantics_stay_complete() {
    assert_complete_semantics(
        "extractps eax, xmm0, 1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x3a, 0x17, 0xc0, 0x01],
    );
}
