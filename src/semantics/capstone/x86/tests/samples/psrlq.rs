use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn psrlq_semantics_stay_complete() {
    assert_complete_semantics(
        "psrlq xmm0, 1",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x73, 0xd0, 0x01],
    );
}
