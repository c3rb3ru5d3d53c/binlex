use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn pinsrq_semantics_stay_complete() {
    assert_complete_semantics(
        "pinsrq xmm0, rax, 1",
        Architecture::AMD64,
        &[0x66, 0x48, 0x0f, 0x3a, 0x22, 0xc0, 0x01],
    );
}
