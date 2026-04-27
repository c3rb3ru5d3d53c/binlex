use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movlpd_semantics_stay_complete() {
    assert_complete_semantics(
        "movlpd xmm0, qword ptr [rax]",
        Architecture::AMD64,
        &[0x66, 0x0f, 0x12, 0x00],
    );
}
