use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movhps_semantics_stay_complete() {
    assert_complete_semantics(
        "movhps xmm0, qword ptr [rax]",
        Architecture::AMD64,
        &[0x0f, 0x16, 0x00],
    );
}
