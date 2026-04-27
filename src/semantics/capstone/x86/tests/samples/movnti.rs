use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movnti_semantics_stay_complete() {
    assert_complete_semantics(
        "movnti dword ptr [rax], eax",
        Architecture::AMD64,
        &[0x0f, 0xc3, 0x00],
    );
}
