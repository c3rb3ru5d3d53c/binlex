use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn movntq_semantics_stay_complete() {
    assert_complete_semantics(
        "movntq qword ptr [rax], mm0",
        Architecture::AMD64,
        &[0x0f, 0xe7, 0x00],
    );
}
