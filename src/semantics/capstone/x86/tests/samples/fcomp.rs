use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fcomp_semantics_stay_complete() {
    assert_complete_semantics("fcomp dword ptr [eax]", Architecture::I386, &[0xd8, 0x18]);
}
