use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fsubr_semantics_stay_complete() {
    assert_complete_semantics("fsubr dword ptr [eax]", Architecture::I386, &[0xd8, 0x28]);
}
