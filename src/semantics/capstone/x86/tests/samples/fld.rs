use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fld_semantics_stay_complete() {
    assert_complete_semantics("fld dword ptr [eax]", Architecture::I386, &[0xd9, 0x00]);
}
