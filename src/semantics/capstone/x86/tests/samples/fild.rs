use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fild_semantics_stay_complete() {
    assert_complete_semantics("fild dword ptr [eax]", Architecture::I386, &[0xdb, 0x00]);
}
