use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fsub_semantics_stay_complete() {
    assert_complete_semantics("fsub dword ptr [eax]", Architecture::I386, &[0xd8, 0x20]);
}
