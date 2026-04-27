use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fdivr_semantics_stay_complete() {
    assert_complete_semantics("fdivr dword ptr [eax]", Architecture::I386, &[0xd8, 0x38]);
}
