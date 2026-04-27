use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fld1_semantics_stay_complete() {
    assert_complete_semantics("fld1", Architecture::I386, &[0xd9, 0xe8]);
}
