use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fldz_semantics_stay_complete() {
    assert_complete_semantics("fldz", Architecture::I386, &[0xd9, 0xee]);
}
