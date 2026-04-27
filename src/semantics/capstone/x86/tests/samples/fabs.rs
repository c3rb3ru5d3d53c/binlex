use super::super::support::assert_complete_semantics;
use crate::Architecture;

#[test]
fn fabs_semantics_stay_complete() {
    assert_complete_semantics("fabs", Architecture::I386, &[0xd9, 0xe1]);
}
